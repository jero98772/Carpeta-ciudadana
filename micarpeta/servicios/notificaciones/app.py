"""MS-08 ms-notificaciones · Convierte eventos de dominio en avisos al ciudadano.

Consume del bus: ciudadano.registrado (bienvenida), documento.autenticado y
documento.autenticacion_fallida. Guarda cada aviso en la bandeja del
ciudadano y, si hay SMTP configurado (Mailpit en docker-compose), lo envía
por correo. Es idempotente por id de evento.
"""

import logging
import smtplib
from datetime import datetime
from email.message import EmailMessage

from fastapi import Depends, FastAPI
from sqlalchemy import String, Text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from starlette.concurrency import run_in_threadpool

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, FechaUTC, ahora, nuevo_id, sesion_bd
from micarpeta.comun.eventos import (
    AUTENTICACION_FALLIDA,
    CIUDADANO_REGISTRADO,
    DOCUMENTO_AUTENTICADO,
)
from micarpeta.comun.seguridad import Usuario, usuario_actual

log = logging.getLogger("micarpeta.notificaciones")


class Base(DeclarativeBase):
    pass


class Contacto(Base):
    """Copia local del contacto del ciudadano (llega en el evento de registro)."""

    __tablename__ = "contactos"

    ciudadano_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    nombre: Mapped[str] = mapped_column(String(150))
    correo: Mapped[str] = mapped_column(String(254))
    direccion_unica: Mapped[str | None] = mapped_column(String(254), nullable=True)


class Notificacion(Base):
    __tablename__ = "bandeja"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    evento_id: Mapped[str] = mapped_column(String(36), unique=True)
    tipo_evento: Mapped[str] = mapped_column(String(80))
    ciudadano_id: Mapped[str] = mapped_column(String(36), index=True)
    destinatario: Mapped[str] = mapped_column(String(254))
    asunto: Mapped[str] = mapped_column(String(200))
    cuerpo: Mapped[str] = mapped_column(Text)
    canal: Mapped[str] = mapped_column(String(20), default="CORREO")
    estado: Mapped[str] = mapped_column(String(20))  # ENVIADA | EN_BANDEJA | FALLIDA
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fecha: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)


def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    cfg = ctx.config
    db = BaseDatos(db_url or cfg.url_bd("notificaciones"))

    def enviar_correo(destinatario: str, asunto: str, cuerpo: str) -> None:
        msg = EmailMessage()
        msg["From"] = f"{cfg.nombre_operador} <{cfg.smtp_remitente}>"
        msg["To"] = destinatario
        msg["Subject"] = asunto
        msg.set_content(cuerpo)
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_puerto, timeout=10) as smtp:
            smtp.send_message(msg)

    def redactar(evento: dict, contacto: Contacto) -> tuple[str, str] | None:
        datos, tipo = evento["data"], evento["type"]
        saludo = f"Hola {contacto.nombre.split(' ')[0]},\n\n"
        firma = f"\n\n— {cfg.nombre_operador}"
        if tipo == CIUDADANO_REGISTRADO:
            return (
                f"Bienvenido a {cfg.nombre_operador}",
                saludo + "tu Carpeta Ciudadana ya está activa y afiliada en GovCarpeta.\n"
                f"Tu dirección única es: {datos.get('direccion_unica')}" + firma,
            )
        if tipo == DOCUMENTO_AUTENTICADO:
            return (
                f"Tu documento «{datos['titulo']}» fue autenticado",
                saludo + f"GovCarpeta autenticó tu documento «{datos['titulo']}».\n"
                f"Sello de autenticidad: {datos['sello']}" + firma,
            )
        if tipo == AUTENTICACION_FALLIDA:
            return (
                f"No pudimos autenticar «{datos['titulo']}»",
                saludo + f"La autenticación de «{datos['titulo']}» no se completó porque GovCarpeta no respondió.\n"
                "Tu documento sigue en tu carpeta como TEMPORAL; puedes intentarlo de nuevo más tarde." + firma,
            )
        return None

    async def al_recibir(evento: dict) -> None:
        async with db.sesiones() as s:
            if await s.scalar(select(Notificacion.id).where(Notificacion.evento_id == evento["id"])):
                return  # entrega duplicada: ya procesado
            datos = evento["data"]
            ciudadano_id = datos.get("ciudadano_id")
            if evento["type"] == CIUDADANO_REGISTRADO:
                contacto = await s.get(Contacto, ciudadano_id) or Contacto(ciudadano_id=ciudadano_id)
                contacto.nombre = datos["nombre_completo"]
                contacto.correo = datos["correo"]
                contacto.direccion_unica = datos.get("direccion_unica")
                s.add(contacto)
                await s.flush()
            else:
                contacto = await s.get(Contacto, ciudadano_id)
            if contacto is None:
                log.warning("Sin contacto para el ciudadano %s; evento %s ignorado", ciudadano_id, evento["type"])
                return
            mensaje = redactar(evento, contacto)
            if mensaje is None:
                return
            asunto, cuerpo = mensaje
            notif = Notificacion(
                evento_id=evento["id"],
                tipo_evento=evento["type"],
                ciudadano_id=ciudadano_id,
                destinatario=contacto.correo,
                asunto=asunto,
                cuerpo=cuerpo,
                estado="EN_BANDEJA",
            )
            if cfg.smtp_host:
                try:
                    await run_in_threadpool(enviar_correo, contacto.correo, asunto, cuerpo)
                    notif.estado = "ENVIADA"
                except Exception as e:  # noqa: BLE001 - el aviso queda en la bandeja aunque falle el correo
                    notif.estado = "FALLIDA"
                    notif.error = str(e)
                    log.warning("No se pudo enviar correo a %s: %s", contacto.correo, e)
            s.add(notif)
            try:
                await s.commit()
            except IntegrityError:
                await s.rollback()  # otro consumidor ya lo registró

    async def al_iniciar(app: FastAPI) -> None:
        await ctx.bus.suscribir(
            "ms-notificaciones",
            [CIUDADANO_REGISTRADO, DOCUMENTO_AUTENTICADO, AUTENTICACION_FALLIDA],
            al_recibir,
        )

    app = crear_app_base(
        "ms-notificaciones",
        ctx,
        descripcion="Consume eventos y notifica al ciudadano (bandeja + correo).",
        db=db,
        metadata=Base.metadata,
        al_iniciar=al_iniciar,
        gestionar_ciclo=gestionar_ciclo,
    )

    @app.get("/api/v1/notificaciones", tags=["notificaciones"], summary="Bandeja del ciudadano")
    async def bandeja(usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        filas = (
            await s.scalars(
                select(Notificacion).where(Notificacion.ciudadano_id == usuario.ciudadano_id).order_by(Notificacion.fecha.desc())
            )
        ).all()
        return {
            "notificaciones": [
                {
                    "id": n.id,
                    "asunto": n.asunto,
                    "cuerpo": n.cuerpo,
                    "destinatario": n.destinatario,
                    "estado": n.estado,
                    "fecha": n.fecha.isoformat(),
                }
                for n in filas
            ]
        }

    return app

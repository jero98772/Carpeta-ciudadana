"""MS-05 ms-certificacion · Autenticación documental ante GovCarpeta (CU-04).

Orquestador asíncrono: responde 202 Accepted de inmediato y en segundo plano
    1. pide a ms-custodia una URL prefirmada temporal (nunca se envía el binario),
    2. la envía a GovCarpeta a través de la ACL (reintentos + cortacircuitos),
    3. si GovCarpeta confirma, emite un sello de autenticidad y el documento
       pasa a CERTIFICADO; si falla, vuelve a TEMPORAL (nunca queda en limbo).

Soporta la cabecera Idempotency-Key y expone una verificación pública para
entidades, sin sesión.
"""

import hashlib
import hmac
import logging
import secrets
from datetime import datetime

from fastapi import BackgroundTasks, Depends, FastAPI, Header, Query, Response
from sqlalchemy import Integer, String, Text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, FechaUTC, ahora, nuevo_id, sesion_bd
from micarpeta.comun.errores import ErrorDominio, error_desde_respuesta
from micarpeta.comun.eventos import (
    AUTENTICACION_FALLIDA,
    DOCUMENTO_AUTENTICADO,
    crear_evento,
    publicar_seguro,
)
from micarpeta.comun.seguridad import Usuario, usuario_actual

log = logging.getLogger("micarpeta.certificacion")


class Base(DeclarativeBase):
    pass


class EstadoSolicitud:
    EN_PROCESO = "EN_PROCESO"
    AUTENTICADO = "AUTENTICADO"
    FALLIDO = "FALLIDO"


class SolicitudAutenticacion(Base):
    __tablename__ = "solicitudes_autenticacion"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    documento_id: Mapped[str] = mapped_column(String(36), index=True)  # referencia lógica
    ciudadano_id: Mapped[str] = mapped_column(String(36), index=True)
    clave_idempotencia: Mapped[str | None] = mapped_column(String(120), unique=True, nullable=True)
    estado: Mapped[str] = mapped_column(String(20), default=EstadoSolicitud.EN_PROCESO)
    intentos: Mapped[int] = mapped_column(Integer, default=0)
    respuesta_govcarpeta: Mapped[str | None] = mapped_column(Text, nullable=True)
    ultimo_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fecha_solicitud: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)
    fecha_resolucion: Mapped[datetime | None] = mapped_column(FechaUTC, nullable=True)


class SelloAutenticidad(Base):
    __tablename__ = "sellos_autenticidad"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    solicitud_id: Mapped[str] = mapped_column(String(36))
    documento_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    ciudadano_id: Mapped[str] = mapped_column(String(36))
    codigo: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    titulo: Mapped[str] = mapped_column(String(200))
    hash_documento: Mapped[str] = mapped_column(String(64))
    hash_sellado: Mapped[str] = mapped_column(String(64))
    firma: Mapped[str] = mapped_column(String(64))
    emisor: Mapped[str] = mapped_column(String(100))
    fecha_sello: Mapped[str] = mapped_column(String(40))  # ISO-8601, parte de lo firmado


def vista_solicitud(sol: SolicitudAutenticacion) -> dict:
    return {
        "solicitud_id": sol.id,
        "documento_id": sol.documento_id,
        "estado": sol.estado,
        "ultimo_error": sol.ultimo_error,
        "fecha_solicitud": sol.fecha_solicitud.isoformat() if sol.fecha_solicitud else None,
        "fecha_resolucion": sol.fecha_resolucion.isoformat() if sol.fecha_resolucion else None,
    }


def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    cfg = ctx.config
    db = BaseDatos(db_url or cfg.url_bd("certificacion"))
    app = crear_app_base(
        "ms-certificacion",
        ctx,
        descripcion="Orquesta la autenticación documental ante GovCarpeta y emite sellos de autenticidad.",
        db=db,
        metadata=Base.metadata,
        gestionar_ciclo=gestionar_ciclo,
    )

    def firmar_sello(hash_sellado: str) -> str:
        return hmac.new(cfg.clave_sello.encode(), hash_sellado.encode(), hashlib.sha256).hexdigest()

    def calcular_hash_sellado(documento_id: str, hash_documento: str, fecha: str, emisor: str, codigo: str) -> str:
        return hashlib.sha256(f"{documento_id}|{hash_documento}|{fecha}|{emisor}|{codigo}".encode()).hexdigest()

    async def cambiar_estado_documento(documento_id: str, estado: str, **extra) -> None:
        r = await ctx.clientes.llamar(
            "documentos", "PATCH", f"/internal/documentos/{documento_id}/estado", json={"estado": estado, **extra}
        )
        if r.status_code != 200:
            raise error_desde_respuesta(r, "ms-documentos")

    # ---------------------------------------------------------------- procesamiento asíncrono
    async def procesar(solicitud_id: str, doc: dict, documento_ciudadano: str) -> None:
        async with db.sesiones() as s:
            sol = await s.get(SolicitudAutenticacion, solicitud_id)
            sol.intentos += 1
            try:
                # 1. URL temporal del documento (GovCarpeta recibe la URL, nunca el binario)
                r = await ctx.clientes.llamar(
                    "custodia",
                    "POST",
                    "/internal/urls-temporales",
                    json={
                        "objeto_id": doc["objeto_id"],
                        "ciudadano_id": doc["ciudadano_id"],
                        "segundos": cfg.expiracion_url_govcarpeta_segundos,
                        "nombre_archivo": doc["nombre_archivo"],
                    },
                )
                if r.status_code != 200:
                    raise error_desde_respuesta(r, "ms-custodia")
                url = r.json()["url"]

                # 2. Invocar al centralizador a través de la ACL
                r = await ctx.clientes.llamar(
                    "interoperabilidad",
                    "PUT",
                    "/gov/documentos/autenticacion",
                    json={"documento_ciudadano": documento_ciudadano, "url_documento": url, "titulo": doc["titulo"]},
                )
                if r.status_code != 200:
                    raise error_desde_respuesta(r, "ms-interoperabilidad")
                sol.respuesta_govcarpeta = r.json().get("mensaje")

                # 3. Sellar la evidencia localmente
                fecha = ahora()
                codigo = "SELLO-" + secrets.token_hex(8).upper()
                hash_sellado = calcular_hash_sellado(doc["id"], doc["hash_sha256"], fecha.isoformat(), cfg.nombre_operador, codigo)
                sello = SelloAutenticidad(
                    solicitud_id=sol.id,
                    documento_id=doc["id"],
                    ciudadano_id=doc["ciudadano_id"],
                    codigo=codigo,
                    titulo=doc["titulo"],
                    hash_documento=doc["hash_sha256"],
                    hash_sellado=hash_sellado,
                    firma=firmar_sello(hash_sellado),
                    emisor=cfg.nombre_operador,
                    fecha_sello=fecha.isoformat(),
                )
                s.add(sello)
                await s.flush()
                await cambiar_estado_documento(
                    doc["id"], "CERTIFICADO", sello=codigo, fecha_certificacion=fecha.isoformat()
                )
                sol.estado = EstadoSolicitud.AUTENTICADO
                sol.fecha_resolucion = ahora()
                await s.commit()
                log.info("Documento %s CERTIFICADO con %s", doc["id"], codigo)
                await publicar_seguro(
                    ctx.bus,
                    crear_evento(
                        DOCUMENTO_AUTENTICADO,
                        "/ms-certificacion",
                        {
                            "documento_id": doc["id"],
                            "ciudadano_id": doc["ciudadano_id"],
                            "titulo": doc["titulo"],
                            "sello": codigo,
                            "hash_sha256": doc["hash_sha256"],
                            "solicitud_id": sol.id,
                        },
                        sujeto=doc["id"],
                    ),
                )
            except Exception as e:  # noqa: BLE001 - cualquier fallo devuelve el documento a TEMPORAL
                await s.rollback()
                sol = await s.get(SolicitudAutenticacion, solicitud_id)
                sol.intentos += 1
                if isinstance(e, ErrorDominio):
                    error = f"{e.codigo}: {e.detalle or e.titulo}"
                else:
                    log.exception("Fallo inesperado autenticando %s", doc["id"])
                    error = f"ERROR_INTERNO: {e}"
                try:
                    await cambiar_estado_documento(doc["id"], "TEMPORAL")
                except ErrorDominio as e2:
                    log.error("No se pudo devolver %s a TEMPORAL: %s", doc["id"], e2)
                    error += f" | rollback pendiente: {e2.codigo}"
                sol.estado = EstadoSolicitud.FALLIDO
                sol.ultimo_error = error
                sol.fecha_resolucion = ahora()
                await s.commit()
                log.warning("Autenticación de %s FALLIDA: %s", doc["id"], error)
                await publicar_seguro(
                    ctx.bus,
                    crear_evento(
                        AUTENTICACION_FALLIDA,
                        "/ms-certificacion",
                        {
                            "documento_id": doc["id"],
                            "ciudadano_id": doc["ciudadano_id"],
                            "titulo": doc["titulo"],
                            "error": error,
                            "solicitud_id": sol.id,
                        },
                        sujeto=doc["id"],
                    ),
                )

    # ---------------------------------------------------------------- públicas
    @app.post(
        "/api/v1/documentos/{documento_id}/autenticacion",
        status_code=202,
        tags=["autenticacion"],
        summary="CU-04 Solicitar autenticación ante GovCarpeta",
    )
    async def solicitar(
        documento_id: str,
        tareas: BackgroundTasks,
        response: Response,
        usuario: Usuario = Depends(usuario_actual),
        s: AsyncSession = Depends(sesion_bd),
        idempotency_key: str | None = Header(None, max_length=64),
    ):
        clave = f"{usuario.ciudadano_id}:{idempotency_key}" if idempotency_key else None
        if clave:
            previa = await s.scalar(select(SolicitudAutenticacion).where(SolicitudAutenticacion.clave_idempotencia == clave))
            if previa:
                if previa.documento_id != documento_id:
                    raise ErrorDominio(422, "DATOS_INVALIDOS", "La Idempotency-Key ya se usó con otro documento")
                response.headers["Location"] = f"/api/v1/solicitudes/{previa.id}"
                response.headers["Idempotent-Replay"] = "true"
                return vista_solicitud(previa)

        r = await ctx.clientes.llamar("documentos", "GET", f"/internal/documentos/{documento_id}")
        if r.status_code == 404:
            raise ErrorDominio(404, "DOCUMENTO_NO_ENCONTRADO")
        if r.status_code != 200:
            raise error_desde_respuesta(r, "ms-documentos")
        doc = r.json()
        if doc["ciudadano_id"] != usuario.ciudadano_id:
            raise ErrorDominio(404, "DOCUMENTO_NO_ENCONTRADO")
        if doc["estado"] != "TEMPORAL":
            raise ErrorDominio(409, "ESTADO_INVALIDO", f"El documento está en estado {doc['estado']}")

        await cambiar_estado_documento(documento_id, "EN_AUTENTICACION")
        sol = SolicitudAutenticacion(documento_id=documento_id, ciudadano_id=usuario.ciudadano_id, clave_idempotencia=clave)
        s.add(sol)
        try:
            await s.commit()
        except IntegrityError:
            await s.rollback()
            await cambiar_estado_documento(documento_id, "TEMPORAL")
            raise ErrorDominio(409, "ESTADO_INVALIDO", "Ya hay una solicitud con esa Idempotency-Key")

        tareas.add_task(procesar, sol.id, doc, usuario.documento)
        response.headers["Location"] = f"/api/v1/solicitudes/{sol.id}"
        return vista_solicitud(sol)

    @app.get("/api/v1/solicitudes/{solicitud_id}", tags=["autenticacion"], summary="Estado de una solicitud")
    async def consultar(solicitud_id: str, usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        sol = await s.get(SolicitudAutenticacion, solicitud_id)
        if sol is None or sol.ciudadano_id != usuario.ciudadano_id:
            raise ErrorDominio(404, "SOLICITUD_NO_ENCONTRADA")
        return vista_solicitud(sol)

    @app.get("/api/v1/verificacion/{documento_id}", tags=["verificacion"], summary="Verificación pública (sin sesión)")
    async def verificar(
        documento_id: str,
        hash: str | None = Query(None, min_length=64, max_length=64, description="SHA-256 del archivo recibido"),
        s: AsyncSession = Depends(sesion_bd),
    ):
        sello = await s.scalar(
            select(SelloAutenticidad).where(
                (SelloAutenticidad.documento_id == documento_id) | (SelloAutenticidad.codigo == documento_id)
            )
        )
        if sello is None:
            raise ErrorDominio(404, "SELLO_NO_ENCONTRADO")
        esperado = calcular_hash_sellado(sello.documento_id, sello.hash_documento, sello.fecha_sello, sello.emisor, sello.codigo)
        integro = hmac.compare_digest(sello.hash_sellado, esperado) and hmac.compare_digest(
            sello.firma, firmar_sello(sello.hash_sellado)
        )
        coincide = None if hash is None else hmac.compare_digest(hash.lower().encode(), sello.hash_documento.encode())
        return {
            "autentico": bool(integro and coincide is not False),
            "documento_id": sello.documento_id,
            "titulo": sello.titulo,
            "hash_sha256": sello.hash_documento,
            "coincide_hash": coincide,
            "sello": sello.codigo,
            "emisor": sello.emisor,
            "fecha_certificacion": sello.fecha_sello,
            "autenticado_ante": "GovCarpeta (MinTIC)",
        }

    return app

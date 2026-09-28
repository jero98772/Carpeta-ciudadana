"""MS-09 ms-auditoria · Bitácora append-only con cadena de hashes (HU-04.6).

Cada registro guarda el hash del anterior:
    hash_registro = SHA-256(hash_anterior + contenido canónico del registro)
Si alguien altera un registro, la verificación de la cadena falla desde ese
punto. En PostgreSQL además un trigger impide UPDATE y DELETE.
"""

import asyncio
import hashlib
import hmac
import json
import logging

from fastapi import Depends, FastAPI, Header, Query
from sqlalchemy import Integer, String, Text, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, ahora, sesion_bd
from micarpeta.comun.errores import ErrorDominio

log = logging.getLogger("micarpeta.auditoria")

GENESIS = "0" * 64

TIPOS = {
    "co.micarpeta.ciudadano.registrado": "CIUDADANO_REGISTRADO",
    "co.micarpeta.documento.cargado": "DOCUMENTO_CARGADO",
    "co.micarpeta.documento.autenticado": "DOCUMENTO_AUTENTICADO",
    "co.micarpeta.documento.autenticacion_fallida": "AUTENTICACION_FALLIDA",
    "co.micarpeta.sesion.login_exitoso": "LOGIN_EXITOSO",
    "co.micarpeta.sesion.login_fallido": "LOGIN_FALLIDO",
}

# Datos personales que no se copian a la bitácora
CAMPOS_EXCLUIDOS = {"correo", "nombre_completo", "direccion_unica"}


class Base(DeclarativeBase):
    pass


class RegistroAuditoria(Base):
    __tablename__ = "registros_auditoria"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evento_id: Mapped[str] = mapped_column(String(36), unique=True)
    tipo: Mapped[str] = mapped_column(String(40), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    recurso: Mapped[str | None] = mapped_column(String(120), nullable=True)
    resultado: Mapped[str] = mapped_column(String(20))
    cargo_util: Mapped[str] = mapped_column(Text)
    fecha: Mapped[str] = mapped_column(String(40))
    hash_anterior: Mapped[str] = mapped_column(String(64))
    hash_registro: Mapped[str] = mapped_column(String(64))


def calcular_hash(hash_anterior: str, r: RegistroAuditoria) -> str:
    canonico = json.dumps(
        {
            "evento_id": r.evento_id,
            "tipo": r.tipo,
            "actor_id": r.actor_id,
            "recurso": r.recurso,
            "resultado": r.resultado,
            "cargo_util": r.cargo_util,
            "fecha": r.fecha,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256((hash_anterior + canonico).encode()).hexdigest()


TRIGGER_POSTGRES = [
    """
    CREATE OR REPLACE FUNCTION bitacora_append_only() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'La bitácora de auditoría es append-only';
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS registros_inmutables ON registros_auditoria",
    """
    CREATE TRIGGER registros_inmutables BEFORE UPDATE OR DELETE ON registros_auditoria
    FOR EACH ROW EXECUTE FUNCTION bitacora_append_only()
    """,
]


def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    cfg = ctx.config
    db = BaseDatos(db_url or cfg.url_bd("auditoria"))
    candado = asyncio.Lock()  # un único escritor por proceso mantiene la cadena lineal

    async def registrar(evento: dict) -> None:
        datos = dict(evento.get("data") or {})
        tipo = TIPOS.get(evento["type"], evento["type"])
        async with candado, db.sesiones() as s:
            if await s.scalar(select(RegistroAuditoria.id).where(RegistroAuditoria.evento_id == evento["id"])):
                return  # idempotencia
            ultimo = await s.scalar(select(RegistroAuditoria).order_by(RegistroAuditoria.id.desc()).limit(1))
            registro = RegistroAuditoria(
                evento_id=evento["id"],
                tipo=tipo,
                actor_id=datos.get("ciudadano_id"),
                recurso=evento.get("subject"),
                resultado="FALLIDO" if tipo in {"AUTENTICACION_FALLIDA", "LOGIN_FALLIDO"} else "EXITOSO",
                cargo_util=json.dumps({k: v for k, v in datos.items() if k not in CAMPOS_EXCLUIDOS}, sort_keys=True, ensure_ascii=False),
                fecha=evento.get("time") or ahora().isoformat(),
                hash_anterior=ultimo.hash_registro if ultimo else GENESIS,
            )
            registro.hash_registro = calcular_hash(registro.hash_anterior, registro)
            s.add(registro)
            try:
                await s.commit()
            except IntegrityError:
                await s.rollback()

    async def al_iniciar(app: FastAPI) -> None:
        if db.dialecto == "postgresql":
            async with db.motor.begin() as conexion:
                for sentencia in TRIGGER_POSTGRES:
                    await conexion.execute(text(sentencia))
        await ctx.bus.suscribir("ms-auditoria", ["co.micarpeta.#"], registrar)

    app = crear_app_base(
        "ms-auditoria",
        ctx,
        descripcion="Bitácora de auditoría append-only con cadena de hashes verificable.",
        db=db,
        metadata=Base.metadata,
        al_iniciar=al_iniciar,
        gestionar_ciclo=gestionar_ciclo,
    )

    def exigir_admin(x_admin_key: str | None = Header(None)) -> None:
        if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), cfg.admin_api_key.encode()):
            raise ErrorDominio(403, "ACCESO_DENEGADO", "Se requiere la cabecera X-Admin-Key")

    async def verificar_cadena(s: AsyncSession) -> dict:
        anterior, total = GENESIS, 0
        for r in (await s.scalars(select(RegistroAuditoria).order_by(RegistroAuditoria.id))).all():
            total += 1
            if r.hash_anterior != anterior or calcular_hash(anterior, r) != r.hash_registro:
                return {"valida": False, "total_registros": total, "primer_registro_alterado": r.id}
            anterior = r.hash_registro
        return {"valida": True, "total_registros": total, "primer_registro_alterado": None, "ultimo_hash": anterior}

    app.state.verificar_cadena = verificar_cadena

    @app.get("/api/v1/auditoria/verificacion", tags=["auditoria"], dependencies=[Depends(exigir_admin)])
    async def verificacion(s: AsyncSession = Depends(sesion_bd)):
        return await verificar_cadena(s)

    @app.get("/api/v1/auditoria/registros", tags=["auditoria"], dependencies=[Depends(exigir_admin)])
    async def registros(
        tipo: str | None = None, limite: int = Query(50, ge=1, le=500), s: AsyncSession = Depends(sesion_bd)
    ):
        consulta = select(RegistroAuditoria).order_by(RegistroAuditoria.id.desc()).limit(limite)
        if tipo:
            consulta = consulta.where(RegistroAuditoria.tipo == tipo)
        return {
            "registros": [
                {
                    "id": r.id,
                    "tipo": r.tipo,
                    "actor_id": r.actor_id,
                    "recurso": r.recurso,
                    "resultado": r.resultado,
                    "fecha": r.fecha,
                    "hash_registro": r.hash_registro,
                    "hash_anterior": r.hash_anterior,
                }
                for r in (await s.scalars(consulta)).all()
            ]
        }

    return app

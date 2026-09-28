"""Acceso a datos con SQLAlchemy 2.0 asíncrono. Una base de datos por servicio.

Las referencias entre servicios se guardan como cadenas (UUID) sin claves
foráneas físicas: la consistencia entre dominios se logra con sagas y eventos.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Request
from sqlalchemy import DateTime, MetaData
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.types import TypeDecorator

log = logging.getLogger("micarpeta.db")


def ahora() -> datetime:
    return datetime.now(UTC)


def nuevo_id() -> str:
    return str(uuid.uuid4())


class FechaUTC(TypeDecorator):
    """Fecha siempre en UTC con zona horaria, también sobre SQLite (que no la guarda)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value if value.tzinfo else value.replace(tzinfo=UTC)


class BaseDatos:
    def __init__(self, url: str):
        self.url = url
        if url.startswith("sqlite"):
            ruta = url.split(":///", 1)[-1]
            if ruta and ruta != ":memory:":
                Path(ruta).parent.mkdir(parents=True, exist_ok=True)
            self.motor = create_async_engine(url, connect_args={"timeout": 30})
        else:
            self.motor = create_async_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)
        self.sesiones = async_sessionmaker(self.motor, expire_on_commit=False)

    @property
    def dialecto(self) -> str:
        return self.motor.dialect.name

    async def crear_tablas(self, metadata: MetaData, intentos: int = 15) -> None:
        """Crea las tablas del servicio. Reintenta mientras la base de datos arranca."""
        for intento in range(1, intentos + 1):
            try:
                async with self.motor.begin() as conexion:
                    await conexion.run_sync(metadata.create_all)
                return
            except Exception as e:  # conexión rechazada, BD iniciando, etc.
                if intento == intentos:
                    raise
                log.warning("Base de datos no disponible (%s), reintento %s/%s", e, intento, intentos)
                await asyncio.sleep(2)

    async def cerrar(self) -> None:
        await self.motor.dispose()


async def sesion_bd(request: Request):
    """Dependencia de FastAPI: una sesión por petición sobre la BD del servicio."""
    async with request.app.state.db.sesiones() as sesion:
        yield sesion


__all__ = ["AsyncSession", "BaseDatos", "FechaUTC", "ahora", "nuevo_id", "sesion_bd"]

from datetime import datetime

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from micarpeta.comun.db import FechaUTC, ahora, nuevo_id


class Base(DeclarativeBase):
    pass


class Credencial(Base):
    __tablename__ = "credenciales"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    ciudadano_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)  # referencia lógica
    documento: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    hash_password: Mapped[str] = mapped_column(String(255))
    algoritmo: Mapped[str] = mapped_column(String(20), default="argon2id")
    intentos_fallidos: Mapped[int] = mapped_column(Integer, default=0)
    bloqueado_hasta: Mapped[datetime | None] = mapped_column(FechaUTC, nullable=True)
    ultimo_acceso: Mapped[datetime | None] = mapped_column(FechaUTC, nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)
    fecha_cambio_password: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)


class RefreshToken(Base):
    """Refresh tokens opacos y rotativos. Solo se guarda su hash SHA-256."""

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    credencial_id: Mapped[str] = mapped_column(String(36), index=True)
    familia: Mapped[str] = mapped_column(String(36), index=True)
    hash_token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    emitido_en: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)
    expira_en: Mapped[datetime] = mapped_column(FechaUTC)
    revocado: Mapped[bool] = mapped_column(Boolean, default=False)
    revocado_en: Mapped[datetime | None] = mapped_column(FechaUTC, nullable=True)
    reemplazado_por: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ip_origen: Mapped[str | None] = mapped_column(String(64), nullable=True)


class IntentoAcceso(Base):
    __tablename__ = "intentos_acceso"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    documento: Mapped[str] = mapped_column(String(20), index=True)
    exitoso: Mapped[bool] = mapped_column(Boolean)
    motivo: Mapped[str] = mapped_column(String(40))
    ip_origen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fecha: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)

from datetime import datetime

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from micarpeta.comun.db import FechaUTC, ahora, nuevo_id


class Base(DeclarativeBase):
    pass


class EstadoCiudadano:
    PENDIENTE = "PENDIENTE"
    ACTIVO = "ACTIVO"
    TRASLADADO = "TRASLADADO"
    INACTIVO = "INACTIVO"


class EstadoSaga:
    EN_CURSO = "EN_CURSO"
    COMPLETADA = "COMPLETADA"
    COMPENSADA = "COMPENSADA"
    RECHAZADA = "RECHAZADA"
    COMPENSACION_PENDIENTE = "COMPENSACION_PENDIENTE"


class Ciudadano(Base):
    __tablename__ = "ciudadanos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    documento: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    tipo_documento: Mapped[str] = mapped_column(String(5), default="CC")
    nombre_completo: Mapped[str] = mapped_column(String(150))
    correo: Mapped[str] = mapped_column(String(254))
    direccion_fisica: Mapped[str] = mapped_column(String(250))
    direccion_unica: Mapped[str | None] = mapped_column(String(254), unique=True, nullable=True)
    estado: Mapped[str] = mapped_column(String(20), default=EstadoCiudadano.PENDIENTE, index=True)
    operador: Mapped[str] = mapped_column(String(100))
    fecha_registro: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)
    fecha_actualizacion: Mapped[datetime] = mapped_column(FechaUTC, default=ahora, onupdate=ahora)


class SagaRegistro(Base):
    """Bitácora de la saga de registro: paso actual, estado final y último error."""

    __tablename__ = "sagas_registro"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    ciudadano_id: Mapped[str] = mapped_column(String(36), index=True)  # referencia lógica
    documento: Mapped[str] = mapped_column(String(20), index=True)
    paso_actual: Mapped[str] = mapped_column(String(20))
    estado: Mapped[str] = mapped_column(String(30), default=EstadoSaga.EN_CURSO)
    pasos_completados: Mapped[str] = mapped_column(Text, default="")
    intentos: Mapped[int] = mapped_column(Integer, default=1)
    ultimo_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fecha_inicio: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)
    fecha_actualizacion: Mapped[datetime] = mapped_column(FechaUTC, default=ahora, onupdate=ahora)

"""MS-01 ms-identidad · Ciclo de vida del ciudadano y saga de registro (CU-01, ADR-004).

La saga es orquestada: VALIDAR -> AFILIAR -> CREDENCIAL -> ACTIVAR.
Si un paso falla, se ejecutan en orden inverso las compensaciones de los pasos
ya completados (p. ej. DELETE /unregisterCitizen), de modo que nunca queda un
ciudadano ACTIVO local sin estar afiliado en GovCarpeta, ni al revés.
"""

import logging
import re
import unicodedata
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, sesion_bd
from micarpeta.comun.errores import ErrorDominio, error_desde_respuesta
from micarpeta.comun.eventos import CIUDADANO_REGISTRADO, crear_evento, publicar_seguro
from micarpeta.comun.seguridad import Usuario, usuario_actual

from .modelos import Base, Ciudadano, EstadoCiudadano, EstadoSaga, SagaRegistro

log = logging.getLogger("micarpeta.identidad")


# ============================================================ dirección única
def generar_direccion_unica(nombre_completo: str, documento: str, dominio: str, completa: bool = False) -> str:
    """"Ana María Restrepo", "1020304050" -> "ana.maria.4050@micarpeta.co" (solo ASCII)."""
    ascii_ = unicodedata.normalize("NFKD", nombre_completo).encode("ascii", "ignore").decode().lower()
    palabras = re.findall(r"[a-z0-9]+", ascii_)
    base = ".".join(palabras[:2]) or "ciudadano"
    sufijo = documento if completa else documento[-4:]
    return f"{base}.{sufijo}@{dominio}"


# ============================================================ entrada
class SolicitudRegistro(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    documento: str
    tipo_documento: Literal["CC", "CE", "TI"] = "CC"
    nombre_completo: str
    correo: EmailStr
    direccion: str
    password: str

    @field_validator("documento")
    @classmethod
    def _documento(cls, v: str) -> str:
        if not re.fullmatch(r"\d{6,10}", v):
            raise ValueError("el documento debe tener entre 6 y 10 dígitos")
        return v

    @field_validator("nombre_completo")
    @classmethod
    def _nombre(cls, v: str) -> str:
        if len(v) < 3 or not re.search(r"[^\W\d_]", v):
            raise ValueError("el nombre debe tener al menos 3 caracteres y contener letras")
        return re.sub(r"\s+", " ", v)

    @field_validator("direccion")
    @classmethod
    def _direccion(cls, v: str) -> str:
        if len(v) < 5:
            raise ValueError("la dirección debe tener al menos 5 caracteres")
        return v

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        if len(v) < 10 or not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
            raise ValueError("la contraseña debe tener al menos 10 caracteres, con letras y números")
        return v


def vista(c: Ciudadano) -> dict:
    return {
        "id": c.id,
        "documento": c.documento,
        "tipo_documento": c.tipo_documento,
        "nombre_completo": c.nombre_completo,
        "correo": c.correo,
        "direccion": c.direccion_fisica,
        "direccion_unica": c.direccion_unica,
        "estado": c.estado,
        "operador": c.operador,
        "fecha_registro": c.fecha_registro.isoformat() if c.fecha_registro else None,
    }


# ============================================================ saga
Accion = Callable[[], Awaitable[None]]


class SagaRegistroCiudadano:
    def __init__(self, ctx: Contexto, sesion: AsyncSession, ciudadano: Ciudadano, saga: SagaRegistro, password: str):
        self.ctx = ctx
        self.s = sesion
        self.c = ciudadano
        self.saga = saga
        self._password = password

    async def ejecutar(self) -> None:
        pasos: list[tuple[str, Accion, Accion | None]] = [
            ("VALIDAR", self._validar_disponibilidad, None),
            ("AFILIAR", self._afiliar_en_govcarpeta, self._desafiliar_de_govcarpeta),
            ("CREDENCIAL", self._crear_credencial, self._eliminar_credencial),
            ("ACTIVAR", self._activar, None),
        ]
        completados: list[tuple[str, Accion | None]] = []
        for nombre, accion, compensacion in pasos:
            self.saga.paso_actual = nombre
            await self.s.commit()
            try:
                await accion()
            except Exception as e:  # noqa: BLE001 - cualquier fallo dispara la compensación
                error = await self._normalizar_error(e)
                await self._compensar(completados, error)
                raise error from e
            completados.append((nombre, compensacion))
            self.saga.pasos_completados = ",".join(n for n, _ in completados)

        self.saga.estado = EstadoSaga.COMPLETADA
        await self.s.commit()
        log.info("Saga %s COMPLETADA para %s", self.saga.id, self.c.documento)
        await publicar_seguro(
            self.ctx.bus,
            crear_evento(
                CIUDADANO_REGISTRADO,
                "/ms-identidad",
                {
                    "ciudadano_id": self.c.id,
                    "documento": self.c.documento,
                    "nombre_completo": self.c.nombre_completo,
                    "correo": self.c.correo,
                    "direccion_unica": self.c.direccion_unica,
                    "operador": self.c.operador,
                },
                sujeto=self.c.id,
            ),
        )

    async def _normalizar_error(self, e: Exception) -> ErrorDominio:
        if isinstance(e, SQLAlchemyError):
            await self.s.rollback()
            await self.s.refresh(self.c)
            await self.s.refresh(self.saga)
            log.exception("Error de base de datos en la saga %s", self.saga.id)
            return ErrorDominio(503, "SERVICIO_NO_DISPONIBLE", "Error de persistencia en ms-identidad")
        if isinstance(e, ErrorDominio):
            return e
        log.exception("Error inesperado en la saga %s", self.saga.id)
        return ErrorDominio(500, "ERROR_INTERNO", str(e))

    async def _compensar(self, completados: list[tuple[str, Accion | None]], error: ErrorDominio) -> None:
        fallas = []
        for nombre, compensacion in reversed(completados):
            if compensacion is None:
                continue
            try:
                await compensacion()
                log.info("Saga %s: compensado el paso %s", self.saga.id, nombre)
            except Exception as e:  # noqa: BLE001
                fallas.append(f"{nombre}: {e}")
                log.error("Saga %s: la compensación de %s falló: %s", self.saga.id, nombre, e)

        self.saga.ultimo_error = f"{error.codigo}: {error.detalle or error.titulo}"
        if fallas:
            self.saga.ultimo_error += " | compensación pendiente: " + "; ".join(fallas)

        if error.codigo == "CIUDADANO_YA_AFILIADO":
            # Rechazo de negocio: no debe quedar ningún registro local del ciudadano.
            self.saga.estado = EstadoSaga.RECHAZADA
            await self.s.delete(self.c)
        else:
            self.c.estado = EstadoCiudadano.PENDIENTE
            self.c.direccion_unica = None
            self.saga.estado = EstadoSaga.COMPENSACION_PENDIENTE if fallas else EstadoSaga.COMPENSADA
        await self.s.commit()

    # ---- paso 1
    async def _validar_disponibilidad(self) -> None:
        r = await self.ctx.clientes.llamar("interoperabilidad", "GET", f"/gov/ciudadanos/{self.c.documento}/disponibilidad")
        if r.status_code != 200:
            raise error_desde_respuesta(r, "ms-interoperabilidad")
        datos = r.json()
        if not datos["disponible"]:
            actual = datos.get("operador_actual")
            if actual and actual.lower() == self.ctx.config.nombre_operador.lower():
                # Ya está con nosotros en GovCarpeta (p. ej. una compensación anterior quedó
                # pendiente): se continúa y el paso AFILIAR es idempotente en la ACL.
                return
            raise ErrorDominio(
                409,
                "CIUDADANO_YA_AFILIADO",
                f"El ciudadano ya está afiliado al operador {actual or 'desconocido'}. "
                "Para cambiarse debe solicitar el traslado desde su operador actual.",
                extra={"operador_actual": actual},
            )

    # ---- paso 2
    async def _afiliar_en_govcarpeta(self) -> None:
        r = await self.ctx.clientes.llamar(
            "interoperabilidad",
            "POST",
            "/gov/ciudadanos",
            json={
                "documento": self.c.documento,
                "nombre": self.c.nombre_completo,
                "direccion": self.c.direccion_fisica,
                "correo": self.c.correo,
            },
        )
        if r.status_code != 201:
            raise error_desde_respuesta(r, "ms-interoperabilidad")

    async def _desafiliar_de_govcarpeta(self) -> None:
        r = await self.ctx.clientes.llamar("interoperabilidad", "DELETE", f"/gov/ciudadanos/{self.c.documento}")
        if r.status_code != 200:
            raise error_desde_respuesta(r, "ms-interoperabilidad")

    # ---- paso 3
    async def _crear_credencial(self) -> None:
        r = await self.ctx.clientes.llamar(
            "autenticacion",
            "POST",
            "/internal/credenciales",
            json={"ciudadano_id": self.c.id, "documento": self.c.documento, "password": self._password},
        )
        if r.status_code != 201:
            raise error_desde_respuesta(r, "ms-autenticacion")

    async def _eliminar_credencial(self) -> None:
        r = await self.ctx.clientes.llamar("autenticacion", "DELETE", f"/internal/credenciales/{self.c.id}")
        if r.status_code not in (204, 404):
            raise error_desde_respuesta(r, "ms-autenticacion")

    # ---- paso 4
    async def _activar(self) -> None:
        dominio = self.ctx.config.dominio_direcciones
        direccion = generar_direccion_unica(self.c.nombre_completo, self.c.documento, dominio)
        ocupada = await self.s.scalar(
            select(Ciudadano.id).where(Ciudadano.direccion_unica == direccion, Ciudadano.id != self.c.id)
        )
        if ocupada:
            direccion = generar_direccion_unica(self.c.nombre_completo, self.c.documento, dominio, completa=True)
        self.c.direccion_unica = direccion
        self.c.estado = EstadoCiudadano.ACTIVO
        await self.s.commit()


# ============================================================ app
def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    db = BaseDatos(db_url or ctx.config.url_bd("identidad"))
    app = crear_app_base(
        "ms-identidad",
        ctx,
        descripcion="Ciclo de vida del ciudadano y saga de registro con compensación.",
        db=db,
        metadata=Base.metadata,
        gestionar_ciclo=gestionar_ciclo,
    )

    @app.post("/api/v1/ciudadanos", status_code=201, tags=["ciudadanos"], summary="CU-01 Registrar ciudadano")
    async def registrar(datos: SolicitudRegistro, s: AsyncSession = Depends(sesion_bd)):
        ciudadano = await s.scalar(select(Ciudadano).where(Ciudadano.documento == datos.documento))
        if ciudadano and ciudadano.estado != EstadoCiudadano.PENDIENTE:
            raise ErrorDominio(409, "CIUDADANO_YA_REGISTRADO", "Ya existe una carpeta para este documento")

        if ciudadano is None:  # si quedó PENDIENTE de un intento compensado, se reutiliza
            ciudadano = Ciudadano(documento=datos.documento, operador=ctx.config.nombre_operador)
            s.add(ciudadano)
        ciudadano.tipo_documento = datos.tipo_documento
        ciudadano.nombre_completo = datos.nombre_completo
        ciudadano.correo = str(datos.correo)
        ciudadano.direccion_fisica = datos.direccion
        ciudadano.estado = EstadoCiudadano.PENDIENTE
        try:
            await s.flush()
        except IntegrityError:
            await s.rollback()
            raise ErrorDominio(409, "CIUDADANO_YA_REGISTRADO", "Ya existe un registro en curso para este documento")

        previas = await s.scalar(select(func.count()).select_from(SagaRegistro).where(SagaRegistro.documento == datos.documento))
        saga = SagaRegistro(
            ciudadano_id=ciudadano.id, documento=datos.documento, paso_actual="VALIDAR", intentos=(previas or 0) + 1
        )
        s.add(saga)
        await s.commit()

        await SagaRegistroCiudadano(ctx, s, ciudadano, saga, datos.password).ejecutar()
        return vista(ciudadano)

    @app.get("/api/v1/ciudadanos/yo", tags=["ciudadanos"], summary="Perfil del ciudadano autenticado")
    async def perfil(usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        c = await s.get(Ciudadano, usuario.ciudadano_id)
        if c is None:
            raise ErrorDominio(404, "CIUDADANO_NO_ENCONTRADO")
        return vista(c)

    @app.get("/internal/ciudadanos/documento/{documento}", tags=["interno"])
    async def por_documento(documento: str, s: AsyncSession = Depends(sesion_bd)):
        c = await s.scalar(select(Ciudadano).where(Ciudadano.documento == documento))
        if c is None:
            raise ErrorDominio(404, "CIUDADANO_NO_ENCONTRADO")
        return vista(c)

    @app.get("/internal/ciudadanos/{ciudadano_id}", tags=["interno"])
    async def por_id(ciudadano_id: str, s: AsyncSession = Depends(sesion_bd)):
        c = await s.get(Ciudadano, ciudadano_id)
        if c is None:
            raise ErrorDominio(404, "CIUDADANO_NO_ENCONTRADO")
        return vista(c)

    return app

"""Esqueleto común de cada microservicio FastAPI."""

import hmac
import logging
import uuid
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import MetaData
from starlette.datastructures import Headers, MutableHeaders

from .clientes import id_solicitud
from .contexto import Contexto
from .db import BaseDatos
from .errores import instalar_manejadores, respuesta_problema

Gancho = Callable[[FastAPI], Awaitable[None]]


class MiddlewareBase:
    """Propaga X-Request-ID y protege las rutas internas con el token interno."""

    def __init__(self, app, token_interno: str, rutas_internas: tuple[str, ...]):
        self.app = app
        self.token_interno = token_interno
        self.rutas_internas = rutas_internas

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cabeceras = Headers(scope=scope)
        rid = cabeceras.get("x-request-id") or uuid.uuid4().hex
        marca = id_solicitud.set(rid)
        try:
            if self.rutas_internas and scope["path"].startswith(self.rutas_internas):
                recibido = cabeceras.get("x-token-interno", "")
                if not hmac.compare_digest(recibido.encode(), self.token_interno.encode()):
                    resp = respuesta_problema(403, "ACCESO_DENEGADO", detalle="Ruta de uso interno", instancia=scope["path"])
                    return await resp(scope, receive, send)

            async def enviar(mensaje):
                if mensaje["type"] == "http.response.start":
                    MutableHeaders(scope=mensaje)["X-Request-ID"] = rid
                await send(mensaje)

            await self.app(scope, receive, enviar)
        finally:
            id_solicitud.reset(marca)


def crear_app_base(
    nombre: str,
    ctx: Contexto,
    *,
    descripcion: str = "",
    db: BaseDatos | None = None,
    metadata: MetaData | None = None,
    al_iniciar: Gancho | None = None,
    al_detener: Gancho | None = None,
    gestionar_ciclo: bool = False,
    rutas_internas: tuple[str, ...] = ("/internal",),
) -> FastAPI:
    """Crea la app de un microservicio.

    ``gestionar_ciclo=True`` (modo contenedor) hace que el lifespan de FastAPI
    conecte la infraestructura y cree las tablas. En pruebas y en modo local
    quien arma el sistema llama a ``app.state.iniciar()`` explícitamente.
    """

    async def iniciar() -> None:
        if db is not None and metadata is not None:
            await db.crear_tablas(metadata)
        if al_iniciar:
            await al_iniciar(app)

    async def detener() -> None:
        if al_detener:
            await al_detener(app)
        if db is not None:
            await db.cerrar()

    @asynccontextmanager
    async def ciclo(_app: FastAPI):
        await ctx.iniciar()
        await iniciar()
        try:
            yield
        finally:
            await detener()
            await ctx.detener()

    app = FastAPI(
        title=f"{nombre} · MiCarpeta CO",
        description=descripcion,
        version="1.0.0",
        lifespan=ciclo if gestionar_ciclo else None,
    )
    app.state.nombre = nombre
    app.state.ctx = ctx
    app.state.db = db
    app.state.iniciar = iniciar
    app.state.detener = detener
    instalar_manejadores(app)
    app.add_middleware(MiddlewareBase, token_interno=ctx.config.token_interno, rutas_internas=rutas_internas)

    @app.get("/salud", tags=["salud"], summary="Estado del servicio")
    async def salud():
        return {"servicio": nombre, "estado": "ok"}

    return app


def configurar_logs() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

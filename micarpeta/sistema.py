"""Arma los nueve microservicios en un solo proceso.

Cada servicio sigue siendo una app FastAPI independiente, con su propia base
de datos; la única diferencia con el despliegue en contenedores es que se
llaman entre sí con el transporte ASGI de httpx en lugar de por la red.
Lo usan las pruebas (sección 8 del documento) y el modo local sin Docker.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI

from micarpeta.comun.cache import CacheMemoria
from micarpeta.comun.clientes import Clientes
from micarpeta.comun.config import Config
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.eventos import BusMemoria
from micarpeta.servicios.auditoria.app import crear_app as crear_auditoria
from micarpeta.servicios.autenticacion.app import crear_app as crear_autenticacion
from micarpeta.servicios.certificacion.app import crear_app as crear_certificacion
from micarpeta.servicios.custodia.app import crear_app as crear_custodia
from micarpeta.servicios.documentos.app import crear_app as crear_documentos
from micarpeta.servicios.gateway.app import crear_app as crear_gateway
from micarpeta.servicios.govcarpeta_mock.app import (
    EstadoGovCarpeta,
    crear_app_govcarpeta,
)
from micarpeta.servicios.identidad.app import crear_app as crear_identidad
from micarpeta.servicios.interoperabilidad.app import (
    crear_app as crear_interoperabilidad,
)
from micarpeta.servicios.notificaciones.app import crear_app as crear_notificaciones

FABRICAS = {
    "identidad": crear_identidad,
    "autenticacion": crear_autenticacion,
    "documentos": crear_documentos,
    "custodia": crear_custodia,
    "certificacion": crear_certificacion,
    "interoperabilidad": crear_interoperabilidad,
    "notificaciones": crear_notificaciones,
    "auditoria": crear_auditoria,
    "gateway": crear_gateway,
}


@dataclass
class Sistema:
    config: Config
    ctx: Contexto
    apps: dict[str, FastAPI]
    gov: EstadoGovCarpeta | None = None
    gov_app: FastAPI | None = None
    _clientes_abiertos: list = field(default_factory=list)

    @property
    def bus(self) -> BusMemoria:
        return self.ctx.bus

    def cliente(self, servicio: str = "gateway", base_url: str = "http://micarpeta.test") -> httpx.AsyncClient:
        """Cliente HTTP contra un servicio (por defecto el gateway, como lo haría el portal)."""
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.apps[servicio]), base_url=base_url, timeout=30)
        self._clientes_abiertos.append(c)
        return c

    def sesion(self, servicio: str):
        """Sesión directa a la base de datos de un servicio (para inspección en pruebas)."""
        return self.apps[servicio].state.db.sesiones()

    async def cerrar(self) -> None:
        for c in self._clientes_abiertos:
            await c.aclose()
        for app in self.apps.values():
            await app.state.detener()
        await self.ctx.detener()


async def construir_sistema(
    config: Config,
    url_bd: Callable[[str], str] | None = None,
    usar_simulador_govcarpeta: bool = True,
) -> Sistema:
    clientes = Clientes(config.token_interno, config.timeout_interno_segundos)
    ctx = Contexto(config, BusMemoria(), CacheMemoria(), clientes)

    gov = gov_app = None
    if usar_simulador_govcarpeta:
        gov = EstadoGovCarpeta()
        config.govcarpeta_operator_id = gov.registrar_operador(
            config.nombre_operador, config.govcarpeta_operator_id or None
        )
        gov_app = crear_app_govcarpeta(gov)
        clientes.registrar_asgi("govcarpeta", gov_app)
        config.govcarpeta_url = "simulador (en proceso)"
    else:
        clientes.registrar_url("govcarpeta", config.govcarpeta_url)

    apps: dict[str, FastAPI] = {}
    for nombre, fabrica in FABRICAS.items():
        kwargs = {"db_url": url_bd(nombre)} if url_bd and nombre not in ("gateway", "interoperabilidad") else {}
        apps[nombre] = fabrica(ctx, **kwargs)
        clientes.registrar_asgi(nombre, apps[nombre])

    await ctx.iniciar()
    for app in apps.values():
        await app.state.iniciar()
    return Sistema(config=config, ctx=ctx, apps=apps, gov=gov, gov_app=gov_app)

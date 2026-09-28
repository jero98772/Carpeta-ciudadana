"""Dependencias de infraestructura que comparte un proceso: configuración,
bus de eventos, caché, clientes hacia otros servicios y verificador JWT."""

import logging

from .cache import CacheMemoria, CacheRedis
from .clientes import Clientes
from .config import SERVICIOS, Config
from .eventos import BusMemoria, BusRabbitMQ
from .seguridad import VerificadorJWT

log = logging.getLogger("micarpeta")


class Contexto:
    def __init__(self, config: Config, bus, cache, clientes: Clientes):
        self.config = config
        self.bus = bus
        self.cache = cache
        self.clientes = clientes
        self.verificador = VerificadorJWT(clientes, config.jwt_emisor, config.jwt_audiencia)

    @classmethod
    def desde_config(cls, config: Config | None = None) -> "Contexto":
        """Modo distribuido: infraestructura real según la configuración."""
        config = config or Config()
        bus = BusRabbitMQ(config.rabbitmq_url) if config.bus == "rabbitmq" else BusMemoria()
        cache = CacheRedis(config.redis_url) if config.cache == "redis" else CacheMemoria()
        clientes = Clientes(config.token_interno, config.timeout_interno_segundos)
        for servicio in SERVICIOS:
            clientes.registrar_url(servicio, config.url_servicio(servicio))
        clientes.registrar_url("govcarpeta", config.govcarpeta_url)
        if config.entorno == "produccion":
            for campo in ("token_interno", "secreto_urls", "clave_sello", "admin_api_key"):
                if getattr(config, campo).startswith("cambiar-"):
                    log.warning("⚠ %s tiene el valor por defecto; cámbialo antes de producción", campo.upper())
        return cls(config, bus, cache, clientes)

    async def iniciar(self) -> None:
        await self.bus.iniciar()

    async def detener(self) -> None:
        await self.bus.detener()
        await self.clientes.cerrar()
        await self.cache.cerrar()

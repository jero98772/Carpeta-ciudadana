"""Cómo llega un microservicio a otro.

El mismo código funciona en dos modos:
- distribuido: cada servicio es un contenedor y se llama por HTTP (URL);
- un solo proceso: se llama a la app FastAPI directamente con el transporte
  ASGI de httpx (pruebas y modo local), sin abrir puertos.
"""

import contextvars

import httpx

from .errores import ErrorDominio

id_solicitud: contextvars.ContextVar[str] = contextvars.ContextVar("id_solicitud", default="-")


class Clientes:
    def __init__(self, token_interno: str, timeout: float = 20.0):
        self.token_interno = token_interno
        self.timeout = timeout
        self._destinos: dict[str, tuple[str, httpx.AsyncBaseTransport | None]] = {}
        self._clientes: dict[str, httpx.AsyncClient] = {}

    def registrar_url(self, nombre: str, url: str) -> None:
        self._destinos[nombre] = (url.rstrip("/"), None)
        self._clientes.pop(nombre, None)

    def registrar_asgi(self, nombre: str, app) -> None:
        self.registrar_transporte(nombre, httpx.ASGITransport(app=app, raise_app_exceptions=False))

    def registrar_transporte(self, nombre: str, transporte: httpx.AsyncBaseTransport, base_url: str | None = None) -> None:
        self._destinos[nombre] = (base_url or f"http://{nombre}", transporte)
        self._clientes.pop(nombre, None)

    def cliente(self, nombre: str) -> httpx.AsyncClient:
        if nombre not in self._destinos:
            raise ErrorDominio(503, "SERVICIO_NO_DISPONIBLE", f"Destino desconocido: {nombre}")
        if nombre not in self._clientes:
            base, transporte = self._destinos[nombre]
            self._clientes[nombre] = httpx.AsyncClient(base_url=base, transport=transporte, timeout=self.timeout)
        return self._clientes[nombre]

    async def llamar(self, nombre: str, metodo: str, ruta: str, **kwargs) -> httpx.Response:
        """Llamada interna entre microservicios (lleva el token interno y el id de correlación)."""
        cabeceras = dict(kwargs.pop("headers", None) or {})
        cabeceras["X-Token-Interno"] = self.token_interno
        cabeceras.setdefault("X-Request-ID", id_solicitud.get())
        try:
            return await self.cliente(nombre).request(metodo, ruta, headers=cabeceras, **kwargs)
        except httpx.TransportError as e:
            raise ErrorDominio(503, "SERVICIO_NO_DISPONIBLE", f"{nombre} no responde ({type(e).__name__})") from e

    async def cerrar(self) -> None:
        for c in self._clientes.values():
            await c.aclose()
        self._clientes.clear()

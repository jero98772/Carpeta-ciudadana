"""MS-00 ms-gateway · Puerta de entrada (API Gateway / BFF).

- Enruta /api/v1/... al microservicio dueño de cada recurso.
- Valida el JWT en el borde (firma RS256 con la clave pública del JWKS,
  expiración, emisor, audiencia y revocación por jti).
- Rate limiting por IP (más estricto en el login).
- Nunca expone las rutas /internal ni /gov.
- Sirve el portal web del ciudadano en "/".
"""

import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.clientes import id_solicitud
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.errores import ErrorDominio, respuesta_problema
from micarpeta.comun.seguridad import extraer_bearer

PORTAL = Path(__file__).resolve().parents[2] / "portal" / "index.html"


@dataclass(frozen=True)
class Ruta:
    metodos: frozenset[str] | None
    patron: re.Pattern
    servicio: str
    publica: bool
    grupo_limite: str = "general"


def _r(metodos, patron, servicio, publica=False, grupo="general") -> Ruta:
    return Ruta(frozenset(metodos) if metodos else None, re.compile(patron), servicio, publica, grupo)


RUTAS = [
    _r({"POST"}, r"^/api/v1/ciudadanos$", "identidad", publica=True, grupo="registro"),
    _r({"GET"}, r"^/api/v1/ciudadanos/yo$", "identidad"),
    _r({"POST"}, r"^/api/v1/auth/login$", "autenticacion", publica=True, grupo="login"),
    _r({"POST"}, r"^/api/v1/auth/refresh$", "autenticacion", publica=True, grupo="login"),
    _r({"POST"}, r"^/api/v1/auth/logout$", "autenticacion"),
    _r({"GET"}, r"^/\.well-known/jwks\.json$", "autenticacion", publica=True),
    _r({"POST"}, r"^/api/v1/documentos/[^/]+/autenticacion$", "certificacion"),
    _r({"GET", "POST"}, r"^/api/v1/documentos$", "documentos"),
    _r({"GET"}, r"^/api/v1/documentos/[^/]+(/descarga|/contenido)?$", "documentos"),
    _r({"GET"}, r"^/api/v1/solicitudes/[^/]+$", "certificacion"),
    _r({"GET"}, r"^/api/v1/verificacion/[^/]+$", "certificacion", publica=True),
    _r({"GET"}, r"^/api/v1/notificaciones$", "notificaciones"),
    # Rutas de administración: se protegen con X-Admin-Key dentro de cada servicio
    _r({"GET"}, r"^/api/v1/auditoria/(verificacion|registros)$", "auditoria", publica=True),
    _r({"GET"}, r"^/api/v1/admin/govcarpeta$", "interoperabilidad", publica=True),
]

CABECERAS_SALTO = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "x-token-interno",
}


def resolver(metodo: str, ruta: str) -> Ruta | None:
    for r in RUTAS:
        if r.patron.match(ruta) and (r.metodos is None or metodo in r.metodos):
            return r
    return None


def crear_app(ctx: Contexto, gestionar_ciclo: bool = False, **_) -> FastAPI:
    cfg = ctx.config
    app = crear_app_base(
        "ms-gateway",
        ctx,
        descripcion="Punto de entrada: JWT en el borde, rate limiting y enrutamiento a los microservicios.",
        gestionar_ciclo=gestionar_ciclo,
        rutas_internas=(),
    )
    origenes = [o.strip() for o in cfg.cors_origenes.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origenes,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Location", "X-Request-ID", "Retry-After"],
    )
    limites = {
        "login": cfg.limite_login_por_minuto,
        "registro": cfg.limite_login_por_minuto,
        "general": cfg.limite_general_por_minuto,
    }

    @app.get("/", include_in_schema=False)
    async def portal():
        return FileResponse(PORTAL, media_type="text/html")

    async def limitar(request: Request, grupo: str) -> None:
        ip = request.client.host if request.client else "desconocida"
        ventana = int(time.time() // 60)
        cuenta = await ctx.cache.incr(f"rl:{grupo}:{ip}:{ventana}", ttl=61)
        if cuenta > limites[grupo]:
            espera = 60 - int(time.time() % 60)
            raise ErrorDominio(
                429, "LIMITE_EXCEDIDO", f"Máximo {limites[grupo]} solicitudes por minuto", cabeceras={"Retry-After": str(espera)}
            )

    @app.api_route(
        "/{ruta:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False
    )
    async def proxy(ruta: str, request: Request):
        camino = "/" + ruta
        destino = resolver(request.method, camino)
        if destino is None:
            raise ErrorDominio(404, "RUTA_NO_ENCONTRADA")

        await limitar(request, destino.grupo_limite)

        if not destino.publica:
            usuario = await ctx.verificador.verificar(extraer_bearer(request))
            if await ctx.cache.get(f"revocado:{usuario.jti}"):
                raise ErrorDominio(401, "TOKEN_REVOCADO", cabeceras={"WWW-Authenticate": "Bearer"})

        tamano = int(request.headers.get("content-length") or 0)
        if tamano > cfg.tamano_maximo_peticion_bytes:
            raise ErrorDominio(413, "PETICION_DEMASIADO_GRANDE")

        cabeceras = {k: v for k, v in request.headers.items() if k.lower() not in CABECERAS_SALTO}
        ip = request.client.host if request.client else ""
        previas = request.headers.get("x-forwarded-for")
        cabeceras["X-Forwarded-For"] = f"{previas}, {ip}" if previas else ip
        cabeceras["X-Request-ID"] = id_solicitud.get()
        cuerpo = await request.body()
        try:
            resp = await ctx.clientes.cliente(destino.servicio).request(
                request.method, camino, params=list(request.query_params.multi_items()), content=cuerpo, headers=cabeceras
            )
        except httpx.TransportError:
            return respuesta_problema(
                503, "SERVICIO_NO_DISPONIBLE", detalle=f"ms-{destino.servicio} no responde", instancia=camino
            )
        salida = {k: v for k, v in resp.headers.items() if k.lower() not in CABECERAS_SALTO and k.lower() != "x-request-id"}
        return Response(content=resp.content, status_code=resp.status_code, headers=salida)

    return app

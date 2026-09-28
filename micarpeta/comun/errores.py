"""Errores de dominio y formato de respuesta RFC 7807 (application/problem+json).

Todas las respuestas de error del sistema llevan un campo ``codigo`` estable
(por ejemplo CIUDADANO_YA_AFILIADO) que el portal y las pruebas usan para
decidir qué hacer, sin depender del texto.
"""

import logging

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("micarpeta.errores")

TITULOS = {
    "DATOS_INVALIDOS": "Los datos enviados no son válidos",
    "CIUDADANO_YA_AFILIADO": "El ciudadano ya está afiliado a otro operador",
    "CIUDADANO_YA_REGISTRADO": "El ciudadano ya está registrado en este operador",
    "CIUDADANO_NO_ENCONTRADO": "Ciudadano no encontrado",
    "GOVCARPETA_NO_DISPONIBLE": "GovCarpeta no está disponible en este momento",
    "GOVCARPETA_RECHAZO": "GovCarpeta rechazó la operación",
    "OPERADOR_NO_CONFIGURADO": "El operador no está registrado en GovCarpeta",
    "SERVICIO_NO_DISPONIBLE": "Un servicio interno no está disponible",
    "CREDENCIALES_INVALIDAS": "Documento o contraseña incorrectos",
    "CREDENCIAL_EXISTENTE": "La credencial ya existe",
    "CUENTA_BLOQUEADA": "Cuenta bloqueada temporalmente por intentos fallidos",
    "CIUDADANO_NO_ACTIVO": "La cuenta no está activa",
    "NO_AUTENTICADO": "Se requiere un token de acceso",
    "TOKEN_INVALIDO": "El token no es válido",
    "TOKEN_EXPIRADO": "El token expiró",
    "TOKEN_REVOCADO": "El token fue revocado",
    "LIMITE_EXCEDIDO": "Demasiadas solicitudes, intenta de nuevo en un momento",
    "PETICION_DEMASIADO_GRANDE": "La petición excede el tamaño permitido",
    "TIPO_NO_PERMITIDO": "Tipo de archivo no permitido",
    "TAMANO_EXCEDIDO": "El archivo excede el tamaño máximo permitido",
    "ARCHIVO_VACIO": "El archivo está vacío",
    "ARCHIVO_INFECTADO": "El archivo fue rechazado por el antivirus",
    "CUOTA_EXCEDIDA": "Se alcanzó la cuota de la carpeta",
    "DOCUMENTO_NO_ENCONTRADO": "Documento no encontrado",
    "OBJETO_NO_ENCONTRADO": "Objeto no encontrado",
    "ESTADO_INVALIDO": "El documento no está en un estado válido para esta operación",
    "FIRMA_INVALIDA": "La firma de la URL no es válida",
    "URL_EXPIRADA": "La URL de descarga expiró",
    "SELLO_NO_ENCONTRADO": "El documento no tiene un sello de autenticidad",
    "SOLICITUD_NO_ENCONTRADA": "Solicitud no encontrada",
    "ACCESO_DENEGADO": "Acceso denegado",
    "RUTA_NO_ENCONTRADA": "Ruta no encontrada",
    "METODO_NO_PERMITIDO": "Método no permitido",
    "ERROR_INTERNO": "Error interno del servidor",
}

_CODIGO_POR_ESTADO = {
    400: "DATOS_INVALIDOS",
    401: "NO_AUTENTICADO",
    403: "ACCESO_DENEGADO",
    404: "RUTA_NO_ENCONTRADA",
    405: "METODO_NO_PERMITIDO",
    413: "PETICION_DEMASIADO_GRANDE",
    422: "DATOS_INVALIDOS",
    429: "LIMITE_EXCEDIDO",
    503: "SERVICIO_NO_DISPONIBLE",
}


class ErrorDominio(Exception):
    """Error esperado del negocio. Se traduce a problem+json con su código."""

    def __init__(
        self,
        estado: int,
        codigo: str,
        detalle: str | None = None,
        *,
        titulo: str | None = None,
        extra: dict | None = None,
        cabeceras: dict | None = None,
    ):
        self.estado = estado
        self.codigo = codigo
        self.titulo = titulo or TITULOS.get(codigo, codigo.replace("_", " ").capitalize())
        self.detalle = detalle
        self.extra = extra or {}
        self.cabeceras = cabeceras
        super().__init__(f"{estado} {codigo}: {detalle or self.titulo}")


def respuesta_problema(
    estado: int,
    codigo: str,
    titulo: str | None = None,
    detalle: str | None = None,
    instancia: str | None = None,
    extra: dict | None = None,
    cabeceras: dict | None = None,
) -> JSONResponse:
    cuerpo = {
        "type": f"https://micarpeta.co/errores/{codigo}",
        "title": titulo or TITULOS.get(codigo, codigo),
        "status": estado,
        "codigo": codigo,
    }
    if detalle:
        cuerpo["detail"] = detalle
    if instancia:
        cuerpo["instance"] = instancia
    if extra:
        cuerpo.update(extra)
    return JSONResponse(cuerpo, status_code=estado, headers=cabeceras, media_type="application/problem+json")


def error_desde_respuesta(resp: httpx.Response, servicio: str) -> ErrorDominio:
    """Reconstruye el ErrorDominio que devolvió otro microservicio."""
    try:
        cuerpo = resp.json()
    except ValueError:
        cuerpo = {}
    if not isinstance(cuerpo, dict):
        cuerpo = {}
    codigo = cuerpo.get("codigo")
    if not codigo:
        codigo = "SERVICIO_NO_DISPONIBLE" if resp.status_code >= 500 else _CODIGO_POR_ESTADO.get(resp.status_code, "ERROR_INTERNO")
    extra = {k: v for k, v in cuerpo.items() if k not in {"type", "title", "status", "codigo", "detail", "instance"}}
    detalle = cuerpo.get("detail") or (f"{servicio} respondió {resp.status_code}" if resp.status_code >= 500 else None)
    return ErrorDominio(resp.status_code, codigo, detalle, titulo=cuerpo.get("title"), extra=extra)


def _campo(loc: tuple) -> str:
    partes = [str(p) for p in loc if p not in ("body", "query", "path", "header", "form")]
    return ".".join(partes) or "cuerpo"


def instalar_manejadores(app: FastAPI) -> None:
    @app.exception_handler(ErrorDominio)
    async def _dominio(request: Request, exc: ErrorDominio):
        return respuesta_problema(
            exc.estado, exc.codigo, exc.titulo, exc.detalle, request.url.path, exc.extra, exc.cabeceras
        )

    @app.exception_handler(RequestValidationError)
    async def _validacion(request: Request, exc: RequestValidationError):
        errores = [{"campo": _campo(tuple(e.get("loc", ()))), "mensaje": e.get("msg", "")} for e in exc.errors()]
        return respuesta_problema(
            422,
            "DATOS_INVALIDOS",
            detalle="; ".join(f"{e['campo']}: {e['mensaje']}" for e in errores),
            instancia=request.url.path,
            extra={"errores": errores},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        codigo = _CODIGO_POR_ESTADO.get(exc.status_code, "ERROR_INTERNO")
        detalle = exc.detail if isinstance(exc.detail, str) else None
        return respuesta_problema(exc.status_code, codigo, detalle=detalle, instancia=request.url.path)

    @app.exception_handler(Exception)
    async def _inesperado(request: Request, exc: Exception):
        log.exception("Error no controlado en %s %s", request.method, request.url.path)
        return respuesta_problema(500, "ERROR_INTERNO", instancia=request.url.path)

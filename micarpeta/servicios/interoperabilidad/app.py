"""MS-06 ms-interoperabilidad · Capa anticorrupción (ACL) hacia GovCarpeta (ADR-003).

Es el ÚNICO componente que conoce el contrato de GovCarpeta: nombres en
camelCase inconsistentes (idCitizen / UrlDocument / documentTitle), respuestas
en prosa y códigos HTTP con semántica propia (204 = libre, 501 = error de
negocio). El resto del sistema habla con este servicio en su propio idioma:

    GET    /gov/ciudadanos/{documento}/disponibilidad  -> validateCitizen
    POST   /gov/ciudadanos                             -> registerCitizen
    DELETE /gov/ciudadanos/{documento}                 -> unregisterCitizen
    PUT    /gov/documentos/autenticacion               -> authenticateDocument
    GET    /gov/operadores                             -> getOperators (con caché)

Incluye reintentos con backoff exponencial + jitter y un cortacircuitos.
"""

import asyncio
import hmac
import json
import logging
import random
import re
import time
from enum import StrEnum

import httpx
from fastapi import FastAPI, Header
from pydantic import BaseModel, Field

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.errores import ErrorDominio

log = logging.getLogger("micarpeta.interoperabilidad")


# ============================================================ cortacircuitos
class EstadoCircuito(StrEnum):
    CERRADO = "CERRADO"
    ABIERTO = "ABIERTO"
    SEMI_ABIERTO = "SEMI_ABIERTO"


class Cortacircuitos:
    """Deja de llamar a GovCarpeta tras ``umbral`` fallos consecutivos.

    Pasado ``espera`` segundos deja pasar una llamada de prueba (SEMI_ABIERTO):
    si funciona se cierra, si falla vuelve a abrirse.
    """

    def __init__(self, umbral: int, espera: float, reloj=time.monotonic):
        self.umbral = umbral
        self.espera = espera
        self._reloj = reloj
        self.estado = EstadoCircuito.CERRADO
        self.fallos_consecutivos = 0
        self.fallos_totales = 0
        self.rechazos = 0
        self._abierto_desde = 0.0

    def permitir(self) -> bool:
        if self.estado == EstadoCircuito.ABIERTO:
            if self._reloj() - self._abierto_desde >= self.espera:
                self.estado = EstadoCircuito.SEMI_ABIERTO
                return True
            self.rechazos += 1
            return False
        return True

    def registrar_exito(self) -> None:
        self.fallos_consecutivos = 0
        self.estado = EstadoCircuito.CERRADO

    def registrar_fallo(self) -> None:
        self.fallos_consecutivos += 1
        self.fallos_totales += 1
        if self.estado == EstadoCircuito.SEMI_ABIERTO or self.fallos_consecutivos >= self.umbral:
            if self.estado != EstadoCircuito.ABIERTO:
                log.warning("Cortacircuitos ABIERTO tras %s fallos consecutivos", self.fallos_consecutivos)
            self.estado = EstadoCircuito.ABIERTO
            self._abierto_desde = self._reloj()

    def resumen(self) -> dict:
        return {
            "estado": self.estado.value,
            "fallos_consecutivos": self.fallos_consecutivos,
            "fallos_totales": self.fallos_totales,
            "llamadas_rechazadas": self.rechazos,
            "umbral": self.umbral,
        }


# ============================================================ cliente GovCarpeta
class GovCarpetaNoDisponible(Exception):
    pass


class _FalloTransitorio(Exception):
    pass


class ClienteGovCarpeta:
    def __init__(self, ctx: Contexto, cortacircuitos: Cortacircuitos):
        self.ctx = ctx
        self.config = ctx.config
        self.cb = cortacircuitos

    def _espera(self, intento: int) -> float:
        base = self.config.govcarpeta_backoff_base_segundos
        return base * (2 ** (intento - 1)) + random.uniform(0, base)

    async def llamar(self, metodo: str, ruta: str, cuerpo: dict | None = None) -> httpx.Response:
        http = self.ctx.clientes.cliente("govcarpeta")
        ultimo, intentos = "", 0
        for intento in range(1, self.config.govcarpeta_reintentos + 1):
            if not self.cb.permitir():
                previo = f"; último fallo: {ultimo}" if ultimo else ""
                raise GovCarpetaNoDisponible(f"Cortacircuitos abierto, no se llama a GovCarpeta por ahora{previo}")
            intentos = intento
            try:
                resp = await http.request(
                    metodo,
                    ruta,
                    content=json.dumps(cuerpo).encode() if cuerpo is not None else None,
                    headers={"Content-Type": "application/json"} if cuerpo is not None else None,
                    timeout=self.config.govcarpeta_timeout_segundos,
                )
                # 501 es la forma en que GovCarpeta reporta errores de negocio: no se reintenta.
                if resp.status_code >= 500 and resp.status_code != 501:
                    raise _FalloTransitorio(f"HTTP {resp.status_code}")
                self.cb.registrar_exito()
                return resp
            except (httpx.TransportError, _FalloTransitorio) as e:
                ultimo = f"respondió {e}" if isinstance(e, _FalloTransitorio) else f"no respondió ({type(e).__name__})"
                self.cb.registrar_fallo()
                log.warning("GovCarpeta %s %s falló (intento %s): %s", metodo, ruta, intento, ultimo)
                if intento < self.config.govcarpeta_reintentos:
                    await asyncio.sleep(self._espera(intento))
        raise GovCarpetaNoDisponible(f"GovCarpeta {ultimo} tras {intentos} intento(s)")

    def _operador(self) -> tuple[str, str]:
        if not self.config.govcarpeta_operator_id:
            raise ErrorDominio(
                503,
                "OPERADOR_NO_CONFIGURADO",
                "Falta GOVCARPETA_OPERATOR_ID. Registra el operador con scripts/registrar_operador.py",
            )
        return self.config.govcarpeta_operator_id, self.config.nombre_operador

    # ---- operaciones traducidas
    async def consultar_afiliacion(self, documento: str) -> dict:
        resp = await self.llamar("GET", f"/apis/validateCitizen/{int(documento)}")
        if resp.status_code == 204:
            return {"disponible": True, "operador_actual": None}
        if resp.status_code == 200:
            texto = resp.text.strip()
            m = re.search(r"operador\s+(.+?)[\s.]*$", texto, re.IGNORECASE)
            operador = m.group(1).strip() if m else None
            return {"disponible": False, "operador_actual": operador, "mensaje": texto}
        raise ErrorDominio(502, "GOVCARPETA_RECHAZO", f"validateCitizen respondió {resp.status_code}: {resp.text[:200]}")

    async def afiliar(self, documento: str, nombre: str, direccion: str, correo: str) -> dict:
        operador_id, operador_nombre = self._operador()
        cuerpo = {
            "id": int(documento),
            "name": nombre,
            "address": direccion,
            "email": correo,
            "operatorId": operador_id,
            "operatorName": operador_nombre,
        }
        resp = await self.llamar("POST", "/apis/registerCitizen", cuerpo)
        if resp.status_code in (200, 201):
            return {"afiliado": True, "mensaje": resp.text.strip()}
        if resp.status_code == 501:
            # Un reintento pudo haber registrado al ciudadano aunque la respuesta se perdiera:
            # si GovCarpeta dice que ya está con NOSOTROS, la operación es idempotente.
            afiliacion = await self.consultar_afiliacion(documento)
            actual = (afiliacion.get("operador_actual") or "").lower()
            if not afiliacion["disponible"] and actual == operador_nombre.lower():
                return {"afiliado": True, "mensaje": "Ya estaba afiliado a este operador"}
            raise ErrorDominio(409, "CIUDADANO_YA_AFILIADO", resp.text.strip() or None,
                               extra={"operador_actual": afiliacion.get("operador_actual")})
        raise ErrorDominio(502, "GOVCARPETA_RECHAZO", f"registerCitizen respondió {resp.status_code}: {resp.text[:200]}")

    async def desafiliar(self, documento: str) -> dict:
        operador_id, operador_nombre = self._operador()
        cuerpo = {"id": int(documento), "operatorId": operador_id, "operatorName": operador_nombre}
        resp = await self.llamar("DELETE", "/apis/unregisterCitizen", cuerpo)
        if resp.status_code in (200, 201, 204):
            return {"desafiliado": True, "existia": resp.status_code != 204}
        raise ErrorDominio(502, "GOVCARPETA_RECHAZO", f"unregisterCitizen respondió {resp.status_code}: {resp.text[:200]}")

    async def autenticar_documento(self, documento: str, url: str, titulo: str) -> dict:
        cuerpo = {"idCitizen": int(documento), "UrlDocument": url, "documentTitle": titulo}
        resp = await self.llamar("PUT", "/apis/authenticateDocument", cuerpo)
        if resp.status_code == 200:
            return {"autenticado": True, "mensaje": resp.text.strip()}
        raise ErrorDominio(502, "GOVCARPETA_RECHAZO", f"authenticateDocument respondió {resp.status_code}: {resp.text[:200]}")

    async def operadores(self) -> list[dict]:
        cache = self.ctx.cache
        guardado = await cache.get("govcarpeta:operadores")
        if guardado:
            return json.loads(guardado)
        resp = await self.llamar("GET", "/apis/getOperators")
        if resp.status_code != 200:
            raise ErrorDominio(502, "GOVCARPETA_RECHAZO", f"getOperators respondió {resp.status_code}")
        operadores = [
            {"id": o.get("_id"), "nombre": o.get("operatorName"), "url_transferencia": o.get("transferAPIURL")}
            for o in resp.json()
        ]
        await cache.set("govcarpeta:operadores", json.dumps(operadores), ttl=self.config.cache_operadores_segundos)
        return operadores


# ============================================================ API de dominio
class AfiliacionEntrada(BaseModel):
    documento: str = Field(pattern=r"^\d{5,12}$")
    nombre: str
    direccion: str
    correo: str


class AutenticacionEntrada(BaseModel):
    documento_ciudadano: str = Field(pattern=r"^\d{5,12}$")
    url_documento: str
    titulo: str


def _no_disponible(e: GovCarpetaNoDisponible) -> ErrorDominio:
    return ErrorDominio(503, "GOVCARPETA_NO_DISPONIBLE", str(e), cabeceras={"Retry-After": "30"})


def crear_app(ctx: Contexto, gestionar_ciclo: bool = False, **_) -> FastAPI:
    app = crear_app_base(
        "ms-interoperabilidad",
        ctx,
        descripcion="Capa anticorrupción hacia GovCarpeta: reintentos, cortacircuitos y traducción del contrato.",
        gestionar_ciclo=gestionar_ciclo,
        rutas_internas=("/gov",),
    )
    cb = Cortacircuitos(ctx.config.cortacircuitos_umbral, ctx.config.cortacircuitos_espera_segundos)
    gov = ClienteGovCarpeta(ctx, cb)
    app.state.cortacircuitos = cb
    app.state.govcarpeta = gov

    @app.get("/gov/ciudadanos/{documento}/disponibilidad")
    async def disponibilidad(documento: str):
        if not documento.isdigit():
            raise ErrorDominio(422, "DATOS_INVALIDOS", "El documento debe ser numérico")
        try:
            return await gov.consultar_afiliacion(documento)
        except GovCarpetaNoDisponible as e:
            raise _no_disponible(e)

    @app.post("/gov/ciudadanos", status_code=201)
    async def afiliar(datos: AfiliacionEntrada):
        try:
            return await gov.afiliar(datos.documento, datos.nombre, datos.direccion, datos.correo)
        except GovCarpetaNoDisponible as e:
            raise _no_disponible(e)

    @app.delete("/gov/ciudadanos/{documento}")
    async def desafiliar(documento: str):
        try:
            return await gov.desafiliar(documento)
        except GovCarpetaNoDisponible as e:
            raise _no_disponible(e)

    @app.put("/gov/documentos/autenticacion")
    async def autenticar(datos: AutenticacionEntrada):
        if not datos.url_documento.startswith(("https://", "http://")):
            raise ErrorDominio(422, "DATOS_INVALIDOS", "Solo se envían URLs a GovCarpeta, nunca contenido")
        try:
            return await gov.autenticar_documento(datos.documento_ciudadano, datos.url_documento, datos.titulo)
        except GovCarpetaNoDisponible as e:
            raise _no_disponible(e)

    @app.get("/gov/operadores")
    async def operadores():
        try:
            return {"operadores": await gov.operadores()}
        except GovCarpetaNoDisponible as e:
            raise _no_disponible(e)

    def resumen_estado() -> dict:
        return {
            "cortacircuitos": cb.resumen(),
            "govcarpeta_url": ctx.config.govcarpeta_url,
            "operador_configurado": bool(ctx.config.govcarpeta_operator_id),
        }

    @app.get("/gov/estado")
    async def estado():
        return resumen_estado()

    @app.get("/api/v1/admin/govcarpeta", tags=["administracion"], summary="Estado de la integración con GovCarpeta")
    async def estado_admin(x_admin_key: str | None = Header(None)):
        if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), ctx.config.admin_api_key.encode()):
            raise ErrorDominio(403, "ACCESO_DENEGADO", "Se requiere la cabecera X-Admin-Key")
        return resumen_estado()

    return app

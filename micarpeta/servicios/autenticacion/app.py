"""MS-02 ms-autenticacion · Credenciales y sesión (CU-02).

- Contraseñas con Argon2id (nunca en claro).
- Access token JWT RS256 de corta duración; la clave pública se publica en
  /.well-known/jwks.json para que el gateway y los servicios validen sin red.
- Refresh token opaco, rotativo y con detección de reutilización.
- Anti-enumeración: documento inexistente y contraseña incorrecta producen la
  misma respuesta, y en ambos casos se ejecuta un hash (señuelo) para igualar tiempos.
- Bloqueo temporal tras N intentos fallidos. El login es 100 % local: no
  depende de GovCarpeta.
"""

import hashlib
import json
import logging
import secrets
import time
import uuid
from datetime import timedelta
from pathlib import Path

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, ahora, sesion_bd
from micarpeta.comun.errores import ErrorDominio, error_desde_respuesta
from micarpeta.comun.eventos import (
    LOGIN_EXITOSO,
    LOGIN_FALLIDO,
    crear_evento,
    publicar_seguro,
)
from micarpeta.comun.seguridad import extraer_bearer

from .modelos import Base, Credencial, IntentoAcceso, RefreshToken

log = logging.getLogger("micarpeta.autenticacion")


# ============================================================ claves RS256
class GestorClaves:
    def __init__(self, archivo: str):
        ruta = Path(archivo) if archivo else None
        if ruta and ruta.exists():
            self.privada = serialization.load_pem_private_key(ruta.read_bytes(), password=None)
        else:
            self.privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if ruta:
                ruta.parent.mkdir(parents=True, exist_ok=True)
                ruta.write_bytes(
                    self.privada.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
                ruta.chmod(0o600)
                log.info("Clave RS256 generada en %s", ruta)
        self.publica = self.privada.public_key()
        der = self.publica.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = hashlib.sha256(der).hexdigest()[:16]

    def jwks(self) -> dict:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.publica))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}


# ============================================================ entrada
class CredencialEntrada(BaseModel):
    ciudadano_id: str
    documento: str = Field(pattern=r"^\d{5,12}$")
    password: str = Field(min_length=1, max_length=256)


class LoginEntrada(BaseModel):
    documento: str = Field(min_length=1, max_length=20)
    password: str = Field(min_length=1, max_length=256)


class RefreshEntrada(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=200)


class LogoutEntrada(BaseModel):
    refresh_token: str | None = None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ip(request: Request) -> str | None:
    reenviada = request.headers.get("x-forwarded-for")
    if reenviada:
        return reenviada.split(",")[0].strip()
    return request.client.host if request.client else None


# ============================================================ app
def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    cfg = ctx.config
    db = BaseDatos(db_url or cfg.url_bd("autenticacion"))
    hasher = PasswordHasher(
        time_cost=cfg.argon2_tiempo,
        memory_cost=cfg.argon2_memoria_kib,
        parallelism=cfg.argon2_paralelismo,
        type=Type.ID,
    )
    estado: dict = {}

    async def al_iniciar(app: FastAPI) -> None:
        claves = GestorClaves(cfg.jwt_clave_privada_archivo)
        estado["claves"] = claves
        estado["senuelo"] = await run_in_threadpool(hasher.hash, secrets.token_urlsafe(24))
        ctx.verificador.agregar_clave(claves.kid, claves.publica)

    app = crear_app_base(
        "ms-autenticacion",
        ctx,
        descripcion="Credenciales Argon2id, JWT RS256, refresh tokens rotativos y bloqueo por intentos.",
        db=db,
        metadata=Base.metadata,
        al_iniciar=al_iniciar,
        gestionar_ciclo=gestionar_ciclo,
    )
    app.state.hasher = hasher

    # ---------------------------------------------------------------- utilidades
    async def verificar_password(hash_: str, password: str) -> bool:
        try:
            return await run_in_threadpool(hasher.verify, hash_, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def emitir_access(cred: Credencial) -> tuple[str, dict]:
        claves: GestorClaves = estado["claves"]
        ahora_ts = int(time.time())
        claims = {
            "iss": cfg.jwt_emisor,
            "aud": cfg.jwt_audiencia,
            "sub": cred.ciudadano_id,
            "doc": cred.documento,
            "roles": ["ciudadano"],
            "operador": cfg.nombre_operador,
            "jti": str(uuid.uuid4()),
            "iat": ahora_ts,
            "nbf": ahora_ts,
            "exp": ahora_ts + cfg.jwt_expiracion_segundos,
        }
        return jwt.encode(claims, claves.privada, algorithm="RS256", headers={"kid": claves.kid}), claims

    def emitir_refresh(s: AsyncSession, cred: Credencial, familia: str, ip: str | None) -> tuple[str, RefreshToken]:
        token = secrets.token_urlsafe(48)
        rt = RefreshToken(
            credencial_id=cred.id,
            familia=familia,
            hash_token=_hash_token(token),
            expira_en=ahora() + timedelta(hours=cfg.refresh_expiracion_horas),
            ip_origen=ip,
        )
        s.add(rt)
        return token, rt

    def respuesta_tokens(access: str, refresh: str) -> dict:
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": cfg.jwt_expiracion_segundos,
            "refresh_token": refresh,
            "refresh_expires_in": cfg.refresh_expiracion_horas * 3600,
        }

    async def ciudadano_activo(cred: Credencial) -> dict:
        r = await ctx.clientes.llamar("identidad", "GET", f"/internal/ciudadanos/{cred.ciudadano_id}")
        if r.status_code == 404:
            raise ErrorDominio(403, "CIUDADANO_NO_ACTIVO")
        if r.status_code != 200:
            raise error_desde_respuesta(r, "ms-identidad")
        ciudadano = r.json()
        if ciudadano["estado"] != "ACTIVO":
            raise ErrorDominio(403, "CIUDADANO_NO_ACTIVO", f"Estado actual: {ciudadano['estado']}")
        return ciudadano

    async def revocar_familia(s: AsyncSession, familia: str) -> None:
        await s.execute(
            update(RefreshToken)
            .where(RefreshToken.familia == familia, RefreshToken.revocado.is_(False))
            .values(revocado=True, revocado_en=ahora())
        )

    # ---------------------------------------------------------------- internas (saga de registro)
    @app.post("/internal/credenciales", status_code=201, tags=["interno"])
    async def crear_credencial(datos: CredencialEntrada, s: AsyncSession = Depends(sesion_bd)):
        hash_ = await run_in_threadpool(hasher.hash, datos.password)
        cred = await s.scalar(select(Credencial).where(Credencial.ciudadano_id == datos.ciudadano_id))
        if cred is None:
            cred = await s.scalar(select(Credencial).where(Credencial.documento == datos.documento))
        if cred is None:
            cred = Credencial(ciudadano_id=datos.ciudadano_id, documento=datos.documento, hash_password=hash_)
            s.add(cred)
        else:  # reintento de una saga compensada: se reemplaza la credencial
            cred.ciudadano_id = datos.ciudadano_id
            cred.hash_password = hash_
            cred.intentos_fallidos = 0
            cred.bloqueado_hasta = None
            cred.fecha_cambio_password = ahora()
        await s.commit()
        return {"credencial_id": cred.id}

    @app.delete("/internal/credenciales/{ciudadano_id}", status_code=204, tags=["interno"])
    async def eliminar_credencial(ciudadano_id: str, s: AsyncSession = Depends(sesion_bd)):
        cred = await s.scalar(select(Credencial).where(Credencial.ciudadano_id == ciudadano_id))
        if cred is None:
            raise ErrorDominio(404, "CIUDADANO_NO_ENCONTRADO")
        await s.delete(cred)
        await s.commit()
        return Response(status_code=204)

    # ---------------------------------------------------------------- públicas
    @app.get("/.well-known/jwks.json", tags=["tokens"], summary="Claves públicas para validar JWT")
    async def jwks():
        return estado["claves"].jwks()

    @app.post("/api/v1/auth/login", tags=["sesion"], summary="CU-02 Iniciar sesión")
    async def login(datos: LoginEntrada, request: Request, s: AsyncSession = Depends(sesion_bd)):
        ip, agente = _ip(request), (request.headers.get("user-agent") or "")[:255]

        async def registrar_intento(exitoso: bool, motivo: str) -> None:
            s.add(IntentoAcceso(documento=datos.documento, exitoso=exitoso, motivo=motivo, ip_origen=ip, user_agent=agente))
            await s.commit()

        cred = await s.scalar(select(Credencial).where(Credencial.documento == datos.documento))

        if cred is not None and cred.bloqueado_hasta and cred.bloqueado_hasta > ahora():
            await registrar_intento(False, "CUENTA_BLOQUEADA")
            restantes = max(1, int((cred.bloqueado_hasta - ahora()).total_seconds() // 60) + 1)
            raise ErrorDominio(
                423,
                "CUENTA_BLOQUEADA",
                f"Intenta de nuevo en {restantes} minuto(s)",
                extra={"minutos_restantes": restantes},
            )

        if cred is None:
            await verificar_password(estado["senuelo"], datos.password)  # iguala el tiempo de respuesta
            await registrar_intento(False, "DOCUMENTO_INEXISTENTE")
            raise ErrorDominio(401, "CREDENCIALES_INVALIDAS")

        if not await verificar_password(cred.hash_password, datos.password):
            cred.intentos_fallidos += 1
            if cred.intentos_fallidos >= cfg.max_intentos_fallidos:
                cred.bloqueado_hasta = ahora() + timedelta(minutes=cfg.minutos_bloqueo)
                cred.intentos_fallidos = 0
                log.warning("Cuenta %s bloqueada por intentos fallidos", cred.ciudadano_id)
            await registrar_intento(False, "CREDENCIALES_INVALIDAS")
            await publicar_seguro(
                ctx.bus,
                crear_evento(LOGIN_FALLIDO, "/ms-autenticacion", {"ciudadano_id": cred.ciudadano_id, "ip": ip}, cred.ciudadano_id),
            )
            raise ErrorDominio(401, "CREDENCIALES_INVALIDAS")

        try:
            ciudadano = await ciudadano_activo(cred)
        except ErrorDominio as e:
            await registrar_intento(False, e.codigo)
            raise

        if hasher.check_needs_rehash(cred.hash_password):
            cred.hash_password = await run_in_threadpool(hasher.hash, datos.password)
        cred.intentos_fallidos = 0
        cred.bloqueado_hasta = None
        cred.ultimo_acceso = ahora()
        access, _ = emitir_access(cred)
        refresh, _ = emitir_refresh(s, cred, str(uuid.uuid4()), ip)
        await registrar_intento(True, "EXITOSO")
        await publicar_seguro(
            ctx.bus,
            crear_evento(LOGIN_EXITOSO, "/ms-autenticacion", {"ciudadano_id": cred.ciudadano_id, "ip": ip}, cred.ciudadano_id),
        )
        return respuesta_tokens(access, refresh) | {
            "ciudadano": {
                "id": ciudadano["id"],
                "nombre_completo": ciudadano["nombre_completo"],
                "direccion_unica": ciudadano["direccion_unica"],
            }
        }

    @app.post("/api/v1/auth/refresh", tags=["sesion"], summary="Renovar sesión (rota el refresh token)")
    async def refrescar(datos: RefreshEntrada, request: Request, s: AsyncSession = Depends(sesion_bd)):
        rt = await s.scalar(select(RefreshToken).where(RefreshToken.hash_token == _hash_token(datos.refresh_token)))
        if rt is None:
            raise ErrorDominio(401, "TOKEN_INVALIDO")
        if rt.revocado:
            # Reutilización de un token ya rotado: posible robo. Se revoca toda la familia.
            await revocar_familia(s, rt.familia)
            await s.commit()
            log.warning("Reutilización de refresh token detectada (familia %s)", rt.familia)
            raise ErrorDominio(401, "TOKEN_REVOCADO", "El refresh token ya fue usado; inicia sesión de nuevo")
        if rt.expira_en <= ahora():
            raise ErrorDominio(401, "TOKEN_EXPIRADO")
        cred = await s.get(Credencial, rt.credencial_id)
        if cred is None:
            raise ErrorDominio(401, "TOKEN_INVALIDO")
        if cred.bloqueado_hasta and cred.bloqueado_hasta > ahora():
            raise ErrorDominio(423, "CUENTA_BLOQUEADA")
        await ciudadano_activo(cred)

        nuevo, nuevo_rt = emitir_refresh(s, cred, rt.familia, _ip(request))
        await s.flush()
        rt.revocado = True
        rt.revocado_en = ahora()
        rt.reemplazado_por = nuevo_rt.id
        access, _ = emitir_access(cred)
        await s.commit()
        return respuesta_tokens(access, nuevo)

    @app.post("/api/v1/auth/logout", status_code=204, tags=["sesion"], summary="Cerrar sesión")
    async def logout(request: Request, s: AsyncSession = Depends(sesion_bd), datos: LogoutEntrada | None = None):
        usuario = await ctx.verificador.verificar(extraer_bearer(request))
        restante = max(1, usuario.exp - int(time.time()))
        await ctx.cache.set(f"revocado:{usuario.jti}", "1", ttl=restante)

        cred = await s.scalar(select(Credencial).where(Credencial.ciudadano_id == usuario.ciudadano_id))
        if cred is not None:
            rt = None
            if datos and datos.refresh_token:
                rt = await s.scalar(select(RefreshToken).where(RefreshToken.hash_token == _hash_token(datos.refresh_token)))
            if rt is not None and rt.credencial_id == cred.id:
                await revocar_familia(s, rt.familia)
            else:
                await s.execute(
                    update(RefreshToken)
                    .where(RefreshToken.credencial_id == cred.id, RefreshToken.revocado.is_(False))
                    .values(revocado=True, revocado_en=ahora())
                )
            await s.commit()
        return Response(status_code=204)

    return app

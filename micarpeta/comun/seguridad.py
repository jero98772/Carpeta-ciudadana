"""Validación de tokens JWT RS256 en cualquier microservicio.

La clave pública se obtiene del JWKS de ms-autenticacion y se guarda en
memoria, así que validar un token no requiere llamar a ningún servicio.
"""

from dataclasses import dataclass

import jwt
from fastapi import Request

from .errores import ErrorDominio


@dataclass
class Usuario:
    ciudadano_id: str
    documento: str
    roles: list[str]
    jti: str
    exp: int
    token: str


class VerificadorJWT:
    def __init__(self, clientes, emisor: str, audiencia: str):
        self._clientes = clientes
        self.emisor = emisor
        self.audiencia = audiencia
        self._claves: dict[str, object] = {}

    def agregar_clave(self, kid: str, clave_publica) -> None:
        self._claves[kid] = clave_publica

    async def _cargar_jwks(self) -> None:
        resp = await self._clientes.llamar("autenticacion", "GET", "/.well-known/jwks.json")
        if resp.status_code != 200:
            raise ErrorDominio(503, "SERVICIO_NO_DISPONIBLE", "No se pudo obtener el JWKS")
        for jwk in resp.json().get("keys", []):
            self._claves[jwk["kid"]] = jwt.PyJWK(jwk).key

    async def verificar(self, token: str) -> Usuario:
        try:
            cabecera = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise ErrorDominio(401, "TOKEN_INVALIDO", cabeceras={"WWW-Authenticate": "Bearer"})
        kid = cabecera.get("kid", "")
        if cabecera.get("alg") != "RS256":
            raise ErrorDominio(401, "TOKEN_INVALIDO", "Algoritmo no permitido", cabeceras={"WWW-Authenticate": "Bearer"})
        if kid not in self._claves:
            await self._cargar_jwks()
        clave = self._claves.get(kid)
        if clave is None:
            raise ErrorDominio(401, "TOKEN_INVALIDO", "Clave desconocida", cabeceras={"WWW-Authenticate": "Bearer"})
        try:
            claims = jwt.decode(
                token,
                clave,
                algorithms=["RS256"],
                audience=self.audiencia,
                issuer=self.emisor,
                options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise ErrorDominio(401, "TOKEN_EXPIRADO", cabeceras={"WWW-Authenticate": "Bearer"})
        except jwt.InvalidTokenError:
            raise ErrorDominio(401, "TOKEN_INVALIDO", cabeceras={"WWW-Authenticate": "Bearer"})
        return Usuario(
            ciudadano_id=claims["sub"],
            documento=str(claims.get("doc", "")),
            roles=list(claims.get("roles", [])),
            jti=claims["jti"],
            exp=int(claims["exp"]),
            token=token,
        )


def extraer_bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    esquema, _, token = auth.partition(" ")
    if esquema.lower() != "bearer" or not token.strip():
        raise ErrorDominio(401, "NO_AUTENTICADO", cabeceras={"WWW-Authenticate": "Bearer"})
    return token.strip()


async def usuario_actual(request: Request) -> Usuario:
    """Dependencia de FastAPI: exige un access token válido."""
    return await request.app.state.ctx.verificador.verificar(extraer_bearer(request))

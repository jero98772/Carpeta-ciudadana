"""Arnés de pruebas de extremo a extremo (sección 8 del documento).

Cada prueba recibe un sistema nuevo con los nueve microservicios montados en
un solo proceso mediante el transporte ASGI de httpx: mismas rutas,
middleware y serialización que en producción, sin Docker ni puertos abiertos.
Cada servicio tiene su propia base SQLite; GovCarpeta es el simulador.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from micarpeta.comun.config import Config
from micarpeta.sistema import construir_sistema


@pytest.fixture(scope="session")
def clave_jwt(tmp_path_factory) -> str:
    """Una sola clave RSA para toda la sesión (generarla por prueba es lento)."""
    ruta = tmp_path_factory.mktemp("secretos") / "jwt_privada.pem"
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ruta.write_bytes(
        clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(ruta)


def config_pruebas(tmp_path, clave_jwt: str, **cambios) -> Config:
    base = dict(
        entorno="pruebas",
        # Argon2id con costo bajo solo para que las pruebas sean rápidas
        argon2_tiempo=1,
        argon2_memoria_kib=1024,
        argon2_paralelismo=1,
        govcarpeta_backoff_base_segundos=0,
        govcarpeta_reintentos=3,
        cortacircuitos_umbral=5,
        limite_login_por_minuto=100,
        tamano_maximo_bytes=1024 * 1024,
        ruta_almacenamiento=str(tmp_path / "objetos"),
        jwt_clave_privada_archivo=clave_jwt,
        url_publica_custodia="https://descargas.micarpeta.test",
        clave_cifrado_custodia="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        admin_api_key="admin-pruebas",
    )
    base.update(cambios)
    return Config(_env_file=None, **base)


@pytest.fixture
async def fabrica(tmp_path, clave_jwt):
    """Permite crear un sistema con configuración a la medida dentro de una prueba."""
    creados = []

    async def crear(**cambios):
        carpeta = tmp_path / f"sistema{len(creados)}"
        carpeta.mkdir()
        cfg = config_pruebas(carpeta, clave_jwt, **cambios)
        sistema = await construir_sistema(cfg, url_bd=lambda s: f"sqlite+aiosqlite:///{carpeta}/{s}.db")
        creados.append(sistema)
        return sistema

    yield crear
    for s in creados:
        await s.cerrar()


@pytest.fixture
async def sistema(fabrica):
    return await fabrica()


@pytest.fixture
async def api(sistema):
    return sistema.cliente()

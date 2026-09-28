"""Almacenamiento de binarios, cifrado y antivirus de ms-custodia."""

import asyncio
import base64
import hashlib
import logging
import os
import struct
from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.concurrency import run_in_threadpool

log = logging.getLogger("micarpeta.custodia")


# ============================================================ almacenes
class AlmacenLocal:
    """Carpeta en disco. Útil para pruebas y para correr sin Docker."""

    def __init__(self, ruta: str, bucket: str):
        self.raiz = Path(ruta) / bucket
        self.bucket = bucket

    async def iniciar(self) -> None:
        self.raiz.mkdir(parents=True, exist_ok=True)

    def _ruta(self, clave: str) -> Path:
        destino = (self.raiz / clave).resolve()
        if not str(destino).startswith(str(self.raiz.resolve())):
            raise ValueError("Clave de objeto inválida")
        return destino

    async def guardar(self, clave: str, datos: bytes, tipo: str) -> None:
        ruta = self._ruta(clave)
        ruta.parent.mkdir(parents=True, exist_ok=True)
        await run_in_threadpool(ruta.write_bytes, datos)

    async def leer(self, clave: str) -> bytes:
        return await run_in_threadpool(self._ruta(clave).read_bytes)

    async def contar(self) -> int:
        return sum(1 for p in self.raiz.rglob("*") if p.is_file())


class AlmacenS3:
    """MinIO / Amazon S3 mediante la API S3."""

    def __init__(self, endpoint: str, acceso: str, secreto: str, bucket: str, seguro: bool):
        from minio import Minio

        self.cliente = Minio(endpoint, access_key=acceso, secret_key=secreto, secure=seguro)
        self.bucket = bucket

    async def iniciar(self, intentos: int = 20) -> None:
        for intento in range(1, intentos + 1):
            try:
                if not await run_in_threadpool(self.cliente.bucket_exists, self.bucket):
                    await run_in_threadpool(self.cliente.make_bucket, self.bucket)
                return
            except Exception as e:
                if intento == intentos:
                    raise
                log.warning("MinIO no disponible (%s), reintento %s/%s", e, intento, intentos)
                await asyncio.sleep(3)

    async def guardar(self, clave: str, datos: bytes, tipo: str) -> None:
        await run_in_threadpool(
            self.cliente.put_object, self.bucket, clave, BytesIO(datos), len(datos), content_type="application/octet-stream"
        )

    async def leer(self, clave: str) -> bytes:
        def _leer():
            resp = self.cliente.get_object(self.bucket, clave)
            try:
                return resp.read()
            finally:
                resp.close()
                resp.release_conn()

        return await run_in_threadpool(_leer)

    async def contar(self) -> int:
        return await run_in_threadpool(lambda: sum(1 for _ in self.cliente.list_objects(self.bucket, recursive=True)))


# ============================================================ cifrado
class Cifrador:
    """AES-256-GCM. En producción la clave vendría de KMS/HSM (ADR-001)."""

    def __init__(self, clave_b64: str, respaldo: str):
        if clave_b64:
            clave = base64.b64decode(clave_b64)
        else:
            log.warning("CLAVE_CIFRADO_CUSTODIA vacía: se deriva una clave de desarrollo")
            clave = hashlib.sha256(f"micarpeta-dev:{respaldo}".encode()).digest()
        if len(clave) != 32:
            raise ValueError("CLAVE_CIFRADO_CUSTODIA debe ser base64 de 32 bytes")
        self._aes = AESGCM(clave)

    def cifrar(self, datos: bytes, contexto: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, datos, contexto.encode())

    def descifrar(self, datos: bytes, contexto: str) -> bytes:
        return self._aes.decrypt(datos[:12], datos[12:], contexto.encode())


# ============================================================ antivirus
# La firma de prueba EICAR se arma por partes para que el propio código fuente
# no sea marcado por el antivirus de quien descarga el proyecto.
FIRMA_EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!H+H*").encode()


class AntivirusEicar:
    """Detecta el patrón estándar EICAR. Suficiente para pruebas y demos."""

    async def escanear(self, datos: bytes) -> tuple[bool, str]:
        if FIRMA_EICAR in datos:
            return False, "Eicar-Test-Signature"
        return True, "LIMPIO"


class AntivirusClamAV:
    """Escaneo real con clamd (protocolo INSTREAM por TCP)."""

    def __init__(self, host: str, puerto: int):
        self.host, self.puerto = host, puerto

    async def escanear(self, datos: bytes) -> tuple[bool, str]:
        lector, escritor = await asyncio.wait_for(asyncio.open_connection(self.host, self.puerto), timeout=10)
        try:
            escritor.write(b"zINSTREAM\0")
            for i in range(0, len(datos), 64 * 1024):
                trozo = datos[i : i + 64 * 1024]
                escritor.write(struct.pack("!L", len(trozo)) + trozo)
            escritor.write(struct.pack("!L", 0))
            await escritor.drain()
            respuesta = (await asyncio.wait_for(lector.read(1024), timeout=60)).decode().strip("\0 \n")
        finally:
            escritor.close()
        if respuesta.endswith("OK"):
            return True, "LIMPIO"
        return False, respuesta.replace("stream: ", "").replace(" FOUND", "")

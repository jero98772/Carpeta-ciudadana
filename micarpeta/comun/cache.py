"""Caché clave-valor con expiración: memoria (un proceso) o Redis (compartida).

Se usa para el rate limiting del gateway, la lista de tokens revocados y el
directorio de operadores de GovCarpeta.
"""

import time


class CacheMemoria:
    def __init__(self):
        self._datos: dict[str, tuple[str, float | None]] = {}

    def _vigente(self, clave: str):
        item = self._datos.get(clave)
        if item is None:
            return None
        valor, expira = item
        if expira is not None and time.monotonic() >= expira:
            self._datos.pop(clave, None)
            return None
        return item

    async def get(self, clave: str) -> str | None:
        item = self._vigente(clave)
        return item[0] if item else None

    async def set(self, clave: str, valor: str, ttl: int | None = None) -> None:
        self._datos[clave] = (valor, time.monotonic() + ttl if ttl else None)

    async def incr(self, clave: str, ttl: int) -> int:
        item = self._vigente(clave)
        if item is None:
            self._datos[clave] = ("1", time.monotonic() + ttl)
            return 1
        nuevo = int(item[0]) + 1
        self._datos[clave] = (str(nuevo), item[1])
        return nuevo

    async def delete(self, clave: str) -> None:
        self._datos.pop(clave, None)

    async def cerrar(self) -> None:
        pass


class CacheRedis:
    def __init__(self, url: str):
        import redis.asyncio as redis

        self._r = redis.from_url(url, decode_responses=True)

    async def get(self, clave: str) -> str | None:
        return await self._r.get(clave)

    async def set(self, clave: str, valor: str, ttl: int | None = None) -> None:
        await self._r.set(clave, valor, ex=ttl)

    async def incr(self, clave: str, ttl: int) -> int:
        async with self._r.pipeline(transaction=True) as p:
            p.incr(clave)
            p.expire(clave, ttl, nx=True)
            valor, _ = await p.execute()
        return int(valor)

    async def delete(self, clave: str) -> None:
        await self._r.delete(clave)

    async def cerrar(self) -> None:
        await self._r.aclose()

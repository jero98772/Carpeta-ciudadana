"""Eventos de dominio en formato CloudEvents 1.0 sobre un bus de mensajería.

- BusMemoria: entrega síncrona dentro del mismo proceso (pruebas y modo local).
- BusRabbitMQ: exchange topic "carpeta.eventos" (AMQP 0-9-1) con cola por
  consumidor, mensajes persistentes y dead-letter exchange.

Los consumidores deben ser idempotentes: usan el ``id`` del evento para no
procesar dos veces el mismo mensaje (RabbitMQ entrega al menos una vez).
"""

import asyncio
import json
import logging
import uuid
from collections.abc import Awaitable, Callable

from .db import ahora

log = logging.getLogger("micarpeta.eventos")

EXCHANGE = "carpeta.eventos"
EXCHANGE_DLX = "carpeta.eventos.dlx"

CIUDADANO_REGISTRADO = "co.micarpeta.ciudadano.registrado"
DOCUMENTO_CARGADO = "co.micarpeta.documento.cargado"
DOCUMENTO_AUTENTICADO = "co.micarpeta.documento.autenticado"
AUTENTICACION_FALLIDA = "co.micarpeta.documento.autenticacion_fallida"
LOGIN_EXITOSO = "co.micarpeta.sesion.login_exitoso"
LOGIN_FALLIDO = "co.micarpeta.sesion.login_fallido"

Manejador = Callable[[dict], Awaitable[None]]


def crear_evento(tipo: str, fuente: str, datos: dict, sujeto: str | None = None) -> dict:
    evento = {
        "specversion": "1.0",
        "id": str(uuid.uuid4()),
        "source": fuente,
        "type": tipo,
        "time": ahora().isoformat(),
        "datacontenttype": "application/json",
        "data": datos,
    }
    if sujeto:
        evento["subject"] = sujeto
    return evento


def coincide(patron: str, tipo: str) -> bool:
    """Semántica de routing keys AMQP: '*' = una palabra, '#' = cero o más."""
    p, t = patron.split("."), tipo.split(".")

    def _match(i: int, j: int) -> bool:
        if i == len(p):
            return j == len(t)
        if p[i] == "#":
            return any(_match(i + 1, k) for k in range(j, len(t) + 1))
        if j < len(t) and (p[i] == "*" or p[i] == t[j]):
            return _match(i + 1, j + 1)
        return False

    return _match(0, 0)


class BusMemoria:
    def __init__(self):
        self.publicados: list[dict] = []
        self._suscripciones: list[tuple[str, list[str], Manejador]] = []

    async def iniciar(self) -> None:
        pass

    async def detener(self) -> None:
        pass

    async def publicar(self, evento: dict) -> None:
        self.publicados.append(evento)
        for consumidor, patrones, manejador in list(self._suscripciones):
            if any(coincide(p, evento["type"]) for p in patrones):
                try:
                    await manejador(evento)
                except Exception:
                    log.exception("El consumidor %s falló procesando %s", consumidor, evento["type"])

    async def suscribir(self, consumidor: str, patrones: list[str], manejador: Manejador) -> None:
        self._suscripciones.append((consumidor, patrones, manejador))

    def de_tipo(self, tipo: str) -> list[dict]:
        return [e for e in self.publicados if e["type"] == tipo]


class BusRabbitMQ:
    def __init__(self, url: str):
        self.url = url
        self._conexion = None
        self._canal = None
        self._exchange = None

    async def iniciar(self, intentos: int = 20) -> None:
        import aio_pika

        for intento in range(1, intentos + 1):
            try:
                self._conexion = await aio_pika.connect_robust(self.url)
                break
            except Exception as e:
                if intento == intentos:
                    raise
                log.warning("RabbitMQ no disponible (%s), reintento %s/%s", e, intento, intentos)
                await asyncio.sleep(3)
        self._canal = await self._conexion.channel()
        await self._canal.set_qos(prefetch_count=10)
        self._exchange = await self._canal.declare_exchange(EXCHANGE, aio_pika.ExchangeType.TOPIC, durable=True)
        await self._canal.declare_exchange(EXCHANGE_DLX, aio_pika.ExchangeType.TOPIC, durable=True)

    async def detener(self) -> None:
        if self._conexion:
            await self._conexion.close()

    async def publicar(self, evento: dict) -> None:
        import aio_pika

        mensaje = aio_pika.Message(
            body=json.dumps(evento, ensure_ascii=False).encode(),
            content_type="application/cloudevents+json",
            message_id=evento["id"],
            type=evento["type"],
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )
        await self._exchange.publish(mensaje, routing_key=evento["type"])

    async def suscribir(self, consumidor: str, patrones: list[str], manejador: Manejador) -> None:
        dlx = await self._canal.get_exchange(EXCHANGE_DLX)
        cola_dlq = await self._canal.declare_queue(f"{consumidor}.dlq", durable=True)
        await cola_dlq.bind(dlx, routing_key=consumidor)
        cola = await self._canal.declare_queue(
            consumidor,
            durable=True,
            arguments={"x-dead-letter-exchange": EXCHANGE_DLX, "x-dead-letter-routing-key": consumidor},
        )
        for patron in patrones:
            await cola.bind(self._exchange, routing_key=patron)

        async def _procesar(mensaje):
            # requeue=False: si el manejador falla, el mensaje va a la cola .dlq
            async with mensaje.process(requeue=False):
                await manejador(json.loads(mensaje.body))

        await cola.consume(_procesar)
        log.info("Consumidor %s escuchando %s", consumidor, patrones)


async def publicar_seguro(bus, evento: dict) -> None:
    """Publica sin tumbar la operación de negocio si el broker falla (queda en el log)."""
    try:
        await bus.publicar(evento)
    except Exception:
        log.exception("No se pudo publicar el evento %s (%s)", evento["type"], evento["id"])

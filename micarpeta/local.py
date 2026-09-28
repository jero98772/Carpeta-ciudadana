"""Modo local: los nueve microservicios en un solo proceso, sin Docker.

    python -m micarpeta.local                  # con el simulador de GovCarpeta
    python -m micarpeta.local --govcarpeta-real  # contra la API real (requiere GOVCARPETA_OPERATOR_ID)

Abre:
    http://localhost:8000        portal del ciudadano + API (gateway)
    http://localhost:8004        descargas con URL prefirmada (ms-custodia)
    http://localhost:8090/api-docs  simulador de GovCarpeta (si se usa)

Cada servicio conserva su propia base de datos (SQLite en ./datos/local/).
"""

import argparse
import asyncio
import logging

import uvicorn

from micarpeta.comun.app_base import configurar_logs
from micarpeta.comun.config import Config
from micarpeta.sistema import construir_sistema

log = logging.getLogger("micarpeta.local")


async def principal(usar_real: bool, puerto: int) -> None:
    configurar_logs()
    config = Config()
    if usar_real and not config.govcarpeta_operator_id:
        raise SystemExit("Falta GOVCARPETA_OPERATOR_ID en .env. Ejecuta primero: python scripts/registrar_operador.py")
    sistema = await construir_sistema(
        config,
        url_bd=lambda s: f"sqlite+aiosqlite:///./datos/local/{s}.db",
        usar_simulador_govcarpeta=not usar_real,
    )
    servidores = [
        uvicorn.Server(uvicorn.Config(sistema.apps["gateway"], host="0.0.0.0", port=puerto, log_level="info")),
        uvicorn.Server(uvicorn.Config(sistema.apps["custodia"], host="0.0.0.0", port=8004, log_level="warning")),
    ]
    if sistema.gov_app is not None:
        servidores.append(uvicorn.Server(uvicorn.Config(sistema.gov_app, host="0.0.0.0", port=8090, log_level="warning")))

    print(
        f"\n  MiCarpeta CO en modo local\n"
        f"  · Portal y API:  http://localhost:{puerto}\n"
        f"  · GovCarpeta:    {'simulador en http://localhost:8090/api-docs' if sistema.gov_app else config.govcarpeta_url}\n"
        f"  · Ctrl+C para detener\n"
    )
    try:
        await asyncio.gather(*(s.serve() for s in servidores))
    finally:
        await sistema.cerrar()


def main() -> None:
    parser = argparse.ArgumentParser(description="MiCarpeta CO en un solo proceso")
    parser.add_argument("--govcarpeta-real", action="store_true", help="Usar la API real de GovCarpeta")
    parser.add_argument("--puerto", type=int, default=8000)
    args = parser.parse_args()
    try:
        asyncio.run(principal(args.govcarpeta_real, args.puerto))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

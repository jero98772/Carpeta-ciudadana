"""Punto de entrada del simulador en su propio contenedor."""

import os

from micarpeta.comun.app_base import configurar_logs

from .app import EstadoGovCarpeta, crear_app_govcarpeta

configurar_logs()
_estado = EstadoGovCarpeta()
# Pre-registra el operador para que el sistema funcione sin pasos manuales.
_estado.registrar_operador(
    os.environ.get("NOMBRE_OPERADOR", "MiCarpeta CO"),
    os.environ.get("GOVCARPETA_OPERATOR_ID") or "000000000000000000000001",
)
app = crear_app_govcarpeta(_estado)

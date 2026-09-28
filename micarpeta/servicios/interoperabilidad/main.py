from micarpeta.comun.app_base import configurar_logs
from micarpeta.comun.contexto import Contexto

from .app import crear_app

configurar_logs()
app = crear_app(Contexto.desde_config(), gestionar_ciclo=True)

"""Configuración única, leída de variables de entorno (o de un archivo .env).

Todos los microservicios comparten la misma clase; cada uno usa solo los
campos que le corresponden. En docker-compose se inyecta el mismo .env a
todos los contenedores y cada uno recibe además su variable SERVICIO.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

SERVICIOS = (
    "gateway",
    "identidad",
    "autenticacion",
    "documentos",
    "custodia",
    "certificacion",
    "interoperabilidad",
    "notificaciones",
    "auditoria",
)


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    entorno: str = "desarrollo"
    nombre_operador: str = "MiCarpeta CO"
    dominio_direcciones: str = "micarpeta.co"

    # --- Persistencia: "{servicio}" se reemplaza por el nombre del microservicio (database-per-service)
    database_url: str = "sqlite+aiosqlite:///./datos/{servicio}.db"

    # --- Ubicación de cada microservicio (modo distribuido)
    url_gateway: str = "http://localhost:8000"
    url_identidad: str = "http://localhost:8001"
    url_autenticacion: str = "http://localhost:8002"
    url_documentos: str = "http://localhost:8003"
    url_custodia: str = "http://localhost:8004"
    url_certificacion: str = "http://localhost:8005"
    url_interoperabilidad: str = "http://localhost:8006"
    url_notificaciones: str = "http://localhost:8008"
    url_auditoria: str = "http://localhost:8009"
    token_interno: str = "cambiar-token-interno"
    timeout_interno_segundos: float = 20.0

    # --- GovCarpeta (centralizador MinTIC)
    govcarpeta_url: str = "https://govcarpeta-apis-4905ff3c005b.herokuapp.com"
    govcarpeta_operator_id: str = ""
    govcarpeta_timeout_segundos: float = 10.0
    govcarpeta_reintentos: int = 3
    govcarpeta_backoff_base_segundos: float = 0.5
    cortacircuitos_umbral: int = 5
    cortacircuitos_espera_segundos: float = 30.0
    cache_operadores_segundos: int = 300

    # --- Tokens (JWT RS256)
    jwt_emisor: str = "https://auth.micarpeta.co"
    jwt_audiencia: str = "micarpeta-api"
    jwt_expiracion_segundos: int = 900
    refresh_expiracion_horas: int = 8
    jwt_clave_privada_archivo: str = "./secretos/jwt_privada.pem"

    # --- Contraseñas (Argon2id) y bloqueo
    argon2_tiempo: int = 3
    argon2_memoria_kib: int = 65536
    argon2_paralelismo: int = 4
    max_intentos_fallidos: int = 5
    minutos_bloqueo: int = 15

    # --- Gateway
    limite_login_por_minuto: int = 10
    limite_general_por_minuto: int = 300
    tamano_maximo_peticion_bytes: int = 25 * 1024 * 1024
    cors_origenes: str = "*"

    # --- Documentos
    tamano_maximo_bytes: int = 10 * 1024 * 1024
    cuota_documentos: int = 100
    cuota_bytes: int = 1024 * 1024 * 1024
    extensiones_permitidas: str = "pdf,png,jpg,jpeg,docx"

    # --- Custodia
    almacenamiento: str = "local"  # local | s3
    ruta_almacenamiento: str = "./datos/objetos"
    s3_endpoint: str = "localhost:9000"
    s3_access_key: str = "micarpeta"
    s3_secret_key: str = "micarpeta-secreto"
    s3_bucket: str = "custodia-documentos"
    s3_seguro: bool = False
    clave_cifrado_custodia: str = ""  # base64 de 32 bytes (AES-256-GCM)
    secreto_urls: str = "cambiar-secreto-urls"
    url_publica_custodia: str = "http://localhost:8004"
    expiracion_descarga_segundos: int = 300
    expiracion_url_govcarpeta_segundos: int = 900
    antivirus: str = "eicar"  # eicar | clamav
    clamav_host: str = "clamav"
    clamav_puerto: int = 3310

    # --- Certificación
    clave_sello: str = "cambiar-clave-sello"

    # --- Infraestructura compartida
    bus: str = "memoria"  # memoria | rabbitmq
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672/"
    cache: str = "memoria"  # memoria | redis
    redis_url: str = "redis://localhost:6379/0"

    # --- Notificaciones
    smtp_host: str = ""
    smtp_puerto: int = 1025
    smtp_remitente: str = "no-responder@micarpeta.co"

    # --- Administración (bitácora de auditoría)
    admin_api_key: str = "cambiar-admin"

    def url_bd(self, servicio: str) -> str:
        return self.database_url.replace("{servicio}", servicio)

    def url_servicio(self, servicio: str) -> str:
        return getattr(self, f"url_{servicio}")

    @property
    def extensiones(self) -> set[str]:
        return {e.strip().lower() for e in self.extensiones_permitidas.split(",") if e.strip()}

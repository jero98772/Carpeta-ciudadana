"""Crea el archivo .env a partir de .env.example con secretos aleatorios.

    python scripts/generar_secretos.py
"""

import base64
import os
import secrets
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
destino, plantilla = RAIZ / ".env", RAIZ / ".env.example"

if destino.exists() and "--forzar" not in sys.argv:
    sys.exit(".env ya existe. Usa --forzar para reemplazarlo.")

valores = {
    "TOKEN_INTERNO": secrets.token_urlsafe(32),
    "SECRETO_URLS": secrets.token_urlsafe(32),
    "CLAVE_SELLO": secrets.token_urlsafe(32),
    "ADMIN_API_KEY": secrets.token_urlsafe(24),
    "CLAVE_CIFRADO_CUSTODIA": base64.b64encode(os.urandom(32)).decode(),
}
lineas = []
for linea in plantilla.read_text(encoding="utf-8").splitlines():
    clave = linea.split("=", 1)[0]
    lineas.append(f"{clave}={valores[clave]}" if clave in valores else linea)
destino.write_text("\n".join(lineas) + "\n", encoding="utf-8")
print(f".env creado. ADMIN_API_KEY={valores['ADMIN_API_KEY']}  (úsala en la cabecera X-Admin-Key)")

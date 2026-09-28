# Un solo Dockerfile parametrizado para todos los microservicios (ADR-002).
# El servicio se elige con la variable SERVICIO y el puerto con PUERTO.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SERVICIO=gateway \
    PUERTO=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY micarpeta ./micarpeta
RUN useradd --create-home --uid 10001 micarpeta \
    && mkdir -p /app/secretos /app/datos \
    && chown -R micarpeta /app
USER micarpeta

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PUERTO\"]}/salud', timeout=2)"

CMD ["sh", "-c", "exec uvicorn micarpeta.servicios.${SERVICIO}.main:app --host 0.0.0.0 --port ${PUERTO} --proxy-headers"]

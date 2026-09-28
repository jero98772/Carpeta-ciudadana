"""Librería compartida por los microservicios de MiCarpeta CO.

Cada módulo expone una abstracción con dos implementaciones intercambiables:
una en memoria (pruebas y modo local) y otra de infraestructura real
(PostgreSQL, RabbitMQ, Redis, MinIO) para el despliegue con Docker.
"""

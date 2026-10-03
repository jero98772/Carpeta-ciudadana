# MiCarpeta CO · Operador de Carpeta Ciudadana

Implementación del documento de arquitectura «Carpeta Ciudadana Digital — Operador MiCarpeta CO».
Son microservicios en FastAPI (Python 3.11+) que cubren los cuatro casos de uso pedidos:

| Caso de uso | Qué hace | Endpoint (vía gateway) |
|---|---|---|
| **CU-01** Registro | Saga VALIDAR → AFILIAR → CREDENCIAL → ACTIVAR contra GovCarpeta, con compensación | `POST /api/v1/ciudadanos` |
| **CU-02** Login | Argon2id, JWT RS256, refresh rotativo, bloqueo, anti-enumeración, rate limiting | `POST /api/v1/auth/login` |
| **CU-03** Cargar documentos | Validación, antivirus, SHA-256, deduplicación, cifrado AES-256-GCM, URL prefirmada | `POST /api/v1/documentos` |
| **CU-04** Autenticar documento | 202 asíncrono, URL temporal a GovCarpeta, reintentos, cortacircuitos, sello verificable | `POST /api/v1/documentos/{id}/autenticacion` |

Incluye un portal web para la demo, un simulador de GovCarpeta y **las 49 pruebas de la sección 8**
(12 + 14 + 12 + 11), que pasan.

---

## 1. Arranque rápido

### Opción A · Sin Docker (lo más rápido para probar)

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m micarpeta.local
```

Abre **http://localhost:8000**, crea una cuenta, carga un PDF y autentícalo.
Los nueve microservicios corren en un solo proceso, cada uno con su propia base SQLite
(`./datos/local/`), y GovCarpeta es el simulador (http://localhost:8090/api-docs).

### Opción B · Con Docker (despliegue completo)

```bash
python scripts/generar_secretos.py     # crea .env con secretos aleatorios
docker compose up --build
```

Levanta los 9 microservicios en contenedores separados más PostgreSQL 16 (una base por servicio),
RabbitMQ, Redis, MinIO, Mailpit y el simulador de GovCarpeta.

| URL | Qué es |
|---|---|
| http://localhost:8000 | Portal del ciudadano y API (gateway) |
| http://localhost:8025 | Mailpit: los correos de bienvenida y de autenticación |
| http://localhost:15672 | RabbitMQ (guest / guest): colas `ms-notificaciones`, `ms-auditoria` y sus `.dlq` |
| http://localhost:9001 | Consola de MinIO: los binarios guardados (cifrados) |
| http://localhost:8001/docs … 8009/docs | Swagger de cada microservicio |
| http://localhost:8090/api-docs | Simulador de GovCarpeta |

Para activar ClamAV real en lugar de la detección EICAR: `ANTIVIRUS=clamav` en `.env` y
`docker compose --profile antivirus up`.

### Pruebas

```bash
pytest            # 49 passed
```

Montan todos los microservicios en un proceso con el transporte ASGI de httpx (sin Docker ni puertos),
exactamente como dice la sección 8.1 del documento.

---

## 2. Conectarse a la API real de GovCarpeta

Por defecto todo usa el simulador. Para la entrega real:

1. **Registrar el operador (una sola vez por equipo):**
   ```bash
   python scripts/registrar_operador.py \
     --direccion "https://url-o-direccion-del-operador" \
     --correo "correo-del-equipo@..." \
     --participantes "Danna Gabriela Salazar Cárdenas" "Danielo Arango Sohm"
   ```
   El script revisa primero `getOperators`: si el nombre «MiCarpeta CO» ya existe no registra otro y
   muestra el id existente. Si el nombre es de otro equipo, usa `--nombre "Otro nombre"`.
2. **Copiar el id a `.env`:**
   ```
   GOVCARPETA_URL=https://govcarpeta-apis-4905ff3c005b.herokuapp.com
   GOVCARPETA_OPERATOR_ID=<el id que imprimió el script>
   ```
3. Arrancar con `python -m micarpeta.local --govcarpeta-real` o con `docker compose up`.

**Datos del contrato real que el código ya maneja** (ms-interoperabilidad es el único que los conoce):

- `GET /apis/validateCitizen/{id}`: **200 = el ciudadano YA está registrado** (con un texto que nombra al
  operador) y **204 = está libre**. Ojo: el documento de arquitectura lo dice al revés (ver sección 7).
- `POST /apis/registerCitizen`: 201 creado, **501 si ya existe**. El `id` va como número.
- `DELETE /apis/unregisterCitizen`: los datos van en el cuerpo; 201 eliminado, 204 si no existía.
- `PUT /apis/authenticateDocument`: `{idCitizen (número), UrlDocument (con U mayúscula), documentTitle}`.
  Responde 200 con texto plano.
- Las respuestas son texto en prosa, no JSON. 501 es error de negocio (no se reintenta); 5xx y caídas sí.

GovCarpeta es un sandbox compartido por todos los equipos. Usen números de documento de prueba,
no cédulas reales.

---

## 3. Arquitectura implementada

| # | Servicio | Puerto | Responsabilidad | Datos propios |
|---|---|---|---|---|
| MS-00 | ms-gateway | 8000 | JWT en el borde, revocación por `jti`, rate limiting, enrutamiento, portal | — |
| MS-01 | ms-identidad | 8001 | Ciudadano y orquestador de la saga de registro | `db_identidad` |
| MS-02 | ms-autenticacion | 8002 | Argon2id, JWT RS256 + JWKS, refresh tokens, bloqueo | `db_autenticacion` |
| MS-03 | ms-documentos | 8003 | Catálogo, metadatos, cuota, máquina de estados | `db_documentos` |
| MS-04 | ms-custodia | 8004 | SHA-256, antivirus, deduplicación, AES-256-GCM, URLs HMAC | `db_custodia` + MinIO |
| MS-05 | ms-certificacion | 8005 | Autenticación asíncrona, sello, verificación pública, idempotencia | `db_certificacion` |
| MS-06 | ms-interoperabilidad | 8006 | ACL hacia GovCarpeta: reintentos con backoff + jitter, cortacircuitos | caché Redis |
| MS-08 | ms-notificaciones | 8008 | Consume eventos → bandeja + correo | `db_notificaciones` |
| MS-09 | ms-auditoria | 8009 | Bitácora append-only con cadena de hashes | `db_auditoria` |

- **Sin claves foráneas entre servicios.** La consistencia se logra con la saga (CU-01) y con eventos.
- **Eventos CloudEvents 1.0** en el exchange topic `carpeta.eventos` de RabbitMQ:
  `co.micarpeta.ciudadano.registrado`, `co.micarpeta.documento.cargado`, `co.micarpeta.documento.autenticado`,
  `co.micarpeta.documento.autenticacion_fallida`, `co.micarpeta.sesion.login_exitoso|login_fallido`.
  Hay una cola por consumidor, dead-letter queue y consumidores idempotentes por id de evento.
- **Errores RFC 7807** (`application/problem+json`) con un campo `codigo` estable, por ejemplo
  `CIUDADANO_YA_AFILIADO`, `CUENTA_BLOQUEADA`, `ARCHIVO_INFECTADO` o `ESTADO_INVALIDO`.
- **Rutas `/internal/*` y `/gov/*`**: el gateway nunca las expone y además exigen la cabecera
  `X-Token-Interno`.
- **Un solo Dockerfile** parametrizado con `SERVICIO` y `PUERTO` (ADR-002).
- **El mismo código corre en dos modos.** `micarpeta/comun/` tiene implementaciones en memoria
  (pruebas y modo local) y reales (PostgreSQL, RabbitMQ, Redis, MinIO) de cada pieza de infraestructura.

---

## 4. Los cuatro flujos con `curl`

```bash
API=http://localhost:8000

# CU-01 Registro
curl -s -X POST $API/api/v1/ciudadanos -H 'Content-Type: application/json' -d '{
  "documento": "1020304050", "nombre_completo": "Ana María Restrepo",
  "correo": "ana.restrepo@correo.com", "direccion": "Calle 10 # 20-30, Medellín",
  "password": "ClaveSegura2026"}'
# -> 201 {"estado": "ACTIVO", "direccion_unica": "ana.maria.4050@micarpeta.co", ...}

# CU-02 Login
TOKEN=$(curl -s -X POST $API/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"documento":"1020304050","password":"ClaveSegura2026"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# CU-03 Cargar documento
curl -s -X POST $API/api/v1/documentos -H "Authorization: Bearer $TOKEN" \
  -F titulo="Diploma de pregrado" -F tipo_documental=DIPLOMA -F archivo=@diploma.pdf
# -> 201 {"id": "...", "estado": "TEMPORAL", "hash_sha256": "...", "objeto_urn": "urn:micarpeta:custodia:..."}

# CU-04 Autenticar ante GovCarpeta
curl -s -X POST $API/api/v1/documentos/<ID>/autenticacion -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: $(uuidgen)"
# -> 202 {"solicitud_id": "...", "estado": "EN_PROCESO"}
curl -s $API/api/v1/solicitudes/<SOLICITUD_ID> -H "Authorization: Bearer $TOKEN"   # AUTENTICADO | FALLIDO
curl -s $API/api/v1/verificacion/<ID>                                            # pública, sin token
```

Otros endpoints: `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`, `GET /api/v1/ciudadanos/yo`,
`GET /api/v1/documentos`, `GET /api/v1/documentos/{id}/descarga`, `GET /api/v1/notificaciones`.
Administración, con la cabecera `X-Admin-Key` (valor de `ADMIN_API_KEY` en `.env`; en modo local
sin `.env` es `cambiar-admin`): `GET /api/v1/auditoria/verificacion`, `GET /api/v1/auditoria/registros`
y `GET /api/v1/admin/govcarpeta`.

---

## 5. Guion para la demo

El simulador permite provocar fallas de GovCarpeta en vivo para mostrar la resiliencia:

```bash
SIM=http://localhost:8090
curl -X POST $SIM/_control/fallas -H 'Content-Type: application/json' -d '{"endpoint":"*","veces":2}'   # 2 fallas y luego se recupera
curl -X POST $SIM/_control/fallas -H 'Content-Type: application/json' -d '{"endpoint":"authenticateDocument"}'  # caído indefinidamente
curl -X DELETE $SIM/_control/fallas                                            # vuelve a la normalidad
curl -X POST $SIM/_control/ciudadanos -H 'Content-Type: application/json' -d '{"id":55555555,"operador":"Carpeta Segura SAS"}'
curl $SIM/_control/estado                                                      # qué recibió GovCarpeta
```

| Qué mostrar | Cómo |
|---|---|
| HU-01.1 Registro y afiliación | Crear cuenta en el portal y luego ver `_control/estado`: aparece con `operatorName: MiCarpeta CO` |
| HU-01.3 Ya afiliado a otro operador | Afiliar 55555555 a otro operador con `_control/ciudadanos` y registrarlo: 409 `CIUDADANO_YA_AFILIADO` |
| HU-01.4 Compensación | Activar fallas `"*"` sin límite y registrar: 503, ciudadano PENDIENTE, saga COMPENSADA |
| HU-01.5 Reintentos | Activar `"veces":2` y registrar: 201 ACTIVO |
| HU-02.4 Bloqueo | 5 contraseñas malas y la sexta devuelve 423 aunque sea la correcta |
| HU-03.2 Antivirus | Subir un PDF que contenga la cadena EICAR: 422 `ARCHIVO_INFECTADO` |
| HU-04.1 Autenticación | Botón «Autenticar ante GovCarpeta»: pasa a Certificado y aparece el sello |
| HU-04.3 / 04.4 Fallo y cortacircuitos | Con GovCarpeta caído, el documento vuelve a Temporal y llega el correo de fallo. Tras 2 o 3 solicitudes, `GET /api/v1/admin/govcarpeta` con `X-Admin-Key` muestra el cortacircuitos ABIERTO |
| HU-04.5 Verificación pública | «Copiar enlace de verificación» y abrirlo en una ventana privada, subiendo el mismo archivo |
| HU-04.6 Bitácora | `GET /api/v1/auditoria/verificacion` con `X-Admin-Key`: `valida: true` |

---

## 6. Estructura

```
micarpeta/
  comun/            config, BD, eventos (memoria/RabbitMQ), caché (memoria/Redis), clientes, JWT, errores
  servicios/
    gateway/  identidad/  autenticacion/  documentos/  custodia/
    certificacion/  interoperabilidad/  notificaciones/  auditoria/
    govcarpeta_mock/   simulador fiel al contrato real + control de fallas
  portal/index.html    portal del ciudadano (lo sirve el gateway)
  sistema.py           arma los 9 servicios en un proceso (pruebas y modo local)
  local.py             python -m micarpeta.local
tests/                 49 pruebas: test_cu01 … test_cu04
scripts/               registrar_operador.py, generar_secretos.py, postgres-init.sql
Dockerfile, docker-compose.yml
```

---


## 7. Limitaciones conocidas

- Las tablas se crean al arrancar (`create_all`). Para evolucionar el esquema en producción conviene Alembic.
- Los eventos se publican después del commit, sin *transactional outbox*: si RabbitMQ cae en ese instante,
  el evento se pierde y queda registrado en el log.
- El cortacircuitos vive en memoria de ms-interoperabilidad; con varias réplicas debería compartirse en Redis.
- El procesamiento asíncrono de CU-04 usa tareas en segundo plano de FastAPI. Si el proceso muere a mitad
  de camino, la solicitud queda EN_PROCESO; una cola de trabajos lo resolvería.
- La URL que se envía a GovCarpeta apunta a `URL_PUBLICA_CUSTODIA`. En local es `http://localhost:8004`,
  y la API real no descarga el documento, así que no afecta la integración. En producción debe ser
  un dominio público con HTTPS.

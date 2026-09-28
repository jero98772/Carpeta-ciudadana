"""CU-02 · Autenticación en el operador / login (14 pruebas)."""

import base64
import json

from sqlalchemy import select

from micarpeta.servicios.autenticacion.modelos import Credencial, IntentoAcceso

from .utilidades import ANA, PASSWORD, auth, claims, iniciar_sesion, registrar, token_de


async def test_hu02_1_login_exitoso_emite_jwt_rs256(sistema, api):
    await registrar(api)

    r = await iniciar_sesion(api)

    assert r.status_code == 200, r.text
    cuerpo = r.json()
    assert cuerpo["token_type"] == "Bearer"
    assert cuerpo["expires_in"] == sistema.config.jwt_expiracion_segundos
    assert cuerpo["refresh_token"]
    c = claims(cuerpo["access_token"])
    assert c["doc"] == ANA["documento"]
    assert c["roles"] == ["ciudadano"]
    assert c["iss"] == sistema.config.jwt_emisor
    assert c["aud"] == sistema.config.jwt_audiencia
    assert c["sub"] and c["jti"]
    cabecera = json.loads(base64.urlsafe_b64decode(cuerpo["access_token"].split(".")[0] + "=="))
    assert cabecera["alg"] == "RS256" and cabecera["kid"]


async def test_hu02_2_login_no_depende_de_govcarpeta(sistema, api):
    await registrar(api)
    llamadas_antes = len(sistema.gov.llamadas)
    sistema.gov.fallar("*")

    r = await iniciar_sesion(api)

    assert r.status_code == 200
    assert len(sistema.gov.llamadas) == llamadas_antes  # el login no tocó GovCarpeta


async def test_hu02_3_anti_enumeracion_misma_respuesta(api):
    await registrar(api)

    inexistente = await iniciar_sesion(api, "9999999999", "CualquierCosa123")
    incorrecta = await iniciar_sesion(api, ANA["documento"], "ClaveEquivocada99")

    assert inexistente.status_code == incorrecta.status_code == 401
    assert inexistente.json()["codigo"] == incorrecta.json()["codigo"] == "CREDENCIALES_INVALIDAS"
    assert inexistente.json()["title"] == incorrecta.json()["title"]
    assert inexistente.json() == incorrecta.json()


async def test_hu02_4_bloqueo_tras_cinco_intentos_fallidos(api):
    await registrar(api)
    for _ in range(5):
        assert (await iniciar_sesion(api, password="ClaveEquivocada99")).status_code == 401

    sexto = await iniciar_sesion(api, password="ClaveEquivocada99")
    con_clave_correcta = await iniciar_sesion(api)

    assert sexto.status_code == 423
    assert sexto.json()["codigo"] == "CUENTA_BLOQUEADA"
    assert con_clave_correcta.status_code == 423


async def test_contrasena_se_guarda_con_argon2id(sistema, api):
    await registrar(api)

    async with sistema.sesion("autenticacion") as s:
        cred = await s.scalar(select(Credencial).where(Credencial.documento == ANA["documento"]))

    assert cred.hash_password.startswith("$argon2id$")
    assert PASSWORD not in cred.hash_password


async def test_intentos_de_acceso_quedan_registrados(sistema, api):
    await registrar(api)
    await iniciar_sesion(api, password="ClaveEquivocada99")
    await iniciar_sesion(api)

    async with sistema.sesion("autenticacion") as s:
        intentos = (await s.scalars(select(IntentoAcceso).order_by(IntentoAcceso.id))).all()

    assert [(i.exitoso, i.motivo) for i in intentos] == [(False, "CREDENCIALES_INVALIDAS"), (True, "EXITOSO")]
    assert all(i.ip_origen for i in intentos)


async def test_acceso_sin_token_es_rechazado(api):
    r = await api.get("/api/v1/documentos")

    assert r.status_code == 401
    assert r.json()["codigo"] == "NO_AUTENTICADO"
    assert r.headers["www-authenticate"] == "Bearer"


async def test_acceso_con_token_valido(api):
    token = await token_de(api)

    r = await api.get("/api/v1/documentos", headers=auth(token))

    assert r.status_code == 200
    assert r.json()["documentos"] == []


async def test_acceso_con_token_manipulado_es_rechazado(api):
    token = await token_de(api)
    cabecera, carga, firma = token.split(".")
    datos = claims(token) | {"sub": "otro-ciudadano"}
    carga_falsa = base64.urlsafe_b64encode(json.dumps(datos).encode()).decode().rstrip("=")

    r = await api.get("/api/v1/documentos", headers=auth(f"{cabecera}.{carga_falsa}.{firma}"))

    assert r.status_code == 401
    assert r.json()["codigo"] == "TOKEN_INVALIDO"


async def test_hu02_5_renovacion_rota_el_refresh_token(api):
    await registrar(api)
    sesion = (await iniciar_sesion(api)).json()

    r = await api.post("/api/v1/auth/refresh", json={"refresh_token": sesion["refresh_token"]})

    assert r.status_code == 200
    nueva = r.json()
    assert nueva["refresh_token"] != sesion["refresh_token"]
    assert (await api.get("/api/v1/documentos", headers=auth(nueva["access_token"]))).status_code == 200


async def test_hu02_5_refresh_token_reutilizado_queda_invalidado(api):
    await registrar(api)
    sesion = (await iniciar_sesion(api)).json()
    nueva = (await api.post("/api/v1/auth/refresh", json={"refresh_token": sesion["refresh_token"]})).json()

    reuso = await api.post("/api/v1/auth/refresh", json={"refresh_token": sesion["refresh_token"]})
    tras_reuso = await api.post("/api/v1/auth/refresh", json={"refresh_token": nueva["refresh_token"]})

    assert reuso.status_code == 401
    assert reuso.json()["codigo"] == "TOKEN_REVOCADO"
    assert tras_reuso.status_code == 401  # se revocó toda la familia por posible robo


async def test_cierre_de_sesion_revoca_el_access_token(api):
    await registrar(api)
    sesion = (await iniciar_sesion(api)).json()

    r = await api.post("/api/v1/auth/logout", headers=auth(sesion["access_token"]), json={"refresh_token": sesion["refresh_token"]})
    despues = await api.get("/api/v1/documentos", headers=auth(sesion["access_token"]))

    assert r.status_code == 204
    assert despues.status_code == 401
    assert despues.json()["codigo"] == "TOKEN_REVOCADO"


async def test_cierre_de_sesion_invalida_el_refresh_token(api):
    await registrar(api)
    sesion = (await iniciar_sesion(api)).json()
    await api.post("/api/v1/auth/logout", headers=auth(sesion["access_token"]), json={"refresh_token": sesion["refresh_token"]})

    r = await api.post("/api/v1/auth/refresh", json={"refresh_token": sesion["refresh_token"]})

    assert r.status_code == 401


async def test_rate_limiting_en_login(fabrica):
    sistema = await fabrica(limite_login_por_minuto=3)
    api = sistema.cliente()

    # 2×límite+1 intentos garantizan superar el límite aunque cambie la ventana de un minuto
    respuestas = [await iniciar_sesion(api, "1234567890", "Cualquiera123") for _ in range(7)]

    bloqueadas = [r for r in respuestas if r.status_code == 429]
    assert bloqueadas
    assert bloqueadas[0].json()["codigo"] == "LIMITE_EXCEDIDO"
    assert int(bloqueadas[0].headers["retry-after"]) > 0

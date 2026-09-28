"""CU-04 · Autenticar documentos a través de GovCarpeta (11 pruebas)."""

import json

from sqlalchemy import select, update

from micarpeta.servicios.auditoria.app import RegistroAuditoria
from micarpeta.servicios.notificaciones.app import Notificacion

from .utilidades import ANA, BRUNO, autenticar, auth, cargar, pdf_distinto, token_de

ADMIN = {"X-Admin-Key": "admin-pruebas"}


async def preparar(api):
    token = await token_de(api)
    doc = (await cargar(api, token)).json()
    return token, doc


async def estado_documento(api, token, doc_id):
    return (await api.get(f"/api/v1/documentos/{doc_id}", headers=auth(token))).json()


async def test_hu04_1_autenticacion_exitosa_certifica_con_sello(api):
    token, doc = await preparar(api)

    r, final = await autenticar(api, token, doc["id"])

    assert r.status_code == 202
    assert r.json()["estado"] == "EN_PROCESO"
    assert r.headers["location"] == f"/api/v1/solicitudes/{r.json()['solicitud_id']}"
    assert final["estado"] == "AUTENTICADO"
    documento = await estado_documento(api, token, doc["id"])
    assert documento["estado"] == "CERTIFICADO"
    assert documento["fecha_certificacion"]
    assert documento["sello"].startswith("SELLO-")


async def test_hu04_2_govcarpeta_recibe_url_nunca_el_binario(sistema, api):
    token, doc = await preparar(api)

    await autenticar(api, token, doc["id"])

    llamada = sistema.gov.llamadas_a("authenticateDocument")[0]
    cuerpo = json.loads(llamada["cuerpo"])
    assert set(cuerpo) == {"idCitizen", "UrlDocument", "documentTitle"}
    assert isinstance(cuerpo["idCitizen"], int) and cuerpo["idCitizen"] == int(ANA["documento"])
    assert cuerpo["documentTitle"] == "Diploma de pregrado"
    assert cuerpo["UrlDocument"].startswith("https://")
    assert "firma=" in cuerpo["UrlDocument"]
    assert len(llamada["cuerpo"]) < 1024  # solo metadatos


async def test_autenticacion_publica_evento_y_notifica(sistema, api):
    token, doc = await preparar(api)

    await autenticar(api, token, doc["id"])

    eventos = sistema.bus.de_tipo("co.micarpeta.documento.autenticado")
    assert len(eventos) == 1 and eventos[0]["data"]["documento_id"] == doc["id"]
    avisos = (await api.get("/api/v1/notificaciones", headers=auth(token))).json()["notificaciones"]
    assert any("fue autenticado" in a["asunto"] for a in avisos)


async def test_idempotencia_de_la_solicitud(sistema, api):
    token, doc = await preparar(api)
    clave = {"Idempotency-Key": "solicitud-123"}

    primera, _ = await autenticar(api, token, doc["id"], **clave)
    repetida, _ = await autenticar(api, token, doc["id"], **clave)
    sin_clave, _ = await autenticar(api, token, doc["id"])

    assert repetida.status_code == 202
    assert repetida.json()["solicitud_id"] == primera.json()["solicitud_id"]
    assert repetida.headers["idempotent-replay"] == "true"
    assert len(sistema.gov.autenticaciones) == 1  # GovCarpeta se invocó una sola vez
    assert sin_clave.status_code == 409
    assert sin_clave.json()["codigo"] == "ESTADO_INVALIDO"


async def test_hu04_3_fallo_persistente_devuelve_el_documento_a_temporal(sistema, api):
    token, doc = await preparar(api)
    sistema.gov.fallar("authenticateDocument")

    r, final = await autenticar(api, token, doc["id"])

    assert r.status_code == 202
    assert final["estado"] == "FALLIDO"
    assert "GOVCARPETA_NO_DISPONIBLE" in final["ultimo_error"]
    assert (await estado_documento(api, token, doc["id"]))["estado"] == "TEMPORAL"
    assert len(sistema.bus.de_tipo("co.micarpeta.documento.autenticacion_fallida")) == 1
    async with sistema.sesion("notificaciones") as s:
        asuntos = (await s.scalars(select(Notificacion.asunto))).all()
    assert any("No pudimos autenticar" in a for a in asuntos)


async def test_fallos_transitorios_son_absorbidos_por_reintentos(sistema, api):
    token, doc = await preparar(api)
    sistema.gov.fallar("authenticateDocument", veces=2)

    _, final = await autenticar(api, token, doc["id"])

    assert final["estado"] == "AUTENTICADO"
    assert len(sistema.gov.llamadas_a("authenticateDocument")) == 3
    assert (await estado_documento(api, token, doc["id"]))["estado"] == "CERTIFICADO"


async def test_hu04_4_cortacircuitos_se_abre_tras_fallos_consecutivos(sistema, api):
    token = await token_de(api)
    docs = [(await cargar(api, token, pdf_distinto(str(i)), titulo=f"Documento {i}")).json() for i in range(3)]
    sistema.gov.fallar("authenticateDocument")

    for d in docs:
        await autenticar(api, token, d["id"])

    estado = sistema.apps["interoperabilidad"].state.cortacircuitos.resumen()
    assert estado["estado"] == "ABIERTO"
    assert estado["fallos_totales"] >= sistema.config.cortacircuitos_umbral
    # 3 solicitudes × 3 intentos serían 9 llamadas; el circuito abierto corta antes
    assert len(sistema.gov.llamadas_a("authenticateDocument")) < 9
    for d in docs:
        assert (await estado_documento(api, token, d["id"]))["estado"] == "TEMPORAL"


async def test_no_se_puede_autenticar_documento_ajeno(sistema, api):
    token_a, doc_a = await preparar(api)
    token_b = await token_de(api, BRUNO)

    r = await api.post(f"/api/v1/documentos/{doc_a['id']}/autenticacion", headers=auth(token_b))

    assert r.status_code == 404
    assert sistema.gov.autenticaciones == []
    assert (await estado_documento(api, token_a, doc_a["id"]))["estado"] == "TEMPORAL"


async def test_hu04_5_verificacion_publica_sin_sesion(api):
    token, doc = await preparar(api)
    await autenticar(api, token, doc["id"])

    r = await api.get(f"/api/v1/verificacion/{doc['id']}")
    con_hash = await api.get(f"/api/v1/verificacion/{doc['id']}", params={"hash": doc["hash_sha256"]})
    hash_distinto = await api.get(f"/api/v1/verificacion/{doc['id']}", params={"hash": "f" * 64})

    assert r.status_code == 200
    assert r.json()["autentico"] is True
    assert r.json()["hash_sha256"] == doc["hash_sha256"]
    assert r.json()["emisor"] == "MiCarpeta CO"
    assert con_hash.json()["autentico"] is True and con_hash.json()["coincide_hash"] is True
    assert hash_distinto.json()["autentico"] is False


async def test_documento_sin_sello_no_se_verifica(api):
    _, doc = await preparar(api)

    r = await api.get(f"/api/v1/verificacion/{doc['id']}")

    assert r.status_code == 404
    assert r.json()["codigo"] == "SELLO_NO_ENCONTRADO"


async def test_hu04_6_bitacora_de_auditoria_verificable(sistema, api):
    token, doc = await preparar(api)
    await autenticar(api, token, doc["id"])

    r = await api.get("/api/v1/auditoria/verificacion", headers=ADMIN)
    tipos = {x["tipo"] for x in (await api.get("/api/v1/auditoria/registros", headers=ADMIN)).json()["registros"]}

    assert r.json()["valida"] is True
    assert {"CIUDADANO_REGISTRADO", "DOCUMENTO_CARGADO", "DOCUMENTO_AUTENTICADO"} <= tipos
    assert (await api.get("/api/v1/auditoria/verificacion")).status_code == 403  # requiere X-Admin-Key

    # Alterar un registro rompe la cadena de hashes
    async with sistema.sesion("auditoria") as s:
        objetivo = await s.scalar(select(RegistroAuditoria).where(RegistroAuditoria.tipo == "DOCUMENTO_CARGADO"))
        await s.execute(update(RegistroAuditoria).where(RegistroAuditoria.id == objetivo.id).values(resultado="ALTERADO"))
        await s.commit()
    alterada = (await api.get("/api/v1/auditoria/verificacion", headers=ADMIN)).json()
    assert alterada["valida"] is False
    assert alterada["primer_registro_alterado"] == objetivo.id

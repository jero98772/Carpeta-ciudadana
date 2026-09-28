"""CU-03 · Cargar documentos en la carpeta (12 pruebas)."""

import hashlib
from urllib.parse import parse_qs, urlparse

from sqlalchemy import func, select

from micarpeta.servicios.custodia.almacen import FIRMA_EICAR
from micarpeta.servicios.custodia.app import ObjetoCustodiado
from micarpeta.servicios.documentos.app import Documento

from .utilidades import BRUNO, PDF, auth, cargar, pdf_distinto, token_de


async def test_hu03_1_carga_exitosa_separa_metadatos_y_binario(sistema, api):
    token = await token_de(api)

    r = await cargar(api, token)

    assert r.status_code == 201, r.text
    doc = r.json()
    assert doc["estado"] == "TEMPORAL"
    assert doc["hash_sha256"] == hashlib.sha256(PDF).hexdigest()
    assert doc["objeto_urn"].startswith("urn:micarpeta:custodia:")
    async with sistema.sesion("documentos") as s:
        assert (await s.get(Documento, doc["id"])).objeto_urn == doc["objeto_urn"]
    async with sistema.sesion("custodia") as s:
        objeto = await s.scalar(select(ObjetoCustodiado).where(ObjetoCustodiado.hash_sha256 == doc["hash_sha256"]))
    assert objeto.estado_antivirus == "LIMPIO"
    assert objeto.cifrado == "AES-256-GCM"
    # En disco queda cifrado: el contenido original no aparece en el almacén
    assert PDF not in await sistema.apps["custodia"].state.almacen.leer(objeto.clave)


async def test_carga_publica_evento_documento_cargado(sistema, api):
    token = await token_de(api)

    doc = (await cargar(api, token)).json()

    eventos = sistema.bus.de_tipo("co.micarpeta.documento.cargado")
    assert len(eventos) == 1
    assert eventos[0]["specversion"] == "1.0"
    assert eventos[0]["data"]["documento_id"] == doc["id"]


async def test_tipo_de_archivo_no_permitido(api):
    token = await token_de(api)

    r = await cargar(api, token, contenido=b"MZ\x90\x00binario", nombre="programa.exe")

    assert r.status_code == 422
    assert r.json()["codigo"] == "TIPO_NO_PERMITIDO"


async def test_tamano_excedido(sistema, api):
    token = await token_de(api)
    grande = PDF + b"0" * sistema.config.tamano_maximo_bytes

    r = await cargar(api, token, contenido=grande)

    assert r.status_code == 422
    assert r.json()["codigo"] == "TAMANO_EXCEDIDO"


async def test_archivo_vacio(api):
    token = await token_de(api)

    r = await cargar(api, token, contenido=b"")

    assert r.status_code == 422
    assert r.json()["codigo"] == "ARCHIVO_VACIO"


async def test_hu03_2_antivirus_rechaza_patron_eicar(api):
    token = await token_de(api)

    r = await cargar(api, token, contenido=PDF + FIRMA_EICAR, nombre="factura.pdf")

    assert r.status_code == 422
    assert r.json()["codigo"] == "ARCHIVO_INFECTADO"
    assert (await api.get("/api/v1/documentos", headers=auth(token))).json()["documentos"] == []


async def test_carga_sin_token_es_rechazada(api):
    r = await api.post(
        "/api/v1/documentos",
        data={"titulo": "Diploma", "tipo_documental": "DIPLOMA"},
        files={"archivo": ("diploma.pdf", PDF, "application/pdf")},
    )

    assert r.status_code == 401


async def test_hu03_3_aislamiento_entre_carpetas(api):
    token_a = await token_de(api)
    token_b = await token_de(api, BRUNO)
    doc_a = (await cargar(api, token_a)).json()

    ajeno = await api.get(f"/api/v1/documentos/{doc_a['id']}", headers=auth(token_b))
    descarga_ajena = await api.get(f"/api/v1/documentos/{doc_a['id']}/descarga", headers=auth(token_b))
    listado_b = await api.get("/api/v1/documentos", headers=auth(token_b))

    assert ajeno.status_code == 404  # no 403: no se confirma que exista
    assert descarga_ajena.status_code == 404
    assert listado_b.json()["documentos"] == []


async def test_hu03_5_descarga_con_url_prefirmada(sistema, api):
    token = await token_de(api)
    doc = (await cargar(api, token)).json()

    r = await api.get(f"/api/v1/documentos/{doc['id']}/descarga", headers=auth(token))

    url = r.json()["url"]
    assert url.startswith("https://")
    assert "firma=" in url and "expira=" in url
    partes = urlparse(url)
    archivo = await sistema.cliente("custodia").get(f"{partes.path}?{partes.query}")
    assert archivo.status_code == 200
    assert archivo.content == PDF  # se descifra al servirlo


async def test_hu03_5_firma_hmac_manipulada_o_vencida_es_rechazada(sistema, api):
    token = await token_de(api)
    doc = (await cargar(api, token)).json()
    url = urlparse((await api.get(f"/api/v1/documentos/{doc['id']}/descarga", headers=auth(token))).json()["url"])
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    custodia = sistema.cliente("custodia")

    manipulada = await custodia.get(url.path, params=q | {"firma": "0" * 64})
    otra_expiracion = await custodia.get(url.path, params=q | {"expira": str(int(q["expira"]) + 3600)})

    assert manipulada.status_code == 401
    assert manipulada.json()["codigo"] == "FIRMA_INVALIDA"
    assert otra_expiracion.status_code == 401  # alterar la expiración invalida la firma


async def test_cuota_de_documentos(fabrica):
    sistema = await fabrica(cuota_documentos=2)
    api = sistema.cliente()
    token = await token_de(api)
    assert (await cargar(api, token, pdf_distinto("1"))).status_code == 201
    assert (await cargar(api, token, pdf_distinto("2"))).status_code == 201

    r = await cargar(api, token, pdf_distinto("3"))

    assert r.status_code == 422
    assert r.json()["codigo"] == "CUOTA_EXCEDIDA"
    assert r.json()["cuota"]["documentos_usados"] == 2


async def test_hu03_4_deduplicacion_de_contenido_identico(sistema, api):
    token = await token_de(api)

    uno = (await cargar(api, token, titulo="Diploma (copia 1)")).json()
    dos = (await cargar(api, token, titulo="Diploma (copia 2)")).json()

    assert uno["id"] != dos["id"]
    assert uno["hash_sha256"] == dos["hash_sha256"]
    async with sistema.sesion("custodia") as s:
        assert await s.scalar(select(func.count()).select_from(ObjetoCustodiado)) == 1
    assert await sistema.apps["custodia"].state.almacen.contar() == 1

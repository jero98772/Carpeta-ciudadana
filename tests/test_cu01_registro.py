"""CU-01 · Registro de un ciudadano en la carpeta (12 pruebas)."""

import pytest
from sqlalchemy import select

from micarpeta.servicios.identidad.app import generar_direccion_unica
from micarpeta.servicios.identidad.modelos import Ciudadano, SagaRegistro
from micarpeta.servicios.notificaciones.app import Notificacion

from .utilidades import ANA, ciudadano, registrar


async def ciudadano_local(sistema, documento):
    async with sistema.sesion("identidad") as s:
        return await s.scalar(select(Ciudadano).where(Ciudadano.documento == documento))


async def ultima_saga(sistema, documento):
    async with sistema.sesion("identidad") as s:
        return await s.scalar(
            select(SagaRegistro).where(SagaRegistro.documento == documento).order_by(SagaRegistro.fecha_inicio.desc())
        )


async def test_hu01_1_registro_exitoso_afilia_en_govcarpeta(sistema, api):
    r = await registrar(api)

    assert r.status_code == 201, r.text
    cuerpo = r.json()
    assert cuerpo["estado"] == "ACTIVO"
    assert cuerpo["direccion_unica"].endswith("@micarpeta.co")
    afiliado = sistema.gov.ciudadanos[int(ANA["documento"])]
    assert afiliado["operatorName"] == "MiCarpeta CO"
    assert afiliado["operatorId"] == sistema.config.govcarpeta_operator_id
    saga = await ultima_saga(sistema, ANA["documento"])
    assert saga.estado == "COMPLETADA"
    assert saga.pasos_completados == "VALIDAR,AFILIAR,CREDENCIAL,ACTIVAR"


async def test_hu01_2_registro_publica_cloudevent_y_notifica(sistema, api):
    await registrar(api)

    eventos = sistema.bus.de_tipo("co.micarpeta.ciudadano.registrado")
    assert len(eventos) == 1
    evento = eventos[0]
    assert evento["specversion"] == "1.0"
    assert evento["data"]["documento"] == ANA["documento"]
    async with sistema.sesion("notificaciones") as s:
        avisos = (await s.scalars(select(Notificacion))).all()
    assert len(avisos) == 1
    assert avisos[0].destinatario == ANA["correo"]
    assert "Bienvenido" in avisos[0].asunto


async def test_hu01_3_ciudadano_ya_afiliado_a_otro_operador(sistema, api):
    sistema.gov.afiliar(int(ANA["documento"]), "Carpeta Segura SAS")

    r = await registrar(api)

    assert r.status_code == 409
    assert r.json()["codigo"] == "CIUDADANO_YA_AFILIADO"
    assert r.json()["operador_actual"] == "Carpeta Segura SAS"
    assert await ciudadano_local(sistema, ANA["documento"]) is None  # sin huérfanos locales
    assert (await ultima_saga(sistema, ANA["documento"])).estado == "RECHAZADA"


async def test_registro_duplicado_local_es_rechazado(sistema, api):
    assert (await registrar(api)).status_code == 201

    r = await registrar(api)

    assert r.status_code == 409
    assert r.json()["codigo"] == "CIUDADANO_YA_REGISTRADO"
    assert len(sistema.gov.llamadas_a("registerCitizen")) == 1


async def test_hu01_4_saga_compensa_ante_fallos(sistema, api):
    # (a) GovCarpeta no responde (fallo persistente): nada queda registrado
    sistema.gov.fallar("*")
    r = await registrar(api)
    assert r.status_code == 503
    assert r.json()["codigo"] == "GOVCARPETA_NO_DISPONIBLE"
    assert (await ciudadano_local(sistema, ANA["documento"])).estado == "PENDIENTE"
    assert (await ultima_saga(sistema, ANA["documento"])).estado == "COMPENSADA"
    assert int(ANA["documento"]) not in sistema.gov.ciudadanos

    # (b) Falla un paso DESPUÉS de afiliar en GovCarpeta: se ejecuta DELETE /unregisterCitizen
    sistema.gov.recuperar()
    import httpx

    sistema.ctx.clientes.registrar_transporte("autenticacion", httpx.MockTransport(lambda req: httpx.Response(503)))
    r = await registrar(api)
    assert r.status_code == 503
    assert len(sistema.gov.llamadas_a("registerCitizen")) == 1
    assert len(sistema.gov.llamadas_a("unregisterCitizen")) == 1
    assert int(ANA["documento"]) not in sistema.gov.ciudadanos
    assert (await ciudadano_local(sistema, ANA["documento"])).estado == "PENDIENTE"
    saga = await ultima_saga(sistema, ANA["documento"])
    assert saga.estado == "COMPENSADA"
    assert saga.paso_actual == "CREDENCIAL"


async def test_hu01_5_reintentos_absorben_fallos_transitorios(sistema, api):
    sistema.gov.fallar("*", veces=2)

    r = await registrar(api)

    assert r.status_code == 201, r.text
    assert r.json()["estado"] == "ACTIVO"
    assert len(sistema.gov.llamadas_a("validateCitizen")) == 3


@pytest.mark.parametrize(
    ("campo", "valor"),
    [
        ("documento", "12AB"),
        ("correo", "no-es-un-correo"),
        ("password", "123"),
        ("nombre_completo", "  "),
        ("direccion", None),
    ],
    ids=["documento_invalido", "correo_invalido", "contrasena_debil", "nombre_vacio", "campo_faltante"],
)
async def test_validaciones_de_entrada(sistema, api, campo, valor):
    datos = ciudadano()
    if valor is None:
        del datos[campo]
    else:
        datos[campo] = valor

    r = await registrar(api, datos)

    assert r.status_code == 422
    assert r.json()["codigo"] == "DATOS_INVALIDOS"
    assert any(e["campo"] == campo for e in r.json()["errores"])
    assert sistema.gov.llamadas == []  # no se llama a GovCarpeta con datos inválidos


async def test_hu01_6_normalizacion_de_direccion_unica(api):
    esperado = "ana.maria.4050@micarpeta.co"
    assert generar_direccion_unica("Ana María Restrepo", "1020304050", "micarpeta.co") == esperado

    r = await registrar(api)

    direccion = r.json()["direccion_unica"]
    assert direccion == esperado
    assert direccion.isascii()

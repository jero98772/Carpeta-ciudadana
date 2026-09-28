"""Datos y pasos reutilizados por las pruebas."""

import asyncio
import base64
import json

PASSWORD = "ClaveSegura2026"

ANA = {
    "documento": "1020304050",
    "tipo_documento": "CC",
    "nombre_completo": "Ana María Restrepo",
    "correo": "ana.restrepo@correo.com",
    "direccion": "Calle 10 # 20-30, Medellín",
    "password": PASSWORD,
}
BRUNO = {
    "documento": "7080901234",
    "tipo_documento": "CC",
    "nombre_completo": "Bruno Díaz Gómez",
    "correo": "bruno.diaz@correo.com",
    "direccion": "Carrera 7 # 45-12, Bogotá",
    "password": PASSWORD,
}

PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"


def ciudadano(**cambios) -> dict:
    return {**ANA, **cambios}


def pdf_distinto(texto: str) -> bytes:
    return PDF + f"% {texto}\n".encode()


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def claims(token: str) -> dict:
    carga = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(carga + "=" * (-len(carga) % 4)))


async def registrar(api, datos: dict = ANA):
    return await api.post("/api/v1/ciudadanos", json=datos)


async def iniciar_sesion(api, documento: str = ANA["documento"], password: str = PASSWORD):
    return await api.post("/api/v1/auth/login", json={"documento": documento, "password": password})


async def token_de(api, datos: dict = ANA) -> str:
    r = await registrar(api, datos)
    assert r.status_code == 201, r.text
    r = await iniciar_sesion(api, datos["documento"], datos["password"])
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def cargar(api, token: str, contenido: bytes = PDF, titulo: str = "Diploma de pregrado",
                 tipo: str = "DIPLOMA", nombre: str = "diploma.pdf"):
    return await api.post(
        "/api/v1/documentos",
        headers=auth(token),
        data={"titulo": titulo, "tipo_documental": tipo},
        files={"archivo": (nombre, contenido, "application/pdf")},
    )


async def esperar_solicitud(api, token: str, solicitud_id: str, intentos: int = 50) -> dict:
    """Consulta la solicitud hasta que salga de EN_PROCESO (como haría el portal)."""
    for _ in range(intentos):
        r = await api.get(f"/api/v1/solicitudes/{solicitud_id}", headers=auth(token))
        assert r.status_code == 200, r.text
        if r.json()["estado"] != "EN_PROCESO":
            return r.json()
        await asyncio.sleep(0.02)
    raise AssertionError("La solicitud no terminó")


async def autenticar(api, token: str, documento_id: str, **cabeceras) -> tuple:
    r = await api.post(f"/api/v1/documentos/{documento_id}/autenticacion", headers=auth(token) | cabeceras)
    final = await esperar_solicitud(api, token, r.json()["solicitud_id"]) if r.status_code == 202 else None
    return r, final

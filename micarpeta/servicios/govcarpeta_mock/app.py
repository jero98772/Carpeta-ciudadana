"""Simulador de GovCarpeta (centralizador MinTIC) para desarrollo y pruebas.

Replica el contrato observado en la API real
(https://govcarpeta-apis-4905ff3c005b.herokuapp.com/api-docs/):

- GET    /apis/validateCitizen/{id}   200 + texto si YA está registrado, 204 si está libre
- POST   /apis/registerCitizen        201 creado, 501 si ya existe
- DELETE /apis/unregisterCitizen      201 eliminado, 204 si no existía (datos en el cuerpo)
- PUT    /apis/authenticateDocument   200 + texto (recibe una URL, nunca el binario)
- POST   /apis/registerOperator       201 + id en texto plano
- PUT    /apis/registerTransferEndPoint
- GET    /apis/getOperators           [{_id, operatorName, participants, transferAPIURL}]

Las respuestas son texto plano en prosa, como en la API real. Además expone
rutas /_control para inyectar fallas (que NO existen en la API real).
"""

import secrets
from dataclasses import dataclass, field

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response


@dataclass
class Falla:
    restantes: int  # -1 = siempre
    codigo: int = 503


@dataclass
class EstadoGovCarpeta:
    ciudadanos: dict[int, dict] = field(default_factory=dict)
    operadores: dict[str, dict] = field(default_factory=dict)
    autenticaciones: list[dict] = field(default_factory=list)
    llamadas: list[dict] = field(default_factory=list)
    fallas: dict[str, Falla] = field(default_factory=dict)

    # ---- utilidades para pruebas y demos
    def fallar(self, endpoint: str = "*", veces: int = -1, codigo: int = 503) -> None:
        """Hace que ``endpoint`` (o todos con "*") responda ``codigo`` las próximas ``veces``."""
        self.fallas[endpoint] = Falla(veces, codigo)

    def recuperar(self) -> None:
        self.fallas.clear()

    def registrar_operador(self, nombre: str, id_operador: str | None = None) -> str:
        id_operador = id_operador or secrets.token_hex(12)
        self.operadores[id_operador] = {
            "_id": id_operador,
            "operatorName": nombre,
            "participants": [],
            "transferAPIURL": None,
        }
        return id_operador

    def afiliar(self, documento: int, operador: str, nombre: str = "Ciudadano de prueba") -> None:
        id_op = next((k for k, v in self.operadores.items() if v["operatorName"] == operador), None)
        id_op = id_op or self.registrar_operador(operador)
        self.ciudadanos[int(documento)] = {
            "id": int(documento),
            "name": nombre,
            "address": "N/A",
            "email": "n/a@n/a.co",
            "operatorId": id_op,
            "operatorName": operador,
        }

    def llamadas_a(self, endpoint: str) -> list[dict]:
        return [c for c in self.llamadas if c["endpoint"] == endpoint]

    def _consumir_falla(self, endpoint: str) -> Falla | None:
        for clave in (endpoint, "*"):
            falla = self.fallas.get(clave)
            if falla and falla.restantes != 0:
                if falla.restantes > 0:
                    falla.restantes -= 1
                return falla
        return None


def crear_app_govcarpeta(estado: EstadoGovCarpeta | None = None) -> FastAPI:
    estado = estado or EstadoGovCarpeta()
    app = FastAPI(title="GovCarpeta (simulador)", version="1.0.0", docs_url="/api-docs")
    app.state.gov = estado

    @app.middleware("http")
    async def registrar_y_fallar(request: Request, call_next):
        partes = request.url.path.strip("/").split("/")
        if len(partes) >= 2 and partes[0] == "apis":
            endpoint = partes[1]
            cuerpo = await request.body()
            llamada = {"metodo": request.method, "endpoint": endpoint, "ruta": request.url.path, "cuerpo": cuerpo.decode(errors="replace")}
            estado.llamadas.append(llamada)
            falla = estado._consumir_falla(endpoint)
            if falla:
                llamada["estado"] = falla.codigo
                return PlainTextResponse("Application Error", status_code=falla.codigo)
            resp = await call_next(request)
            llamada["estado"] = resp.status_code
            return resp
        return await call_next(request)

    @app.get("/salud", include_in_schema=False)
    async def salud():
        return {"servicio": "govcarpeta-simulador", "estado": "ok"}

    # ------------------------------------------------------------------ operadores
    @app.post("/apis/registerOperator")
    async def register_operator(request: Request):
        datos = await request.json()
        nombre = datos.get("name") or datos.get("nameOperator")
        if not nombre:
            return PlainTextResponse("Faltan campos obligatorios", status_code=501)
        id_op = estado.registrar_operador(nombre)
        estado.operadores[id_op]["participants"] = datos.get("participants", [])
        return PlainTextResponse(id_op, status_code=201)

    @app.put("/apis/registerTransferEndPoint")
    async def register_transfer_endpoint(request: Request):
        datos = await request.json()
        op = estado.operadores.get(datos.get("idOperator", ""))
        if not op:
            return PlainTextResponse("Operador no existe", status_code=501)
        op["transferAPIURL"] = datos.get("endPoint")
        return PlainTextResponse("Endpoint registrado", status_code=201)

    @app.get("/apis/getOperators")
    async def get_operators():
        return JSONResponse(list(estado.operadores.values()))

    # ------------------------------------------------------------------ ciudadanos
    @app.get("/apis/validateCitizen/{id_ciudadano}")
    async def validate_citizen(id_ciudadano: int):
        c = estado.ciudadanos.get(id_ciudadano)
        if c is None:
            return Response(status_code=204)
        return PlainTextResponse(
            f"El ciudadano con id: {id_ciudadano} ya se encuentra registrado en el operador {c['operatorName']} ",
            status_code=200,
        )

    @app.post("/apis/registerCitizen")
    async def register_citizen(request: Request):
        datos = await request.json()
        requeridos = ("id", "name", "address", "email", "operatorId", "operatorName")
        if any(datos.get(k) in (None, "") for k in requeridos):
            return PlainTextResponse("Faltan campos obligatorios", status_code=501)
        id_c = int(datos["id"])
        if id_c in estado.ciudadanos:
            return PlainTextResponse(f"El ciudadano con id: {id_c} ya se encuentra registrado", status_code=501)
        if datos["operatorId"] not in estado.operadores:
            return PlainTextResponse("El operador no existe", status_code=501)
        estado.ciudadanos[id_c] = {k: datos[k] for k in requeridos} | {"id": id_c}
        return PlainTextResponse(f"Ciudadano con id: {id_c} se ha creado exitosamente", status_code=201)

    @app.delete("/apis/unregisterCitizen")
    async def unregister_citizen(request: Request):
        datos = await request.json()
        id_c = int(datos.get("id", 0))
        c = estado.ciudadanos.get(id_c)
        if c is None:
            return Response(status_code=204)
        if c["operatorId"] != datos.get("operatorId"):
            return PlainTextResponse("El ciudadano pertenece a otro operador", status_code=501)
        del estado.ciudadanos[id_c]
        return PlainTextResponse(f"Ciudadano con id: {id_c} eliminado", status_code=201)

    # ------------------------------------------------------------------ documentos
    @app.put("/apis/authenticateDocument")
    async def authenticate_document(request: Request):
        datos = await request.json()
        if not all(datos.get(k) for k in ("idCitizen", "UrlDocument", "documentTitle")):
            return PlainTextResponse("Faltan campos obligatorios", status_code=501)
        estado.autenticaciones.append(datos)
        return PlainTextResponse(
            f"El documento: {datos['documentTitle']} del ciudadano {datos['idCitizen']} ha sido autenticado exitosamente",
            status_code=200,
        )

    # ------------------------------------------------------------------ control (solo simulador)
    @app.post("/_control/fallas")
    async def control_fallas(request: Request):
        """{"endpoint": "authenticateDocument" | "*", "veces": 2, "codigo": 503}"""
        datos = await request.json()
        estado.fallar(datos.get("endpoint", "*"), int(datos.get("veces", -1)), int(datos.get("codigo", 503)))
        return {"fallas": {k: vars(v) for k, v in estado.fallas.items()}}

    @app.delete("/_control/fallas")
    async def control_recuperar():
        estado.recuperar()
        return {"fallas": {}}

    @app.post("/_control/ciudadanos")
    async def control_afiliar(request: Request):
        """Afilia un ciudadano a otro operador: {"id": 123, "operador": "Carpeta Segura SAS"}"""
        datos = await request.json()
        estado.afiliar(int(datos["id"]), datos.get("operador", "Carpeta Segura SAS"))
        return {"ok": True}

    @app.get("/_control/estado")
    async def control_estado():
        return {
            "ciudadanos": list(estado.ciudadanos.values()),
            "operadores": list(estado.operadores.values()),
            "autenticaciones": estado.autenticaciones,
            "ultimas_llamadas": estado.llamadas[-50:],
        }

    return app

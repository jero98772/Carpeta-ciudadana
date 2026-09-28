"""MS-03 ms-documentos · Catálogo, metadatos, cuota y máquina de estados (CU-03).

El binario vive en ms-custodia; aquí solo se guardan metadatos y la URN del
objeto. Estados del documento:

    TEMPORAL -> EN_AUTENTICACION -> CERTIFICADO
                        \\-> TEMPORAL   (si GovCarpeta falla)
"""

from datetime import datetime
from enum import StrEnum

from fastapi import Depends, FastAPI, File, Form, UploadFile
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import BigInteger, Integer, String, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, FechaUTC, ahora, nuevo_id, sesion_bd
from micarpeta.comun.errores import ErrorDominio, error_desde_respuesta
from micarpeta.comun.eventos import DOCUMENTO_CARGADO, crear_evento, publicar_seguro
from micarpeta.comun.seguridad import Usuario, usuario_actual


# ============================================================ modelo
class Base(DeclarativeBase):
    pass


class EstadoDocumento(StrEnum):
    TEMPORAL = "TEMPORAL"
    EN_AUTENTICACION = "EN_AUTENTICACION"
    CERTIFICADO = "CERTIFICADO"


TRANSICIONES = {
    EstadoDocumento.TEMPORAL: {EstadoDocumento.EN_AUTENTICACION},
    EstadoDocumento.EN_AUTENTICACION: {EstadoDocumento.CERTIFICADO, EstadoDocumento.TEMPORAL},
    EstadoDocumento.CERTIFICADO: set(),
}


class TipoDocumental(StrEnum):
    DIPLOMA = "DIPLOMA"
    ACTA_GRADO = "ACTA_GRADO"
    CERTIFICADO_LABORAL = "CERTIFICADO_LABORAL"
    CERTIFICADO_ACADEMICO = "CERTIFICADO_ACADEMICO"
    CEDULA = "CEDULA"
    REGISTRO_CIVIL = "REGISTRO_CIVIL"
    PASAPORTE = "PASAPORTE"
    HISTORIA_CLINICA = "HISTORIA_CLINICA"
    OTRO = "OTRO"


class Documento(Base):
    __tablename__ = "documentos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    ciudadano_id: Mapped[str] = mapped_column(String(36), index=True)  # referencia lógica
    titulo: Mapped[str] = mapped_column(String(200))
    tipo_documental: Mapped[str] = mapped_column(String(40))
    nombre_archivo: Mapped[str] = mapped_column(String(255))
    tipo_mime: Mapped[str] = mapped_column(String(120))
    tamano_bytes: Mapped[int] = mapped_column(BigInteger)
    hash_sha256: Mapped[str] = mapped_column(String(64), index=True)
    objeto_id: Mapped[str] = mapped_column(String(36))
    objeto_urn: Mapped[str] = mapped_column(String(120))
    estado: Mapped[str] = mapped_column(String(20), default=EstadoDocumento.TEMPORAL, index=True)
    sello: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fecha_carga: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)
    fecha_certificacion: Mapped[datetime | None] = mapped_column(FechaUTC, nullable=True)
    fecha_actualizacion: Mapped[datetime] = mapped_column(FechaUTC, default=ahora, onupdate=ahora)


class CuotaCiudadano(Base):
    __tablename__ = "cuotas"

    ciudadano_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    documentos_usados: Mapped[int] = mapped_column(Integer, default=0)
    bytes_usados: Mapped[int] = mapped_column(BigInteger, default=0)


class CambioEstado(BaseModel):
    estado: EstadoDocumento
    sello: str | None = None
    fecha_certificacion: datetime | None = None


MIME = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
FIRMAS_MAGICAS = {
    "pdf": (b"%PDF-",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "docx": (b"PK\x03\x04",),
}


def vista(d: Documento, interna: bool = False) -> dict:
    v = {
        "id": d.id,
        "titulo": d.titulo,
        "tipo_documental": d.tipo_documental,
        "nombre_archivo": d.nombre_archivo,
        "tipo_mime": d.tipo_mime,
        "tamano_bytes": d.tamano_bytes,
        "hash_sha256": d.hash_sha256,
        "objeto_urn": d.objeto_urn,
        "estado": d.estado,
        "sello": d.sello,
        "fecha_carga": d.fecha_carga.isoformat() if d.fecha_carga else None,
        "fecha_certificacion": d.fecha_certificacion.isoformat() if d.fecha_certificacion else None,
    }
    if interna:
        v.update({"ciudadano_id": d.ciudadano_id, "objeto_id": d.objeto_id})
    return v


# ============================================================ app
def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    cfg = ctx.config
    db = BaseDatos(db_url or cfg.url_bd("documentos"))
    app = crear_app_base(
        "ms-documentos",
        ctx,
        descripcion="Catálogo de documentos, metadatos, cuota y máquina de estados.",
        db=db,
        metadata=Base.metadata,
        gestionar_ciclo=gestionar_ciclo,
    )

    async def documento_propio(s: AsyncSession, documento_id: str, usuario: Usuario) -> Documento:
        d = await s.get(Documento, documento_id)
        # 404 (no 403) para no confirmar que el documento de otro ciudadano existe
        if d is None or d.ciudadano_id != usuario.ciudadano_id:
            raise ErrorDominio(404, "DOCUMENTO_NO_ENCONTRADO")
        return d

    async def cuota(s: AsyncSession, ciudadano_id: str) -> CuotaCiudadano:
        c = await s.get(CuotaCiudadano, ciudadano_id)
        if c is None:
            c = CuotaCiudadano(ciudadano_id=ciudadano_id, documentos_usados=0, bytes_usados=0)
            s.add(c)
        return c

    def vista_cuota(c: CuotaCiudadano) -> dict:
        return {
            "documentos_usados": c.documentos_usados,
            "limite_documentos": cfg.cuota_documentos,
            "bytes_usados": c.bytes_usados,
            "limite_bytes": cfg.cuota_bytes,
        }

    async def url_descarga(d: Documento) -> dict:
        r = await ctx.clientes.llamar(
            "custodia",
            "POST",
            "/internal/urls-temporales",
            json={
                "objeto_id": d.objeto_id,
                "ciudadano_id": d.ciudadano_id,
                "segundos": cfg.expiracion_descarga_segundos,
                "nombre_archivo": d.nombre_archivo,
            },
        )
        if r.status_code != 200:
            raise error_desde_respuesta(r, "ms-custodia")
        return r.json()

    # ---------------------------------------------------------------- públicas
    @app.post("/api/v1/documentos", status_code=201, tags=["documentos"], summary="CU-03 Cargar documento")
    async def cargar(
        archivo: UploadFile = File(...),
        titulo: str = Form(..., min_length=3, max_length=200),
        tipo_documental: TipoDocumental = Form(...),
        usuario: Usuario = Depends(usuario_actual),
        s: AsyncSession = Depends(sesion_bd),
    ):
        nombre = (archivo.filename or "").strip() or "documento"
        extension = nombre.rsplit(".", 1)[-1].lower() if "." in nombre else ""
        if extension not in cfg.extensiones:
            raise ErrorDominio(
                422, "TIPO_NO_PERMITIDO", f"Extensiones permitidas: {', '.join(sorted(cfg.extensiones))}"
            )
        datos = await archivo.read(cfg.tamano_maximo_bytes + 1)
        if not datos:
            raise ErrorDominio(422, "ARCHIVO_VACIO")
        if len(datos) > cfg.tamano_maximo_bytes:
            raise ErrorDominio(
                422, "TAMANO_EXCEDIDO", f"Máximo {cfg.tamano_maximo_bytes // (1024 * 1024) or 1} MB por archivo"
            )
        firmas = FIRMAS_MAGICAS.get(extension)
        if firmas and not datos.startswith(firmas):
            raise ErrorDominio(422, "TIPO_NO_PERMITIDO", f"El contenido no corresponde a un archivo .{extension}")

        c = await cuota(s, usuario.ciudadano_id)
        if c.documentos_usados + 1 > cfg.cuota_documentos or c.bytes_usados + len(datos) > cfg.cuota_bytes:
            raise ErrorDominio(422, "CUOTA_EXCEDIDA", extra={"cuota": vista_cuota(c)})

        mime = MIME.get(extension, "application/octet-stream")
        r = await ctx.clientes.llamar(
            "custodia",
            "POST",
            "/internal/objetos",
            data={"ciudadano_id": usuario.ciudadano_id, "tipo_mime": mime},
            files={"archivo": (nombre, datos, mime)},
        )
        if r.status_code not in (200, 201):
            raise error_desde_respuesta(r, "ms-custodia")
        objeto = r.json()

        d = Documento(
            ciudadano_id=usuario.ciudadano_id,
            titulo=titulo.strip(),
            tipo_documental=tipo_documental.value,
            nombre_archivo=nombre,
            tipo_mime=mime,
            tamano_bytes=objeto["tamano_bytes"],
            hash_sha256=objeto["hash_sha256"],
            objeto_id=objeto["objeto_id"],
            objeto_urn=objeto["urn"],
            estado=EstadoDocumento.TEMPORAL,
        )
        s.add(d)
        c.documentos_usados += 1
        c.bytes_usados += len(datos)
        await s.commit()

        await publicar_seguro(
            ctx.bus,
            crear_evento(
                DOCUMENTO_CARGADO,
                "/ms-documentos",
                {
                    "documento_id": d.id,
                    "ciudadano_id": d.ciudadano_id,
                    "titulo": d.titulo,
                    "tipo_documental": d.tipo_documental,
                    "hash_sha256": d.hash_sha256,
                    "objeto_urn": d.objeto_urn,
                },
                sujeto=d.id,
            ),
        )
        return vista(d)

    @app.get("/api/v1/documentos", tags=["documentos"], summary="Listar mis documentos")
    async def listar(usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        docs = (
            await s.scalars(
                select(Documento).where(Documento.ciudadano_id == usuario.ciudadano_id).order_by(Documento.fecha_carga.desc())
            )
        ).all()
        c = await s.get(CuotaCiudadano, usuario.ciudadano_id) or CuotaCiudadano(documentos_usados=0, bytes_usados=0)
        return {"documentos": [vista(d) for d in docs], "total": len(docs), "cuota": vista_cuota(c)}

    @app.get("/api/v1/documentos/{documento_id}", tags=["documentos"])
    async def obtener(documento_id: str, usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        return vista(await documento_propio(s, documento_id, usuario))

    @app.get("/api/v1/documentos/{documento_id}/descarga", tags=["documentos"], summary="URL prefirmada de descarga")
    async def descarga(documento_id: str, usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        d = await documento_propio(s, documento_id, usuario)
        url = await url_descarga(d)
        return {"url": url["url"], "expira": url["expira"]}

    @app.get("/api/v1/documentos/{documento_id}/contenido", tags=["documentos"], summary="Redirige a la URL prefirmada")
    async def contenido(documento_id: str, usuario: Usuario = Depends(usuario_actual), s: AsyncSession = Depends(sesion_bd)):
        d = await documento_propio(s, documento_id, usuario)
        return RedirectResponse((await url_descarga(d))["url"], status_code=302)

    # ---------------------------------------------------------------- internas
    @app.get("/internal/documentos/{documento_id}", tags=["interno"])
    async def obtener_interno(documento_id: str, s: AsyncSession = Depends(sesion_bd)):
        d = await s.get(Documento, documento_id)
        if d is None:
            raise ErrorDominio(404, "DOCUMENTO_NO_ENCONTRADO")
        return vista(d, interna=True)

    @app.patch("/internal/documentos/{documento_id}/estado", tags=["interno"], summary="Transición de estado")
    async def cambiar_estado(documento_id: str, cambio: CambioEstado, s: AsyncSession = Depends(sesion_bd)):
        d = await s.get(Documento, documento_id)
        if d is None:
            raise ErrorDominio(404, "DOCUMENTO_NO_ENCONTRADO")
        origen = EstadoDocumento(d.estado)
        if cambio.estado not in TRANSICIONES[origen]:
            raise ErrorDominio(409, "ESTADO_INVALIDO", f"No se puede pasar de {origen} a {cambio.estado}")
        valores = {"estado": cambio.estado.value, "fecha_actualizacion": ahora()}
        if cambio.estado == EstadoDocumento.CERTIFICADO:
            valores.update(sello=cambio.sello, fecha_certificacion=cambio.fecha_certificacion or ahora())
        # Actualización condicional: si otra petición cambió el estado primero, esta pierde.
        resultado = await s.execute(
            update(Documento).where(Documento.id == documento_id, Documento.estado == origen.value).values(**valores)
        )
        if resultado.rowcount != 1:
            await s.rollback()
            raise ErrorDominio(409, "ESTADO_INVALIDO", "El documento cambió de estado en paralelo")
        await s.commit()
        await s.refresh(d)
        return vista(d, interna=True)

    @app.get("/internal/estadisticas", tags=["interno"])
    async def estadisticas(s: AsyncSession = Depends(sesion_bd)):
        filas = (await s.execute(select(Documento.estado, func.count()).group_by(Documento.estado))).all()
        return {estado: total for estado, total in filas}

    return app

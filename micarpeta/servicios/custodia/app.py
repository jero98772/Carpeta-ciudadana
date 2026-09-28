"""MS-04 ms-custodia · Custodia del binario de los documentos (CU-03, CU-04).

- Calcula SHA-256, escanea con antivirus y rechaza archivos infectados.
- Deduplica por contenido: el mismo archivo del mismo ciudadano se guarda una vez.
- Cifra con AES-256-GCM antes de escribir en MinIO/S3.
- Emite URLs prefirmadas con HMAC y vencimiento. La descarga se sirve desde
  este servicio (no atraviesa el gateway) y es lo que se envía a GovCarpeta.
"""

import hashlib
import hmac
import time
from datetime import datetime
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import BigInteger, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from micarpeta.comun.app_base import crear_app_base
from micarpeta.comun.contexto import Contexto
from micarpeta.comun.db import BaseDatos, FechaUTC, ahora, nuevo_id, sesion_bd
from micarpeta.comun.errores import ErrorDominio

from .almacen import AlmacenLocal, AlmacenS3, AntivirusClamAV, AntivirusEicar, Cifrador


class Base(DeclarativeBase):
    pass


class ObjetoCustodiado(Base):
    __tablename__ = "objetos_custodiados"
    __table_args__ = (UniqueConstraint("ciudadano_id", "hash_sha256", name="uq_objeto_ciudadano_hash"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    ciudadano_id: Mapped[str] = mapped_column(String(36), index=True)
    bucket: Mapped[str] = mapped_column(String(63))
    clave: Mapped[str] = mapped_column(String(255))
    hash_sha256: Mapped[str] = mapped_column(String(64), index=True)
    tamano_bytes: Mapped[int] = mapped_column(BigInteger)
    tipo_mime: Mapped[str] = mapped_column(String(120))
    estado_antivirus: Mapped[str] = mapped_column(String(20))
    cifrado: Mapped[str] = mapped_column(String(20), default="AES-256-GCM")
    fecha_creacion: Mapped[datetime] = mapped_column(FechaUTC, default=ahora)


class UrlTemporalEntrada(BaseModel):
    objeto_id: str
    ciudadano_id: str
    segundos: int = Field(default=300, ge=10, le=3600)
    nombre_archivo: str | None = None


def vista(o: ObjetoCustodiado, deduplicado: bool = False) -> dict:
    return {
        "objeto_id": o.id,
        "urn": f"urn:micarpeta:custodia:{o.id}",
        "hash_sha256": o.hash_sha256,
        "tamano_bytes": o.tamano_bytes,
        "tipo_mime": o.tipo_mime,
        "estado_antivirus": o.estado_antivirus,
        "cifrado": o.cifrado,
        "deduplicado": deduplicado,
    }


def crear_app(ctx: Contexto, db_url: str | None = None, gestionar_ciclo: bool = False) -> FastAPI:
    cfg = ctx.config
    db = BaseDatos(db_url or cfg.url_bd("custodia"))
    if cfg.almacenamiento == "s3":
        almacen = AlmacenS3(cfg.s3_endpoint, cfg.s3_access_key, cfg.s3_secret_key, cfg.s3_bucket, cfg.s3_seguro)
    else:
        almacen = AlmacenLocal(cfg.ruta_almacenamiento, cfg.s3_bucket)
    antivirus = AntivirusClamAV(cfg.clamav_host, cfg.clamav_puerto) if cfg.antivirus == "clamav" else AntivirusEicar()
    cifrador = Cifrador(cfg.clave_cifrado_custodia, cfg.secreto_urls)

    async def al_iniciar(app: FastAPI) -> None:
        await almacen.iniciar()

    app = crear_app_base(
        "ms-custodia",
        ctx,
        descripcion="Hash, antivirus, cifrado AES-256-GCM, deduplicación y URLs prefirmadas.",
        db=db,
        metadata=Base.metadata,
        al_iniciar=al_iniciar,
        gestionar_ciclo=gestionar_ciclo,
    )
    app.state.almacen = almacen

    def firmar(objeto_id: str, expira: int) -> str:
        return hmac.new(cfg.secreto_urls.encode(), f"{objeto_id}:{expira}".encode(), hashlib.sha256).hexdigest()

    @app.post("/internal/objetos", tags=["interno"], summary="Custodiar un binario")
    async def custodiar(
        ciudadano_id: str = Form(...),
        tipo_mime: str = Form("application/octet-stream"),
        archivo: UploadFile = File(...),
        s: AsyncSession = Depends(sesion_bd),
    ):
        datos = await archivo.read()
        if not datos:
            raise ErrorDominio(422, "ARCHIVO_VACIO")
        huella = hashlib.sha256(datos).hexdigest()

        limpio, resultado = await antivirus.escanear(datos)
        if not limpio:
            raise ErrorDominio(422, "ARCHIVO_INFECTADO", f"Firma detectada: {resultado}")

        existente = await s.scalar(
            select(ObjetoCustodiado).where(
                ObjetoCustodiado.ciudadano_id == ciudadano_id, ObjetoCustodiado.hash_sha256 == huella
            )
        )
        if existente:
            return vista(existente, deduplicado=True)

        clave = f"{ciudadano_id}/{huella}"
        await almacen.guardar(clave, cifrador.cifrar(datos, clave), tipo_mime)
        objeto = ObjetoCustodiado(
            ciudadano_id=ciudadano_id,
            bucket=cfg.s3_bucket,
            clave=clave,
            hash_sha256=huella,
            tamano_bytes=len(datos),
            tipo_mime=tipo_mime,
            estado_antivirus="LIMPIO",
        )
        s.add(objeto)
        try:
            await s.commit()
        except IntegrityError:  # carga simultánea del mismo archivo: gana la primera
            await s.rollback()
            existente = await s.scalar(
                select(ObjetoCustodiado).where(
                    ObjetoCustodiado.ciudadano_id == ciudadano_id, ObjetoCustodiado.hash_sha256 == huella
                )
            )
            return vista(existente, deduplicado=True)
        return vista(objeto)

    @app.get("/internal/objetos/{objeto_id}", tags=["interno"])
    async def obtener(objeto_id: str, s: AsyncSession = Depends(sesion_bd)):
        objeto = await s.get(ObjetoCustodiado, objeto_id)
        if objeto is None:
            raise ErrorDominio(404, "OBJETO_NO_ENCONTRADO")
        return vista(objeto)

    @app.post("/internal/urls-temporales", tags=["interno"], summary="Generar URL prefirmada (HMAC)")
    async def url_temporal(datos: UrlTemporalEntrada, s: AsyncSession = Depends(sesion_bd)):
        objeto = await s.get(ObjetoCustodiado, datos.objeto_id)
        if objeto is None or objeto.ciudadano_id != datos.ciudadano_id:
            raise ErrorDominio(404, "OBJETO_NO_ENCONTRADO")
        expira = int(time.time()) + datos.segundos
        url = (
            f"{cfg.url_publica_custodia.rstrip('/')}/descargas/{objeto.id}"
            f"?expira={expira}&firma={firmar(objeto.id, expira)}"
        )
        if datos.nombre_archivo:
            url += f"&nombre={quote(datos.nombre_archivo)}"
        return {"url": url, "expira": expira}

    @app.get("/descargas/{objeto_id}", tags=["descargas"], summary="Descarga con URL prefirmada")
    async def descargar(
        objeto_id: str,
        expira: int = Query(...),
        firma: str = Query(...),
        nombre: str | None = Query(None),
        s: AsyncSession = Depends(sesion_bd),
    ):
        if not hmac.compare_digest(firma.encode(), firmar(objeto_id, expira).encode()):
            raise ErrorDominio(401, "FIRMA_INVALIDA")
        if expira < int(time.time()):
            raise ErrorDominio(401, "URL_EXPIRADA")
        objeto = await s.get(ObjetoCustodiado, objeto_id)
        if objeto is None:
            raise ErrorDominio(404, "OBJETO_NO_ENCONTRADO")
        contenido = cifrador.descifrar(await almacen.leer(objeto.clave), objeto.clave)
        nombre_archivo = (nombre or f"documento-{objeto.id[:8]}").replace('"', "")
        return Response(
            content=contenido,
            media_type=objeto.tipo_mime,
            headers={
                "Content-Disposition": f"inline; filename*=UTF-8''{quote(nombre_archivo)}",
                "Cache-Control": "private, no-store",
                "X-Content-SHA256": objeto.hash_sha256,
            },
        )

    return app

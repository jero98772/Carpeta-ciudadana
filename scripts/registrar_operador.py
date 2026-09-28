"""Registra el operador en GovCarpeta (una sola vez por equipo) y muestra su operatorId.

    python scripts/registrar_operador.py \\
        --direccion "https://micarpeta.tu-dominio.co" \\
        --correo "equipo@correo.com" \\
        --participantes "Danna Gabriela Salazar Cárdenas" "Danielo Arango Sohm"

Notas sobre el contrato real (verificado por otros equipos):
- El Swagger exige "nameOperator"/"adress" pero guarda "name"/"address": se envían ambos.
- La respuesta no siempre trae el id de forma legible, así que se busca en getOperators.
- El nombre debe ser único: si ya existe, se muestra su id y no se registra otra vez.
"""

import argparse
import sys

import httpx

URL = "https://govcarpeta-apis-4905ff3c005b.herokuapp.com"


def buscar(cliente: httpx.Client, nombre: str) -> list[dict]:
    r = cliente.get("/apis/getOperators")
    r.raise_for_status()
    return [o for o in r.json() if (o.get("operatorName") or "").strip().lower() == nombre.strip().lower()]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=URL, help="URL base de GovCarpeta")
    p.add_argument("--nombre", default="MiCarpeta CO")
    p.add_argument("--direccion", required=True, help="Dirección o URL pública del operador")
    p.add_argument("--correo", required=True, help="Correo de contacto")
    p.add_argument("--participantes", nargs="+", required=True, help="Integrantes del equipo")
    p.add_argument("--endpoint-transferencia", help="URL pública para recibir traslados (opcional)")
    p.add_argument("--si", action="store_true", help="No pedir confirmación")
    a = p.parse_args()

    with httpx.Client(base_url=a.url, timeout=30) as c:
        existentes = buscar(c, a.nombre)
        if existentes:
            print(f"Ya existe un operador llamado «{a.nombre}» en GovCarpeta:")
            for o in existentes:
                print(f"  _id={o['_id']}  participantes={o.get('participants')}")
            print("\nSi es el de tu equipo, usa ese id. Si no, elige otro --nombre y vuelve a ejecutar.")
            print(f"GOVCARPETA_OPERATOR_ID={existentes[0]['_id']}")
            return

        print(f"Se registrará «{a.nombre}» en {a.url}. Esta operación no se puede deshacer desde la API.")
        if not a.si and input("¿Continuar? [s/N] ").strip().lower() != "s":
            sys.exit("Cancelado.")

        r = c.post(
            "/apis/registerOperator",
            json={
                "name": a.nombre,
                "nameOperator": a.nombre,
                "address": a.direccion,
                "adress": a.direccion,
                "contactMail": a.correo,
                "participants": a.participantes,
            },
        )
        print(f"registerOperator -> {r.status_code}: {r.text.strip()[:200]}")

        registrados = buscar(c, a.nombre)
        if not registrados:
            sys.exit("No se encontró el operador en getOperators. Revisa la respuesta anterior.")
        operador_id = registrados[0]["_id"]

        if a.endpoint_transferencia:
            r = c.put(
                "/apis/registerTransferEndPoint",
                json={"idOperator": operador_id, "endPoint": a.endpoint_transferencia, "endPointConfirm": a.endpoint_transferencia},
            )
            print(f"registerTransferEndPoint -> {r.status_code}: {r.text.strip()[:200]}")

    print("\nListo. Agrega esto a tu .env:")
    print(f"GOVCARPETA_URL={a.url}")
    print(f"GOVCARPETA_OPERATOR_ID={operador_id}")


if __name__ == "__main__":
    main()

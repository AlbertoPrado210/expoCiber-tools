"""Consulta educativa de brechas HIBP con cuentas oficiales de prueba."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import UTC, datetime
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import quote

import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIRECTORY = PROJECT_ROOT / "datos-sinteticos" / "hibp"
API_BASE = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "expoCiber-educational-demo/1.0"
TEST_DOMAIN = "hibp-integration-tests.com"
TEST_API_KEY = "0" * 32

SAMPLES = {
    "multiple": "multiple-breaches@hibp-integration-tests.com",
    "single": "account-exists@hibp-integration-tests.com",
    "none": "not-active-breach@hibp-integration-tests.com",
    "unverified": "unverified-breach@hibp-integration-tests.com",
}

DATA_CLASS_TRANSLATIONS = {
    "Credit cards": "Tarjetas",
    "Email addresses": "Correos",
    "Names": "Nombres",
    "Password hints": "Pistas de contraseña",
    "Passwords": "Contraseñas",
    "Phone numbers": "Teléfonos",
    "Physical addresses": "Direcciones",
    "Usernames": "Nombres de usuario",
}


class DemoError(RuntimeError):
    """Error controlado que puede activar un respaldo seguro."""


def validate_email(value: str) -> str:
    candidate = value.strip().lower()
    _, parsed = parseaddr(candidate)
    if parsed != candidate or candidate.count("@") != 1:
        raise DemoError("el correo no tiene un formato válido")
    local, domain = candidate.rsplit("@", 1)
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise DemoError("el correo no tiene un formato válido")
    return candidate


def is_test_account(email: str) -> bool:
    return email.endswith(f"@{TEST_DOMAIN}")


def mask_email(email: str) -> str:
    local, domain = email.rsplit("@", 1)
    visible = local[:2]
    hidden = "*" * max(3, len(local) - len(visible))
    return f"{visible}{hidden}@{domain}"


def request_api_key(allow_prompt: bool) -> str:
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if api_key or not allow_prompt or not sys.stdin.isatty():
        return api_key

    print("\nSe necesita una API key personal de Have I Been Pwned.")
    print("Puedes pegarla ahora: no se mostrará ni se guardará.")
    try:
        return getpass.getpass("API key: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nIngreso cancelado.")
        return ""


def confirm_authorization(email: str, already_confirmed: bool) -> bool:
    if is_test_account(email) or already_confirmed:
        return True
    if not sys.stdin.isatty():
        return False

    print("\nPrivacidad: una consulta directa envía el correo completo a HIBP.")
    print("Consulta solamente una cuenta propia o con autorización expresa.")
    answer = input("Escribe SI para confirmar: ").strip().upper()
    return answer == "SI"


def create_session(api_key: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "hibp-api-key": api_key,
        }
    )
    return session


def describe_http_error(response: requests.Response) -> DemoError:
    messages = {
        400: "la solicitud no tiene un formato aceptado",
        401: "la API key no fue aceptada",
        403: "falta el identificador de la aplicación o el acceso requerido",
        429: f"se alcanzó el límite; espera {response.headers.get('retry-after', '?')} segundos",
        503: "HIBP no está disponible temporalmente",
    }
    return DemoError(messages.get(response.status_code, f"respuesta HTTP {response.status_code}"))


def get_breach_names(session: requests.Session, email: str) -> list[str]:
    endpoint = f"{API_BASE}/breachedaccount/{quote(email, safe='')}"
    try:
        response = session.get(
            endpoint,
            params={"truncateResponse": "true", "includeUnverified": "true"},
            timeout=15,
        )
    except requests.RequestException as error:
        raise DemoError("no fue posible conectar con HIBP") from error

    if response.status_code == 404:
        return []
    if response.status_code >= 400:
        raise describe_http_error(response)

    try:
        return [item["Name"] for item in response.json()]
    except (KeyError, TypeError, ValueError) as error:
        raise DemoError("la respuesta de cuentas no tiene el formato esperado") from error


def get_breach_metadata(session: requests.Session, breach_name: str) -> dict:
    try:
        response = session.get(f"{API_BASE}/breach/{quote(breach_name)}", timeout=15)
    except requests.RequestException as error:
        raise DemoError("no fue posible obtener el detalle de una brecha") from error
    if response.status_code >= 400:
        raise describe_http_error(response)
    try:
        return response.json()
    except ValueError as error:
        raise DemoError("el detalle de la brecha no tiene el formato esperado") from error


def sanitize_breach(metadata: dict) -> dict:
    return {
        "name": metadata.get("Name"),
        "title": metadata.get("Title") or metadata.get("Name"),
        "domain": metadata.get("Domain"),
        "breach_date": metadata.get("BreachDate"),
        "pwn_count": metadata.get("PwnCount", 0),
        "data_classes": metadata.get("DataClasses", []),
        "is_verified": metadata.get("IsVerified"),
        "is_unverified": metadata.get("IsUnverified"),
        "is_spam_list": metadata.get("IsSpamList"),
    }


def build_report(session: requests.Session, email: str) -> dict:
    names = get_breach_names(session, email)
    breaches = [sanitize_breach(get_breach_metadata(session, name)) for name in names]
    return {
        "schema_version": 1,
        "account": email if is_test_account(email) else mask_email(email),
        "is_official_test_account": is_test_account(email),
        "breach_count": len(breaches),
        "breaches": breaches,
        "backup_created_at": datetime.now(UTC).isoformat(),
    }


def backup_path(sample_name: str) -> Path:
    return BACKUP_DIRECTORY / f"{sample_name}.json"


def save_backup(sample_name: str, report: dict) -> Path:
    BACKUP_DIRECTORY.mkdir(parents=True, exist_ok=True)
    destination = backup_path(sample_name)
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination


def load_backup(sample_name: str) -> dict:
    source = backup_path(sample_name)
    if not source.is_file():
        raise DemoError("todavía no existe un respaldo para este caso oficial")
    return json.loads(source.read_text(encoding="utf-8"))


def compact_number(value: int) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f} mil M"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f} M"
    if value >= 1_000:
        return f"{value / 1_000:.1f} mil"
    return str(value)


def translate_data_class(value: str) -> str:
    return DATA_CLASS_TRANSLATIONS.get(value, value)


def print_report(report: dict, origin: str) -> None:
    print("\nHAVE I BEEN PWNED · EXPOSICIÓN DE CUENTAS")
    print("═" * 66)
    print(f"Cuenta          : {report['account']}")
    print(f"Resultado       : {origin}")
    print(f"Brechas halladas: {report['breach_count']}")

    for index, breach in enumerate(report.get("breaches", []), start=1):
        print("─" * 66)
        print(f"{index}. {breach['title']} · {breach.get('breach_date') or 'fecha no disponible'}")
        print(f"   Cuentas afectadas: {compact_number(breach.get('pwn_count', 0))}")
        data = (
            ", ".join(
                translate_data_class(item) for item in breach.get("data_classes", [])[:5]
            )
            or "No informado"
        )
        print(f"   Datos expuestos  : {data}")
        print(f"   Verificada       : {'Sí' if breach.get('is_verified') else 'No'}")

    if not report.get("breaches"):
        print("─" * 66)
        print("No se encontraron brechas públicas para esta cuenta de prueba.")

    print("═" * 66)
    print("Estar en una brecha no demuestra que la contraseña actual sea conocida.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Consulta educativa de cuentas en Have I Been Pwned."
    )
    parser.add_argument(
        "--sample",
        choices=sorted(SAMPLES),
        default="multiple",
        help="Cuenta oficial de prueba (predeterminado: multiple).",
    )
    parser.add_argument("--email", help="Cuenta propia o expresamente autorizada.")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirma autorización para consultar el correo proporcionado.",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "live", "offline"),
        default="auto",
    )
    parser.add_argument("--no-prompt", action="store_true")
    args = parser.parse_args()

    try:
        email = validate_email(args.email or SAMPLES[args.sample])
    except DemoError as error:
        print(f"Entrada rechazada: {error}.", file=sys.stderr)
        return 2

    custom_account = not is_test_account(email)
    if custom_account and args.mode == "offline":
        print("El modo offline solo admite las cuentas oficiales de prueba.", file=sys.stderr)
        return 2
    if not confirm_authorization(email, args.authorized):
        print("Consulta cancelada: no se confirmó la autorización.", file=sys.stderr)
        return 2

    if args.mode == "offline":
        try:
            print_report(load_backup(args.sample), "respaldo local")
            return 0
        except DemoError as error:
            print(f"No se puede iniciar el modo offline: {error}.", file=sys.stderr)
            return 1

    api_key = TEST_API_KEY if not custom_account else request_api_key(not args.no_prompt)
    if not api_key:
        if args.mode == "live":
            print("No se proporcionó una API key de HIBP.", file=sys.stderr)
            return 2
        try:
            print_report(load_backup(args.sample), "respaldo local")
            return 0
        except DemoError as error:
            print(f"No hay un resultado disponible: {error}.", file=sys.stderr)
            return 1

    try:
        with create_session(api_key) as session:
            report = build_report(session, email)
        api_key = ""
        if not custom_account:
            save_backup(args.sample, report)
        print_report(report, "consulta en vivo")
        if custom_account:
            print("La cuenta fue enmascarada y no se guardó ningún respaldo.")
            print("Recuerda limpiar la API key y el correo del portapapeles.")
        return 0
    except DemoError as error:
        api_key = ""
        if args.mode == "live" or custom_account:
            print(f"La consulta en vivo falló: {error}.", file=sys.stderr)
            return 1
        print(f"Aviso: {error}; se utilizará el respaldo local.")
        try:
            print_report(load_backup(args.sample), "respaldo local")
            return 0
        except DemoError as backup_error:
            print(f"No hay un resultado disponible: {backup_error}.", file=sys.stderr)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())

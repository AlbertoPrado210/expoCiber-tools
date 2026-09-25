"""Consulta pasiva de reputación IP con respaldo local sanitizado."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIRECTORY = PROJECT_ROOT / "datos-sinteticos" / "abuseipdb"
API_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

SAMPLES = {
    "cloudflare": {
        "ip": "1.1.1.1",
        "context": "DNS público de Cloudflare; ejemplo para explicar reportes con baja confianza.",
        "source": "https://www.abuseipdb.com/check/1.1.1.1",
    },
    "reportada": {
        "ip": "45.154.98.44",
        "context": "IP pública con numerosos reportes recientes en AbuseIPDB.",
        "source": "https://www.abuseipdb.com/check/45.154.98.44",
    },
}


class DemoError(RuntimeError):
    """Error controlado que puede activar el respaldo local."""


def validate_public_ip(value: str) -> str:
    try:
        parsed = ip_address(value.strip())
    except ValueError as error:
        raise DemoError("la dirección IP no tiene un formato válido") from error
    if not parsed.is_global:
        raise DemoError("la demostración solo consulta direcciones IP públicas globales")
    return parsed.compressed


def request_api_key(allow_prompt: bool) -> str:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if api_key or not allow_prompt or not sys.stdin.isatty():
        return api_key

    print("\nSe necesita una API key personal de AbuseIPDB.")
    print("Puedes pegarla ahora: no se mostrará ni se guardará.")
    try:
        return getpass.getpass("API key: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nIngreso cancelado.")
        return ""


def get_report(ip: str, api_key: str, max_age_days: int) -> dict:
    try:
        response = requests.get(
            API_ENDPOINT,
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=15,
        )
    except requests.RequestException as error:
        raise DemoError("no fue posible conectar con AbuseIPDB") from error

    if response.status_code == 429:
        raise DemoError("se alcanzó temporalmente el límite de consultas")
    if response.status_code in {401, 403}:
        raise DemoError("la clave no fue aceptada o no tiene acceso")
    if response.status_code >= 400:
        try:
            detail = response.json()["errors"][0]["detail"]
        except (KeyError, IndexError, TypeError, ValueError):
            detail = f"respuesta HTTP {response.status_code}"
        raise DemoError(detail)

    try:
        return response.json()["data"]
    except (KeyError, TypeError, ValueError) as error:
        raise DemoError("la respuesta no tiene el formato esperado") from error


def sanitize_report(ip: str, context: str, report: dict, max_age_days: int) -> dict:
    return {
        "schema_version": 1,
        "ip_address": ip,
        "context": context,
        "query_window_days": max_age_days,
        "is_public": report.get("isPublic"),
        "ip_version": report.get("ipVersion"),
        "is_whitelisted": report.get("isWhitelisted"),
        "abuse_confidence_score": report.get("abuseConfidenceScore", 0),
        "country_code": report.get("countryCode"),
        "usage_type": report.get("usageType"),
        "isp": report.get("isp"),
        "domain": report.get("domain"),
        "total_reports": report.get("totalReports", 0),
        "distinct_reporters": report.get("numDistinctUsers", 0),
        "last_reported_at": report.get("lastReportedAt"),
        "backup_created_at": datetime.now(UTC).isoformat(),
    }


def backup_path(ip: str) -> Path:
    safe_name = ip.replace(".", "-").replace(":", "_")
    return BACKUP_DIRECTORY / f"{safe_name}.json"


def save_backup(report: dict) -> Path:
    BACKUP_DIRECTORY.mkdir(parents=True, exist_ok=True)
    destination = backup_path(report["ip_address"])
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination


def load_backup(ip: str) -> dict:
    source = backup_path(ip)
    if not source.is_file():
        raise DemoError(
            "todavía no existe un respaldo; ejecuta una consulta en vivo durante el ensayo"
        )
    return json.loads(source.read_text(encoding="utf-8"))


def yes_no_unknown(value: bool | None) -> str:
    if value is True:
        return "Sí"
    if value is False:
        return "No"
    return "No informado"


def print_report(report: dict, origin: str) -> None:
    print("\nABUSEIPDB · REPUTACIÓN DE IP")
    print("═" * 62)
    print(f"IP              : {report['ip_address']}")
    print(f"Contexto        : {report['context']}")
    print(f"Resultado       : {origin}")
    print("─" * 62)
    print(f"Confianza abuso : {report.get('abuse_confidence_score', 0):>3}%")
    print(f"Reportes        : {report.get('total_reports', 0):>3}")
    print(f"Fuentes únicas  : {report.get('distinct_reporters', 0):>3}")
    print(f"Lista blanca    : {yes_no_unknown(report.get('is_whitelisted'))}")
    print(f"Último reporte  : {report.get('last_reported_at') or 'No disponible'}")
    print("─" * 62)
    print(f"Proveedor       : {report.get('isp') or 'No informado'}")
    print(f"Tipo de uso     : {report.get('usage_type') or 'No informado'}")
    print(f"País            : {report.get('country_code') or 'No informado'}")
    print("═" * 62)
    print("Consulta pasiva: no se realizó conexión alguna hacia la IP analizada.")


def resolve_target(sample_name: str, custom_ip: str | None) -> tuple[str, str, str | None]:
    if custom_ip:
        return validate_public_ip(custom_ip), "IP proporcionada por el usuario.", None
    sample = SAMPLES[sample_name]
    return validate_public_ip(sample["ip"]), sample["context"], sample["source"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Consulta pasiva de reputación IP con respaldo automático."
    )
    parser.add_argument(
        "--sample",
        choices=sorted(SAMPLES),
        default="reportada",
        help="Caso preparado para la exposición (predeterminado: reportada).",
    )
    parser.add_argument("--ip", help="Dirección IPv4 o IPv6 pública para consultar.")
    parser.add_argument(
        "--mode",
        choices=("auto", "live", "offline"),
        default="auto",
        help="auto intenta la API y usa respaldo si falla; live exige API; offline no usa red.",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        choices=range(1, 366),
        default=90,
        metavar="1-365",
        help="Ventana de reportes consultada (predeterminado: 90 días).",
    )
    parser.add_argument("--show-source", action="store_true")
    parser.add_argument("--no-prompt", action="store_true")
    args = parser.parse_args()

    try:
        ip, context, source = resolve_target(args.sample, args.ip)
    except DemoError as error:
        print(f"Entrada rechazada: {error}.", file=sys.stderr)
        return 2

    if args.show_source and source:
        print(f"Fuente: {source}")

    if args.mode == "offline":
        try:
            print_report(load_backup(ip), "respaldo local")
            return 0
        except DemoError as error:
            print(f"No se puede iniciar el modo offline: {error}.", file=sys.stderr)
            return 1

    api_key = request_api_key(not args.no_prompt)
    if api_key:
        try:
            raw_report = get_report(ip, api_key, args.max_age_days)
            api_key = ""
            report = sanitize_report(ip, context, raw_report, args.max_age_days)
            save_backup(report)
            print_report(report, "consulta en vivo")
            print("Recuerda limpiar la API key del portapapeles.")
            return 0
        except DemoError as error:
            api_key = ""
            if args.mode == "live":
                print(f"La consulta en vivo falló: {error}.", file=sys.stderr)
                return 1
            print(f"Aviso: {error}; se utilizará el respaldo local.")
    elif args.mode == "live":
        print("No se proporcionó una API key de AbuseIPDB.", file=sys.stderr)
        return 2
    else:
        print("Aviso: no se proporcionó una API key; se utilizará el respaldo local.")

    try:
        print_report(load_backup(ip), "respaldo local")
        return 0
    except DemoError as error:
        print(f"No hay un resultado disponible: {error}.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

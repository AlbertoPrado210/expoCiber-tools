"""Consulta reportes existentes de VirusTotal con respaldo local sanitizado."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIRECTORY = PROJECT_ROOT / "datos-sinteticos" / "virustotal"

SAMPLES = {
    "asyncrat": {
        "label": "hxxps://envs[.]sh/Yi-.exe",
        "url_id": "aHR0cHM6Ly9lbnZzLnNoL1lpLS5leGU",
        "source": "https://urlhaus.abuse.ch/host/envs.sh/",
        "context": "URL histórica fuera de línea; URLhaus la asocia con AsyncRAT.",
    },
    "mirai": {
        "label": "hxxp://5[.]255[.]121[.]141/nuts/x86",
        "url_id": "aHR0cDovLzUuMjU1LjEyMS4xNDEvbnV0cy94ODY",
        "source": "https://urlhaus.abuse.ch/host/5.255.121.141/",
        "context": "URL histórica fuera de línea; URLhaus la asocia con Mirai/Mozi.",
    },
}


class DemoError(RuntimeError):
    """Error controlado que puede activar el respaldo local."""


def get_report(url_id: str, api_key: str) -> dict:
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        messages = {
            401: "la clave no fue aceptada",
            403: "la clave no tiene acceso",
            404: "el reporte ya no está disponible",
            429: "se alcanzó temporalmente el límite de consultas",
        }
        raise DemoError(messages.get(error.code, f"respuesta HTTP {error.code}")) from error
    except (TimeoutError, urllib.error.URLError) as error:
        raise DemoError("no fue posible conectar con VirusTotal") from error


def sanitize_report(sample_name: str, report: dict) -> dict:
    sample = SAMPLES[sample_name]
    attributes = report["data"]["attributes"]
    analysis_results = attributes.get("last_analysis_results", {})
    detections = [
        {
            "engine": engine,
            "category": result.get("category", "unknown"),
            "result": result.get("result") or "sin nombre",
        }
        for engine, result in analysis_results.items()
        if result.get("category") in {"malicious", "suspicious"}
    ]

    return {
        "schema_version": 1,
        "sample": sample_name,
        "indicator": sample["label"],
        "context": sample["context"],
        "source": sample["source"],
        "virustotal_object_id": report["data"].get("id", sample["url_id"]),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "stats": attributes.get("last_analysis_stats", {}),
        "detections": detections[:8],
        "backup_created_at": datetime.now(UTC).isoformat(),
    }


def backup_path(sample_name: str) -> Path:
    return BACKUP_DIRECTORY / f"{sample_name}.json"


def save_backup(sample_name: str, sanitized: dict) -> Path:
    BACKUP_DIRECTORY.mkdir(parents=True, exist_ok=True)
    destination = backup_path(sample_name)
    destination.write_text(
        json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination


def load_backup(sample_name: str) -> dict:
    source = backup_path(sample_name)
    if not source.is_file():
        raise DemoError(
            "todavía no existe un respaldo; ejecuta una consulta en vivo durante el ensayo"
        )
    return json.loads(source.read_text(encoding="utf-8"))


def format_timestamp(timestamp: int | None) -> str:
    if not timestamp:
        return "No disponible"
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def print_report(report: dict, origin: str) -> None:
    stats = report.get("stats", {})
    detections = report.get("detections", [])

    print("\nVIRUSTOTAL · REPORTE EXISTENTE")
    print("═" * 58)
    print(f"Indicador  : {report['indicator']}")
    print(f"Contexto   : {report['context']}")
    print(f"Resultado  : {origin}")
    print(f"Analizado  : {format_timestamp(report.get('last_analysis_date'))}")
    print("─" * 58)
    print(f"Malicioso  : {stats.get('malicious', 0):>3}")
    print(f"Sospechoso : {stats.get('suspicious', 0):>3}")
    print(f"Inofensivo : {stats.get('harmless', 0):>3}")
    print(f"Sin vered. : {stats.get('undetected', 0):>3}")

    if detections:
        print("─" * 58)
        print("Algunas detecciones:")
        for detection in detections[:5]:
            print(f"  • {detection['engine']}: {detection['result']}")

    print("═" * 58)
    print("Consulta pasiva: el enlace no fue visitado ni reenviado.")


def request_api_key(allow_prompt: bool) -> str:
    api_key = os.getenv("VT_API_KEY", "").strip()
    if api_key or not allow_prompt or not sys.stdin.isatty():
        return api_key

    print("\nSe necesita una API key personal de VirusTotal.")
    print("Puedes pegarla ahora: no se mostrará ni se guardará.")
    try:
        return getpass.getpass("API key: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nIngreso cancelado.")
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Consulta pasiva de VirusTotal con respaldo automático."
    )
    parser.add_argument(
        "--sample",
        choices=sorted(SAMPLES),
        default="asyncrat",
        help="Caso histórico que se mostrará (predeterminado: asyncrat).",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "live", "offline"),
        default="auto",
        help="auto intenta la API y usa respaldo si falla; live exige API; offline no usa red.",
    )
    parser.add_argument(
        "--show-source",
        action="store_true",
        help="Muestra la página pública de referencia en URLhaus.",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="No solicita una clave interactivamente si VT_API_KEY no existe.",
    )
    args = parser.parse_args()

    sample = SAMPLES[args.sample]
    if args.show_source:
        print(f"Fuente: {sample['source']}")

    if args.mode == "offline":
        try:
            print_report(load_backup(args.sample), "respaldo local")
            return 0
        except DemoError as error:
            print(f"No se puede iniciar el modo offline: {error}.", file=sys.stderr)
            return 1

    api_key = request_api_key(not args.no_prompt)
    if api_key:
        try:
            sanitized = sanitize_report(args.sample, get_report(sample["url_id"], api_key))
            api_key = ""
            save_backup(args.sample, sanitized)
            print_report(sanitized, "consulta en vivo")
            print("Recuerda limpiar la API key del portapapeles.")
            return 0
        except (DemoError, KeyError, TypeError, ValueError) as error:
            api_key = ""
            if args.mode == "live":
                print(f"La consulta en vivo falló: {error}.", file=sys.stderr)
                return 1
            print(f"Aviso: {error}; se utilizará el respaldo local.")
    elif args.mode == "live":
        print(
            "No se proporcionó una API key. Puedes configurar VT_API_KEY "
            "o ejecutar el programa en una terminal interactiva.",
            file=sys.stderr,
        )
        return 2
    else:
        print("Aviso: VT_API_KEY no está configurada; se utilizará el respaldo local.")

    try:
        print_report(load_backup(args.sample), "respaldo local")
        return 0
    except DemoError as error:
        print(f"No hay un resultado disponible: {error}.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Consola integrada para las demostraciones defensivas de expoCiber."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Any

import consultar_abuseipdb as abuse
import consultar_hibp as hibp
import consultar_virustotal as vt
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


console = Console(highlight=False)


class ModuleUnavailable(RuntimeError):
    """La consulta no pudo ejecutarse ni recuperarse desde un respaldo."""


@dataclass(frozen=True)
class Result:
    data: dict[str, Any]
    origin: str


def obtain_virustotal(
    sample_name: str = "asyncrat", mode: str = "auto", allow_prompt: bool = True
) -> Result:
    if mode == "offline":
        try:
            return Result(vt.load_backup(sample_name), "respaldo local")
        except vt.DemoError as error:
            raise ModuleUnavailable(str(error)) from error

    api_key = vt.request_api_key(allow_prompt)
    if api_key:
        try:
            raw = vt.get_report(vt.SAMPLES[sample_name]["url_id"], api_key)
            api_key = ""
            report = vt.sanitize_report(sample_name, raw)
            vt.save_backup(sample_name, report)
            return Result(report, "consulta en vivo")
        except (vt.DemoError, KeyError, TypeError, ValueError) as error:
            api_key = ""
            if mode == "live":
                raise ModuleUnavailable(str(error)) from error
            warning(f"VirusTotal no respondió: {error}. Se intentará el respaldo.")
    elif mode == "live":
        raise ModuleUnavailable("no se proporcionó una API key de VirusTotal")

    try:
        return Result(vt.load_backup(sample_name), "respaldo local")
    except vt.DemoError as error:
        raise ModuleUnavailable(str(error)) from error


def obtain_abuseipdb(
    sample_name: str = "reportada", mode: str = "auto", allow_prompt: bool = True
) -> Result:
    sample = abuse.SAMPLES[sample_name]
    ip = abuse.validate_public_ip(sample["ip"])
    if mode == "offline":
        try:
            return Result(abuse.load_backup(ip), "respaldo local")
        except abuse.DemoError as error:
            raise ModuleUnavailable(str(error)) from error

    api_key = abuse.request_api_key(allow_prompt)
    if api_key:
        try:
            raw = abuse.get_report(ip, api_key, 90)
            api_key = ""
            report = abuse.sanitize_report(ip, sample["context"], raw, 90)
            abuse.save_backup(report)
            return Result(report, "consulta en vivo")
        except abuse.DemoError as error:
            api_key = ""
            if mode == "live":
                raise ModuleUnavailable(str(error)) from error
            warning(f"AbuseIPDB no respondió: {error}. Se intentará el respaldo.")
    elif mode == "live":
        raise ModuleUnavailable("no se proporcionó una API key de AbuseIPDB")

    try:
        return Result(abuse.load_backup(ip), "respaldo local")
    except abuse.DemoError as error:
        raise ModuleUnavailable(str(error)) from error


def obtain_hibp(sample_name: str = "multiple", mode: str = "auto") -> Result:
    if mode == "offline":
        try:
            return Result(hibp.load_backup(sample_name), "respaldo local")
        except hibp.DemoError as error:
            raise ModuleUnavailable(str(error)) from error

    email = hibp.SAMPLES[sample_name]
    try:
        with hibp.create_session(hibp.TEST_API_KEY) as session:
            report = hibp.build_report(session, email)
        hibp.save_backup(sample_name, report)
        return Result(report, "consulta en vivo")
    except hibp.DemoError as error:
        if mode == "live":
            raise ModuleUnavailable(str(error)) from error
        warning(f"HIBP no respondió: {error}. Se intentará el respaldo.")
        try:
            return Result(hibp.load_backup(sample_name), "respaldo local")
        except hibp.DemoError as backup_error:
            raise ModuleUnavailable(str(backup_error)) from backup_error


def header() -> None:
    title = Text("expoCiber", style="bold bright_cyan")
    title.append("  ·  ", style="dim")
    title.append("La confianza también se verifica", style="bold #ffbd2e")
    console.print(Panel.fit(title, border_style="bright_blue", padding=(1, 3)))


def warning(message: str) -> None:
    console.print(Panel(message, title="Aviso", border_style="yellow"))


def show_error(module_name: str, error: Exception) -> None:
    console.print(
        Panel(
            f"{error}\n\nLa exposición puede continuar con la lámina de respaldo.",
            title=f"{module_name} no disponible",
            border_style="red",
        )
    )


def show_virustotal(result: Result) -> None:
    report = result.data
    stats = report.get("stats", {})
    table = Table(box=box.ROUNDED, border_style="bright_blue", expand=True)
    table.add_column("Señal", style="bold")
    table.add_column("Motores", justify="right")
    table.add_row("Malicioso", str(stats.get("malicious", 0)), style="red")
    table.add_row("Sospechoso", str(stats.get("suspicious", 0)), style="yellow")
    table.add_row("Sin detección", str(stats.get("undetected", 0)), style="dim")
    table.add_row("Inofensivo", str(stats.get("harmless", 0)), style="green")

    console.print(
        Panel(
            f"[bold]{report['indicator']}[/bold]\n{report['context']}\n[dim]{result.origin}[/dim]",
            title="1 · Enlace / VirusTotal",
            border_style="bright_cyan",
        )
    )
    console.print(table)
    console.print("[bold #ffbd2e]Cero detecciones no significa cero riesgo.[/bold #ffbd2e]")


def show_abuseipdb(result: Result) -> None:
    report = result.data
    score = report.get("abuse_confidence_score", 0)
    score_style = "red" if score >= 60 else "yellow" if score >= 25 else "green"

    table = Table(box=box.ROUNDED, border_style="bright_blue", expand=True)
    table.add_column("Campo", style="bold")
    table.add_column("Resultado")
    table.add_row("Confianza de abuso", f"[{score_style}]{score}%[/{score_style}]")
    table.add_row("Reportes", str(report.get("total_reports", 0)))
    table.add_row("Fuentes distintas", str(report.get("distinct_reporters", 0)))
    table.add_row("Lista blanca", abuse.yes_no_unknown(report.get("is_whitelisted")))
    table.add_row("Proveedor", report.get("isp") or "No informado")

    console.print(
        Panel(
            f"[bold]{report['ip_address']}[/bold]\n{report['context']}\n[dim]{result.origin}[/dim]",
            title="2 · Dirección IP / AbuseIPDB",
            border_style="bright_cyan",
        )
    )
    console.print(table)
    console.print("[bold #ffbd2e]Reputación orienta; evidencia y contexto deciden.[/bold #ffbd2e]")


def show_hibp(result: Result) -> None:
    report = result.data
    table = Table(box=box.ROUNDED, border_style="bright_blue", expand=True)
    table.add_column("Brecha", style="bold")
    table.add_column("Fecha")
    table.add_column("Cuentas", justify="right")
    table.add_column("Datos expuestos")

    for breach in report.get("breaches", []):
        classes = ", ".join(
            hibp.translate_data_class(item) for item in breach.get("data_classes", [])[:4]
        )
        table.add_row(
            breach["title"],
            breach.get("breach_date") or "—",
            hibp.compact_number(breach.get("pwn_count", 0)),
            classes,
        )

    console.print(
        Panel(
            f"[bold]{report['account']}[/bold]\n"
            f"Brechas encontradas: [bold]{report['breach_count']}[/bold]\n"
            f"[dim]{result.origin}[/dim]",
            title="3 · Identidad / Have I Been Pwned",
            border_style="bright_cyan",
        )
    )
    console.print(table)
    console.print(
        "[bold #ffbd2e]La brecha fue del servicio; reutilizar la contraseña "
        "multiplica el impacto.[/bold #ffbd2e]"
    )


def run_module(module_name: str, mode: str, allow_prompt: bool = True) -> bool:
    try:
        if module_name == "virustotal":
            show_virustotal(obtain_virustotal(mode=mode, allow_prompt=allow_prompt))
        elif module_name == "abuseipdb":
            show_abuseipdb(obtain_abuseipdb(mode=mode, allow_prompt=allow_prompt))
        elif module_name == "hibp":
            show_hibp(obtain_hibp(mode=mode))
        else:
            raise ValueError(f"Módulo desconocido: {module_name}")
        return True
    except ModuleUnavailable as error:
        show_error(module_name, error)
        return False


def pause() -> None:
    Prompt.ask("\n[dim]Presiona Enter para continuar[/dim]", default="")


def guided_run(mode: str, allow_prompt: bool = True, pauses: bool = True) -> bool:
    success = True
    for module_name in ("virustotal", "abuseipdb", "hibp"):
        console.clear()
        header()
        success = run_module(module_name, mode, allow_prompt) and success
        if pauses:
            pause()
    return success


def interactive_menu(mode: str) -> int:
    while True:
        console.clear()
        header()
        console.print("\n[bold]Selecciona una demostración[/bold]\n")
        console.print("  [cyan]1[/cyan]  Enlaces · VirusTotal")
        console.print("  [cyan]2[/cyan]  Direcciones IP · AbuseIPDB")
        console.print("  [cyan]3[/cyan]  Identidades · Have I Been Pwned")
        console.print("  [#ffbd2e]4[/#ffbd2e]  Recorrido completo")
        console.print("  [dim]0  Salir[/dim]\n")
        choice = Prompt.ask("Opción", choices=("0", "1", "2", "3", "4"), default="4")

        if choice == "0":
            return 0
        if choice == "4":
            guided_run(mode)
            continue

        module_name = {"1": "virustotal", "2": "abuseipdb", "3": "hibp"}[choice]
        console.clear()
        header()
        run_module(module_name, mode)
        pause()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consola integrada de expoCiber.")
    parser.add_argument(
        "--module",
        choices=("menu", "virustotal", "abuseipdb", "hibp", "all"),
        default="menu",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "live", "offline"),
        default="auto",
    )
    parser.add_argument("--no-prompt", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.module == "menu":
        if not sys.stdin.isatty():
            console.print("Usa --module para una ejecución no interactiva.", style="red")
            return 2
        return interactive_menu(args.mode)

    header()
    allow_prompt = not args.no_prompt
    if args.module == "all":
        return 0 if guided_run(args.mode, allow_prompt, pauses=False) else 1
    return 0 if run_module(args.module, args.mode, allow_prompt) else 1


if __name__ == "__main__":
    raise SystemExit(main())

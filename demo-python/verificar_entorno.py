"""Comprueba que el entorno local tenga las dependencias del proyecto."""

from importlib.metadata import PackageNotFoundError, version
from platform import python_version

PACKAGES = ("requests", "rich", "pytest", "ruff")


def main() -> int:
    print(f"Python {python_version()}")
    missing = []

    for package in PACKAGES:
        try:
            installed = version(package)
            print(f"  [OK]    {package:<10} {installed}")
        except PackageNotFoundError:
            missing.append(package)
            print(f"  [FALTA] {package:<10} no instalado")

    if missing:
        print("\nFaltan dependencias. Ejecuta ./instalar_entorno.ps1")
        return 1

    print("\nEntorno de expoCiber Tools listo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


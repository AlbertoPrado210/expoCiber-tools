# Contribuciones

## Preparacion

Desde `demo-python`:

```powershell
./instalar_entorno.ps1
./.venv/Scripts/python.exe -m pytest
./.venv/Scripts/python.exe -m ruff check .
```

## Reglas del proyecto

- Las pruebas no deben depender de conectividad ni de API keys reales.
- Los datos de ejemplo deben ser sinteticos o estar sanitizados.
- No se aceptan secretos, correos reales, hashes reutilizables ni indicadores sensibles.
- Toda consulta en vivo debe tener timeout, manejo de errores y respaldo local seguro.
- Los cambios funcionales deben incluir pruebas automatizadas.

## Pull requests

Describa el problema, la solucion, las pruebas realizadas y cualquier impacto de privacidad o
seguridad. Mantenga cada cambio enfocado en una sola finalidad.

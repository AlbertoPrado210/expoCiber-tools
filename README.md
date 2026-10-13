# expoCiber Tools

Toolkit defensivo en Python para consultar información pública de VirusTotal, AbuseIPDB y Have I Been Pwned sin abrir enlaces sospechosos ni conectarse directamente a las direcciones IP analizadas.

El proyecto acompaña la charla *La ciberseguridad aplicada en la vida diaria* y está diseñado para demostraciones educativas, laboratorios controlados y consultas autorizadas.

## Problema que aborda

El análisis inicial de un indicador suele requerir consultar varias fuentes y explicar correctamente sus límites. Este proyecto unifica tres verificaciones frecuentes en una consola y ofrece datos de ejemplo para realizar demostraciones sin exponer información personal.

## Capacidades

- Consulta de reportes existentes de archivos o URL en VirusTotal.
- Consulta de reputación pública de direcciones IP en AbuseIPDB.
- Consulta de brechas conocidas mediante la API de Have I Been Pwned.
- Modos automático, en vivo y con respaldo local sanitizado.
- Solicitud oculta de API keys y soporte para variables de entorno.
- Validación de entradas y funcionamiento verificable sin conexión.
- Pruebas automatizadas y análisis estático con Ruff.

## Arquitectura

```text
expoCiber-tools/
|-- demo-python/          Aplicación de consola y pruebas
|-- datos-sinteticos/     Respuestas sanitizadas para demostraciones
|-- .env.example          Nombres de variables, sin secretos
|-- SECURITY.md           Política para reportar problemas de seguridad
`-- README.md
```

El flujo general es:

```text
entrada del usuario
    -> validación y normalización
    -> selección de modo
    -> consulta en vivo o muestra local
    -> presentación del resultado y sus límites
```

## Inicio rápido en Windows

Requiere Python 3.12 o posterior.

```powershell
cd demo-python
./instalar_entorno.ps1
./ejecutar_exposicion.ps1
```

Para ejecutar una herramienta específica:

```powershell
./.venv/Scripts/python.exe consultar_virustotal.py --sample asyncrat --mode auto
./.venv/Scripts/python.exe consultar_abuseipdb.py --sample reportada --mode auto
./.venv/Scripts/python.exe consultar_hibp.py --sample multiple --mode auto
```

## Configuración de API keys

VirusTotal y AbuseIPDB requieren una API key para las consultas en vivo. La aplicación puede solicitarla mediante una entrada oculta y mantenerla únicamente en memoria durante la ejecución.

También se pueden definir variables de entorno temporales:

```powershell
$env:VT_API_KEY = "tu_clave"
$env:ABUSEIPDB_API_KEY = "tu_clave"
$env:HIBP_API_KEY = "tu_clave"
```

No deben guardarse claves reales en archivos `.env`, capturas, notebooks, historial de terminal ni commits. `.env.example` contiene únicamente los nombres de las variables esperadas.

## Pruebas y calidad

```powershell
cd demo-python
./.venv/Scripts/python.exe -m pytest
./.venv/Scripts/python.exe -m ruff check .
```

Las pruebas cubren validación de entradas, privacidad y comportamiento sin conexión.

## Límites de interpretación

- Una ausencia de detecciones en VirusTotal no demuestra que un recurso sea seguro.
- La puntuación de AbuseIPDB se basa en reportes públicos y no identifica por sí sola a una persona ni confirma una actividad hostil.
- Una coincidencia en Have I Been Pwned informa una exposición conocida, pero no demuestra que una contraseña actual siga comprometida.
- Los resultados deben combinarse con contexto, fuentes adicionales y procedimientos de respuesta autorizados.

## Uso autorizado

- Consultar únicamente indicadores cuya revisión esté autorizada.
- No visitar, descargar ni ejecutar muestras sospechosas.
- No consultar cuentas de terceros sin autorización expresa.
- Respetar los términos, cuotas y políticas de cada API.
- Revocar cualquier credencial expuesta antes de limpiar el historial del repositorio.

## Fuentes oficiales

- [VirusTotal API](https://docs.virustotal.com/reference/overview)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)


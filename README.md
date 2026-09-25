# expoCiber Tools

Herramientas defensivas en Python para consultar reportes existentes de VirusTotal, reputación pública de direcciones IP en AbuseIPDB y brechas conocidas en Have I Been Pwned.

El proyecto acompaña la charla **La ciberseguridad aplicada en la vida diaria**. Su finalidad es educativa: reducir la incertidumbre antes de abrir un enlace, confiar en una dirección IP o reutilizar una contraseña.

## Qué incluye

- Una consola integrada para ejecutar las tres verificaciones.
- Consultas pasivas: el código no abre enlaces sospechosos ni se conecta a las IP analizadas.
- Solicitud oculta de API keys y soporte para variables de entorno.
- Cuenta oficial de integración de HIBP para practicar sin consultar correos personales.
- Modo automático, modo en vivo y respaldo local sanitizado cuando existe.
- Pruebas para validación de entradas, privacidad y funcionamiento sin conexión.

## Inicio rápido en Windows

Requiere Python 3.12 o posterior.

```powershell
cd demo-python
./instalar_entorno.ps1
./ejecutar_exposicion.ps1
```

Para ejecutar únicamente una herramienta:

```powershell
./.venv/Scripts/python.exe consultar_virustotal.py --sample asyncrat --mode auto
./.venv/Scripts/python.exe consultar_abuseipdb.py --sample reportada --mode auto
./.venv/Scripts/python.exe consultar_hibp.py --sample multiple --mode auto
```

## API keys

VirusTotal y AbuseIPDB requieren una API key personal para las consultas en vivo. La aplicación puede solicitarla mediante una entrada oculta y la mantiene únicamente en memoria durante la ejecución.

También puedes definir variables de entorno temporales:

```powershell
$env:VT_API_KEY = "tu_clave"
$env:ABUSEIPDB_API_KEY = "tu_clave"
$env:HIBP_API_KEY = "tu_clave"
```

No guardes claves reales en `.env`, capturas, notebooks, historial de terminal o commits. El archivo `.env.example` contiene solamente nombres de variables vacías.

## Límites de interpretación

- VirusTotal reúne detecciones y reputación. Una ausencia de detecciones no garantiza seguridad.
- AbuseIPDB reúne reportes públicos. Su puntuación no identifica a una persona ni demuestra por sí sola que una conexión sea hostil.
- HIBP informa exposiciones conocidas. Una coincidencia no demuestra que la contraseña actual siga comprometida.

## Uso responsable

- Consulta solamente indicadores que tengas autorización para revisar.
- No visites, descargues ni ejecutes muestras maliciosas.
- No consultes correos de terceros sin autorización expresa.
- Respeta los términos, las cuotas y las políticas de cada API.
- Si una credencial aparece en un repositorio, revócala o rótala antes de limpiar el historial.

## Pruebas

```powershell
cd demo-python
./.venv/Scripts/python.exe -m pytest
./.venv/Scripts/python.exe -m ruff check .
```

## Fuentes oficiales

- VirusTotal: <https://docs.virustotal.com/reference/overview>
- AbuseIPDB: <https://docs.abuseipdb.com/>
- Have I Been Pwned: <https://haveibeenpwned.com/API/v3>


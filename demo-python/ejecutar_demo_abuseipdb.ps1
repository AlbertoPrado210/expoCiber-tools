param(
    [ValidateSet('cloudflare', 'reportada')]
    [string]$Caso = 'reportada'
)

$ErrorActionPreference = 'Stop'
$demoDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $demoDirectory '.venv\Scripts\python.exe'
$script = Join-Path $demoDirectory 'consultar_abuseipdb.py'

if (-not (Test-Path -LiteralPath $python)) {
    throw 'No se encontró el entorno de Python. Ejecuta primero ./instalar_entorno.ps1.'
}

Clear-Host
& $python $script --sample $Caso --mode auto
exit $LASTEXITCODE

param(
    [ValidateSet('asyncrat', 'mirai')]
    [string]$Caso = 'asyncrat'
)

$ErrorActionPreference = 'Stop'
$demoDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $demoDirectory '.venv\Scripts\python.exe'
$script = Join-Path $demoDirectory 'consultar_virustotal.py'

if (-not (Test-Path -LiteralPath $python)) {
    throw 'No se encontró el entorno de Python. Instala primero las dependencias del proyecto.'
}

Clear-Host
& $python $script --sample $Caso --mode auto
exit $LASTEXITCODE

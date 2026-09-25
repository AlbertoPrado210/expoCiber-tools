$ErrorActionPreference = 'Stop'
$demoDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $demoDirectory '.venv\Scripts\python.exe'
$application = Join-Path $demoDirectory 'expociber_app.py'

if (-not (Test-Path -LiteralPath $python)) {
    throw 'No se encontró el entorno de Python. Ejecuta primero ./instalar_entorno.ps1.'
}

$Host.UI.RawUI.WindowTitle = 'expoCiber · Demostración defensiva'
$env:PYTHONUTF8 = '1'
Clear-Host
& $python $application --module menu --mode auto
exit $LASTEXITCODE

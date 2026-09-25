$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$environmentDirectory = Join-Path $projectDirectory '.venv'
$python = Join-Path $environmentDirectory 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    py -3.12 -m venv $environmentDirectory
}

& $python -m pip install -r (Join-Path $projectDirectory 'requirements-dev.txt')
& $python -m pip check

Write-Output 'Entorno de expoCiber instalado correctamente.'

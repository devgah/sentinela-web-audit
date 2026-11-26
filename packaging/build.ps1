$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    python -m PyInstaller --noconfirm --clean (Join-Path $PSScriptRoot 'sentinela-web-audit.spec')
}
finally {
    Pop-Location
}

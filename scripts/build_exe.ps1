# Build a standalone lastwrite.exe locally.
#   powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
$ErrorActionPreference = "Stop"

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    Write-Host "Installing build deps..." -ForegroundColor Cyan
    python -m pip install --upgrade pip
    pip install -e ".[exe]"

    Write-Host "Running PyInstaller..." -ForegroundColor Cyan
    pyinstaller --clean --noconfirm lastwrite.spec

    $exe = Join-Path (Get-Location) "dist\lastwrite.exe"
    if (Test-Path $exe) {
        Write-Host "Built: $exe" -ForegroundColor Green
        & $exe --version
    } else {
        throw "Build finished but $exe not found"
    }
}
finally {
    Pop-Location
}

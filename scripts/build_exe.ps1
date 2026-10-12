# Build a standalone lastwrite.exe locally.
#   powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
# Runs the offline test gate first, then PyInstaller, then writes a SHA-256
# checksum file (dist\lastwrite.exe.sha256) for beta distribution.
# NOTE: output is still UNSIGNED — see lastwrite.spec for signing steps.
$ErrorActionPreference = "Stop"

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    Write-Host "Test gate (offline)..." -ForegroundColor Cyan
    python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "pytest failed — refusing to build exe" }

    Write-Host "Offline smoke (no admin)..." -ForegroundColor Cyan
    python -m lastwrite --from-etl examples\sample_trace.csv --format json -o $env:TEMP\lw-smoke.json
    python -m lastwrite report --from-etl examples\sample_trace.csv --output $env:TEMP\lw-smoke.html
    if (-not (Test-Path $env:TEMP\lw-smoke.html)) { throw "smoke report not produced" }

    Write-Host "Installing build deps..." -ForegroundColor Cyan
    python -m pip install --upgrade pip
    pip install -e ".[exe]"

    Write-Host "Running PyInstaller..." -ForegroundColor Cyan
    pyinstaller --clean --noconfirm lastwrite.spec

    $exe = Join-Path (Get-Location) "dist\lastwrite.exe"
    if (Test-Path $exe) {
        Write-Host "Built: $exe" -ForegroundColor Green
        & $exe --version
        $hash = (Get-FileHash -Algorithm SHA256 $exe).Hash
        $hash | Out-File -Encoding ascii (Join-Path (Get-Location) "dist\lastwrite.exe.sha256")
        Write-Host "SHA256: $hash" -ForegroundColor Green
        Write-Host "Publish the .sha256 next to the exe; testers verify with:" -ForegroundColor Yellow
        Write-Host '  (Get-FileHash -Algorithm SHA256 .\lastwrite.exe).Hash -eq (Get-Content .\lastwrite.exe.sha256)'
    } else {
        throw "Build finished but $exe not found"
    }
}
finally {
    Pop-Location
}

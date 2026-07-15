param(
    [string]$Python = 'python',
    [string]$VirtualEnvironment = (Join-Path $PSScriptRoot '..\..\.venv'),
    [switch]$SkipBrowserInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$venv = [System.IO.Path]::GetFullPath($VirtualEnvironment)

& $Python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw 'Unable to create the Python virtual environment' }
$venvPython = Join-Path $venv 'Scripts\python.exe'
& $venvPython -m pip install --require-hashes -r (Join-Path $repositoryRoot 'requirements-dev.lock')
if ($LASTEXITCODE -ne 0) { throw 'Unable to install Python dependencies' }
& $venvPython -m pip install --no-deps -e $repositoryRoot
if ($LASTEXITCODE -ne 0) { throw 'Unable to install the control-plane package in editable mode' }

Push-Location $repositoryRoot
try {
    if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
        & corepack enable
        if ($LASTEXITCODE -ne 0) { throw 'Unable to enable pnpm through Corepack' }
    }
    & pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Unable to install pnpm workspace dependencies' }
    & pnpm generate:api
    if ($LASTEXITCODE -ne 0) { throw 'Unable to generate API contract types' }
    if (-not $SkipBrowserInstall) {
        & pnpm --filter '@vulnlab/web-console' exec playwright install chromium
        if ($LASTEXITCODE -ne 0) { throw 'Unable to install the Chromium test runtime' }
    }
}
finally {
    Pop-Location
}

Write-Output "Bootstrap completed. Python environment: $venv"

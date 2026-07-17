param(
    [string]$Python = '',
    [switch]$SkipHelm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$composeFile = Join-Path $repositoryRoot 'infrastructure\docker-compose\platform.yml'
$exampleEnv = Join-Path $repositoryRoot 'infrastructure\docker-compose\.env.platform.example'
$chart = Join-Path $repositoryRoot 'infrastructure\kubernetes\helm\vulnlab-platform'
$baselineScripts = @(
    'solve_p0_baseline.py',
    'solve_p1_baseline.py',
    'solve_p2_baseline.py',
    'solve_p3_baseline.py',
    'solve_p4_baseline.py',
    'solve_p5_baseline.py',
    'solve_p6_baseline.py',
    'solve_p7_baseline.py',
    'solve_p8_baseline.py'
)

if ([string]::IsNullOrWhiteSpace($Python)) {
    $venvPython = Join-Path $repositoryRoot '.venv\Scripts\python.exe'
    $Python = if (Test-Path -LiteralPath $venvPython -PathType Leaf) { $venvPython } else { 'python' }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repositoryRoot
try {
    Invoke-Checked $Python @(@('-m', 'compileall', '-q', 'apps/control-plane/src', 'solve_module2.py') + $baselineScripts)
    Invoke-Checked $Python @('-m', 'ruff', 'format', '--check', '.')
    Invoke-Checked $Python @('-m', 'ruff', 'check', '.')
    Invoke-Checked $Python @('-m', 'mypy', 'apps/control-plane/src')
    Invoke-Checked $Python @('-m', 'pytest', '-q', '-p', 'no:cacheprovider')
    Invoke-Checked 'pnpm' @('generate:api')
    Invoke-Checked 'pnpm' @('lint')
    Invoke-Checked 'pnpm' @('typecheck')
    Invoke-Checked 'pnpm' @('test')
    Invoke-Checked 'pnpm' @('build')
    if (Test-Path -LiteralPath (Join-Path $repositoryRoot '.git') -PathType Container) {
        Invoke-Checked 'git' @('diff', '--exit-code', '--', 'packages/shared-types/src/api.generated.ts')
    }
    foreach ($baseline in $baselineScripts) {
        Invoke-Checked $Python @($baseline)
    }
    Invoke-Checked 'docker' @('compose', '--env-file', $exampleEnv, '-f', $composeFile, 'config', '--quiet')
    Invoke-Checked 'docker' @('compose', '--env-file', $exampleEnv, '-f', $composeFile, '--profile', 'identity', 'config', '--quiet')
    if (-not $SkipHelm) {
        Invoke-Checked 'helm' @('lint', $chart, '--strict')
        $rendered = Join-Path $repositoryRoot 'work\rendered-vulnlab-platform.yaml'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $rendered) | Out-Null
        & helm template p1 $chart --namespace vulnlab | Set-Content -LiteralPath $rendered -Encoding UTF8
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $rendered -PathType Leaf)) {
            throw 'Helm chart rendering failed'
        }
    }
}
finally {
    Pop-Location
}

Write-Output 'P0-P8 validation completed successfully.'

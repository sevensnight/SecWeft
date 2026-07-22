param(
    [switch]$RunLocalRuntime
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Head = (git -C $Root rev-parse HEAD).Trim()
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vulnlab-p14-clean-$($Head.Substring(0, 12))-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$Worktree = Join-Path $TempRoot "repo"
$ArtifactDir = Join-Path $Root "artifacts\acceptance\clean-worktree-$($Head.Substring(0, 12))"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

try {
    git -C $Root worktree add --detach $Worktree $Head | Out-Null
    git -C $Worktree clean -xfd | Out-Null
    $python = Join-Path $Worktree ".venv\Scripts\python.exe"
    py -3.11 -m venv (Join-Path $Worktree ".venv")
    & $python -m pip install --require-hashes -r (Join-Path $Worktree "requirements-dev.lock")
    & $python -m pip install --no-deps -e $Worktree
    pnpm --dir $Worktree install --frozen-lockfile
    & $python (Join-Path $Worktree "solve_all_from_scratch.py") --full --json --output (Join-Path $ArtifactDir "from-scratch-result.json")
    if ($RunLocalRuntime) {
        & $python (Join-Path $Worktree "solve_p14_local_authoritative.py") preflight --json | Out-File -Encoding utf8 (Join-Path $ArtifactDir "local-runtime-preflight.json")
        & $python (Join-Path $Worktree "solve_p14_local_authoritative.py") run --json | Out-File -Encoding utf8 (Join-Path $ArtifactDir "local-runtime-run.json")
    }
    $result = [pscustomobject]@{
        valid = $true
        source_commit = $Head
        worktree = $Worktree
        artifact_dir = $ArtifactDir
        local_runtime_requested = [bool]$RunLocalRuntime
    }
    $result | ConvertTo-Json -Depth 5
} finally {
    git -C $Root worktree remove --force $Worktree 2>$null | Out-Null
    if (Test-Path $TempRoot) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force
    }
}

param(
    [switch]$InstallMissing
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$ToolDir = Join-Path $Root ".tools\p14"
$BinDir = Join-Path $ToolDir "bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$Versions = @{
    kind = "v0.27.0"
    kubectl = "v1.32.2"
    helm = "v3.17.3"
}

function Find-Tool {
    param([string]$Name)
    $local = Join-Path $BinDir "$Name.exe"
    if (Test-Path $local) { return $local }
    $global = Get-Command $Name -ErrorAction SilentlyContinue
    if ($global) { return $global.Source }
    return $null
}

function Download-File {
    param([string]$Uri, [string]$OutFile)
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
}

function Ensure-Tool {
    param([string]$Name)
    $found = Find-Tool $Name
    if ($found -or -not $InstallMissing) { return $found }
    if ($Name -eq "kind") {
        $target = Join-Path $BinDir "kind.exe"
        Download-File "https://kind.sigs.k8s.io/dl/$($Versions.kind)/kind-windows-amd64" $target
        return $target
    }
    if ($Name -eq "kubectl") {
        $target = Join-Path $BinDir "kubectl.exe"
        Download-File "https://dl.k8s.io/release/$($Versions.kubectl)/bin/windows/amd64/kubectl.exe" $target
        return $target
    }
    if ($Name -eq "helm") {
        $zip = Join-Path $ToolDir "helm.zip"
        Download-File "https://get.helm.sh/helm-$($Versions.helm)-windows-amd64.zip" $zip
        Expand-Archive -Path $zip -DestinationPath $ToolDir -Force
        Copy-Item (Join-Path $ToolDir "windows-amd64\helm.exe") (Join-Path $BinDir "helm.exe") -Force
        Remove-Item $zip -Force
        return Join-Path $BinDir "helm.exe"
    }
    return $null
}

$checks = @()
foreach ($tool in @("docker", "wsl", "kind", "k3d", "kubectl", "helm", "python", "node", "pnpm")) {
    $resolved = Ensure-Tool $tool
    $available = [bool]$resolved
    $version = ""
    if ($available) {
        try {
            if ($tool -eq "docker") { $version = & $resolved version --format "{{json .}}" 2>&1 | Out-String }
            elseif ($tool -eq "kubectl") { $version = & $resolved version --client=true -o json 2>&1 | Out-String }
            elseif ($tool -eq "helm") { $version = & $resolved version --template "{{.Version}}" 2>&1 | Out-String }
            elseif ($tool -eq "kind") { $version = & $resolved version 2>&1 | Out-String }
            elseif ($tool -eq "k3d") { $version = & $resolved version 2>&1 | Out-String }
            else { $version = & $resolved --version 2>&1 | Out-String }
        } catch {
            $version = $_.Exception.Message
        }
    }
    $checks += [pscustomobject]@{
        tool = $tool
        available = $available
        resolved = $resolved
        version = $version.Trim()
    }
}

$result = [pscustomobject]@{
    valid = ($checks | Where-Object { -not $_.available -and $_.tool -notin @("wsl", "k3d") }).Count -eq 0
    install_missing = [bool]$InstallMissing
    tool_dir = $ToolDir
    checks = $checks
}

$result | ConvertTo-Json -Depth 6
if (-not $result.valid) { exit 1 }

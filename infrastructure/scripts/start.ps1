param(
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\docker-compose\.env.platform'),
    [switch]$NoBuild,
    [switch]$Identity
)

. (Join-Path $PSScriptRoot 'common.ps1')
$platform = Get-PlatformEnvironment -Path $EnvFile
if ($Identity) { Assert-IdentityEnvironment -Environment $platform }
Assert-DockerAvailable
Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @('config', '--quiet')

$arguments = @()
if ($Identity) { $arguments += @('--profile', 'identity') }
$arguments += @('up', '--detach', '--wait', '--remove-orphans')
if (-not $NoBuild) { $arguments += '--build' }
Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments $arguments
Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @('ps')

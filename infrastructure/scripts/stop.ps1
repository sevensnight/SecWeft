param(
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\docker-compose\.env.platform'),
    [switch]$Identity
)

. (Join-Path $PSScriptRoot 'common.ps1')
$platform = Get-PlatformEnvironment -Path $EnvFile
Assert-DockerAvailable
$arguments = @()
if ($Identity) { $arguments += @('--profile', 'identity') }
$arguments += @('down', '--remove-orphans')
Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments $arguments

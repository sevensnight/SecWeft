param(
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\docker-compose\.env.platform'),
    [string]$DestinationRoot = (Join-Path $PSScriptRoot '..\backups')
)

. (Join-Path $PSScriptRoot 'common.ps1')
$platform = Get-PlatformEnvironment -Path $EnvFile
Assert-DockerAvailable

$requiredServices = @('api', 'postgres', 'redis', 'nats', 'minio')
$running = & docker compose --env-file $platform.Path -f $script:PlatformComposeFile ps --status running --services
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect platform services' }
foreach ($service in $requiredServices) {
    if ($running -notcontains $service) {
        throw "Required service is not running: $service"
    }
}

$timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$destination = [System.IO.Path]::GetFullPath($DestinationRoot)
$backupDirectory = Join-Path $destination $timestamp
New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null

$postgresTemporaryPath = '/tmp/vulnlab-platform-postgres.dump'
$statefulStopped = $false
try {
    Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
        'exec', '-T', 'postgres', 'sh', '-ec',
        'export PGPASSWORD="$POSTGRES_PASSWORD"; pg_dump --format=custom --no-owner --no-acl --file=/tmp/vulnlab-platform-postgres.dump --username="$POSTGRES_USER" "$POSTGRES_DB"'
    )
    Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
        'cp', "postgres:${postgresTemporaryPath}", (Join-Path $backupDirectory 'postgres.dump')
    )

    Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @('stop', 'api', 'redis', 'nats', 'minio')
    $statefulStopped = $true
    $mount = "${backupDirectory}:/backup"
    Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
        '--profile', 'tools', 'run', '--rm', '--volume', $mount, 'volume-backup'
    )

    $manifest = [ordered]@{
        schema_version = 1
        platform = 'vulnlab-platform'
        created_at = [DateTime]::UtcNow.ToString('o')
        consistency = 'postgres logical dump plus quiesced named-volume archives'
        files = @('postgres.dump', 'api-data.tar.gz', 'redis-data.tar.gz', 'nats-data.tar.gz', 'minio-data.tar.gz')
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backupDirectory 'manifest.json') -Encoding UTF8

    $checksumFiles = @($manifest.files) + 'manifest.json'
    $checksumLines = foreach ($name in $checksumFiles) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $backupDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    $checksumLines | Set-Content -LiteralPath (Join-Path $backupDirectory 'checksums.sha256') -Encoding ASCII
}
finally {
    try {
        Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @('exec', '-T', 'postgres', 'rm', '-f', $postgresTemporaryPath)
    }
    catch {
        Write-Warning "Could not remove temporary PostgreSQL dump: $($_.Exception.Message)"
    }
    if ($statefulStopped) {
        Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
            'up', '--detach', '--wait', 'api', 'redis', 'nats', 'minio'
        )
    }
}

Write-Output "Backup completed: $backupDirectory"

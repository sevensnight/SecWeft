param(
    [Parameter(Mandatory = $true)][string]$BackupDirectory,
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\docker-compose\.env.platform'),
    [switch]$ConfirmRestore
)

if (-not $ConfirmRestore) {
    throw 'Restore replaces platform data. Re-run with -ConfirmRestore after verifying the backup path.'
}

. (Join-Path $PSScriptRoot 'common.ps1')
$platform = Get-PlatformEnvironment -Path $EnvFile
Assert-DockerAvailable
$backup = [System.IO.Path]::GetFullPath($BackupDirectory)
if (-not (Test-Path -LiteralPath $backup -PathType Container)) {
    throw "Backup directory not found: $backup"
}

$requiredFiles = @(
    'postgres.dump', 'api-data.tar.gz', 'redis-data.tar.gz', 'nats-data.tar.gz',
    'minio-data.tar.gz', 'manifest.json', 'checksums.sha256'
)
foreach ($name in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $backup $name) -PathType Leaf)) {
        throw "Backup is incomplete; missing $name"
    }
}

$manifest = Get-Content -LiteralPath (Join-Path $backup 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.platform -ne 'vulnlab-platform') {
    throw 'Backup manifest is not compatible with this platform'
}
$checksumTargets = @($requiredFiles | Where-Object { $_ -ne 'checksums.sha256' })
$verifiedChecksums = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $backup 'checksums.sha256') -Encoding ASCII) {
    if ($line -notmatch '^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$') {
        throw "Invalid checksum record: $line"
    }
    $name = $Matches[2]
    if ($name -notin $checksumTargets) { throw "Unexpected checksum target: $name" }
    if ($verifiedChecksums.ContainsKey($name)) { throw "Duplicate checksum target: $name" }
    $path = Join-Path $backup $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Checksum target is missing: $name" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Matches[1]) { throw "Checksum mismatch: $name" }
    $verifiedChecksums[$name] = $true
}
foreach ($name in $checksumTargets) {
    if (-not $verifiedChecksums.ContainsKey($name)) { throw "Checksum record is missing: $name" }
}

$postgresTemporaryPath = '/tmp/vulnlab-platform-restore.dump'
$completed = $false
Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @('stop', 'api', 'redis', 'nats', 'minio')
try {
    $mount = "${backup}:/backup:ro"
    Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
        '--profile', 'tools', 'run', '--rm', '--volume', $mount, 'volume-restore'
    )

    $postgresContainer = & docker compose --env-file $platform.Path -f $script:PlatformComposeFile ps -q postgres
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresContainer)) {
        throw 'Unable to resolve the PostgreSQL container for restore'
    }
    & docker cp (Join-Path $backup 'postgres.dump') "${postgresContainer}:${postgresTemporaryPath}"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to copy the PostgreSQL dump into the container' }
    Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
        'exec', '-T', 'postgres', 'sh', '-ec',
        'export PGPASSWORD="$POSTGRES_PASSWORD"; dropdb --if-exists --force --username="$POSTGRES_USER" "$POSTGRES_DB"; createdb --username="$POSTGRES_USER" --owner="$POSTGRES_USER" "$POSTGRES_DB"; pg_restore --exit-on-error --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" /tmp/vulnlab-platform-restore.dump'
    )
    $completed = $true
}
finally {
    try {
        Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @('exec', '-T', 'postgres', 'rm', '-f', $postgresTemporaryPath)
    }
    catch {
        Write-Warning "Could not remove temporary restore dump: $($_.Exception.Message)"
    }
    if ($completed) {
        Invoke-PlatformCompose -EnvironmentFile $platform.Path -Arguments @(
            'up', '--detach', '--wait', 'api', 'redis', 'nats', 'minio'
        )
    }
    else {
        Write-Warning 'Restore did not complete; stateful services remain stopped to prevent use of partial data.'
    }
}

Write-Output "Restore completed from: $backup"

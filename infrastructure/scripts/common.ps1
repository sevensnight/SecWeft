Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$script:PlatformComposeFile = Join-Path $script:RepositoryRoot 'infrastructure\docker-compose\platform.yml'
$script:DefaultPlatformEnvFile = Join-Path $script:RepositoryRoot 'infrastructure\docker-compose\.env.platform'

function Get-PlatformEnvironment {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Platform environment file not found: $resolved. Copy .env.platform.example and replace all placeholders."
    }

    $values = @{}
    foreach ($line in Get-Content -LiteralPath $resolved -Encoding UTF8) {
        if ($line -match '^\s*(?:#|$)') { continue }
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
            throw "Invalid environment line in ${resolved}: $line"
        }
        $value = $Matches[2].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$Matches[1]] = $value
    }

    $required = @(
        'VULNLAB_ADMIN_KEY', 'VULNLAB_MASTER_KEY',
        'PLATFORM_POSTGRES_USER', 'PLATFORM_POSTGRES_PASSWORD',
        'PLATFORM_POSTGRES_APP_PASSWORD', 'PLATFORM_POSTGRES_DB',
        'PLATFORM_REDIS_PASSWORD', 'PLATFORM_NATS_USER', 'PLATFORM_NATS_PASSWORD',
        'PLATFORM_MINIO_ROOT_USER', 'PLATFORM_MINIO_ROOT_PASSWORD'
    )
    foreach ($name in $required) {
        if (-not $values.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($values[$name])) {
            throw "Required environment variable is missing: $name"
        }
        if ($values[$name] -match '^(GENERATE_|CHANGE[_-]?ME|REPLACE[_-]?ME)') {
            throw "Placeholder value is forbidden for $name"
        }
    }

    foreach ($name in @(
        'VULNLAB_ADMIN_KEY', 'PLATFORM_POSTGRES_PASSWORD',
        'PLATFORM_POSTGRES_APP_PASSWORD', 'PLATFORM_REDIS_PASSWORD',
        'PLATFORM_NATS_PASSWORD', 'PLATFORM_MINIO_ROOT_PASSWORD'
    )) {
        if ($values[$name].Length -lt 24) {
            throw "$name must contain at least 24 characters"
        }
    }
    foreach ($name in @(
        'PLATFORM_POSTGRES_PASSWORD', 'PLATFORM_POSTGRES_APP_PASSWORD',
        'PLATFORM_REDIS_PASSWORD', 'PLATFORM_NATS_PASSWORD'
    )) {
        if ($values[$name] -notmatch '^[A-Za-z0-9_-]{24,}$') {
            throw "$name must be URL-safe because it is used in a connection URI or service configuration"
        }
    }
    if ($values['VULNLAB_MASTER_KEY'] -notmatch '^[A-Za-z0-9_-]{43}=$') {
        throw 'VULNLAB_MASTER_KEY must be a URL-safe 32-byte Fernet key'
    }
    foreach ($name in @('PLATFORM_POSTGRES_USER', 'PLATFORM_POSTGRES_DB', 'PLATFORM_NATS_USER')) {
        if ($values[$name] -notmatch '^[A-Za-z_][A-Za-z0-9_-]*$') {
            throw "$name may contain only letters, digits, underscores, and hyphens"
        }
    }
    if ($values['PLATFORM_POSTGRES_DB'] -in @('postgres', 'template0', 'template1')) {
        throw 'PLATFORM_POSTGRES_DB must be an application database, not a PostgreSQL maintenance database'
    }

    return [PSCustomObject]@{ Path = $resolved; Values = $values }
}

function Invoke-PlatformCompose {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentFile,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & docker compose --env-file $EnvironmentFile -f $script:PlatformComposeFile @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

function Assert-DockerAvailable {
    & docker version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Engine is unavailable. Start Docker Desktop or the Docker service and retry.'
    }
    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Compose v2 is required.'
    }
}

function Assert-IdentityEnvironment {
    param([Parameter(Mandatory = $true)]$Environment)

    foreach ($name in @(
        'PLATFORM_KEYCLOAK_ADMIN_USER', 'PLATFORM_KEYCLOAK_ADMIN_PASSWORD',
        'VULNLAB_AUTH_MODE', 'VULNLAB_OIDC_ISSUER', 'VULNLAB_OIDC_BROWSER_ORIGIN',
        'VULNLAB_OIDC_AUDIENCE', 'VULNLAB_OIDC_JWKS_URL'
    )) {
        if (-not $Environment.Values.ContainsKey($name) -or
            [string]::IsNullOrWhiteSpace($Environment.Values[$name])) {
            throw "Required identity profile variable is missing: $name"
        }
        if ($Environment.Values[$name] -match '^(GENERATE_|CHANGE[_-]?ME|REPLACE[_-]?ME)') {
            throw "Placeholder value is forbidden for $name"
        }
    }
    if ($Environment.Values['PLATFORM_KEYCLOAK_ADMIN_USER'] -notmatch '^[A-Za-z0-9._-]{3,64}$') {
        throw 'PLATFORM_KEYCLOAK_ADMIN_USER contains unsupported characters'
    }
    if ($Environment.Values['PLATFORM_KEYCLOAK_ADMIN_PASSWORD'].Length -lt 24) {
        throw 'PLATFORM_KEYCLOAK_ADMIN_PASSWORD must contain at least 24 characters'
    }
    if ($Environment.Values['VULNLAB_AUTH_MODE'] -ne 'oidc') {
        throw 'The identity profile requires VULNLAB_AUTH_MODE=oidc'
    }

    $production = $Environment.Values.ContainsKey('VULNLAB_ENV') -and
        $Environment.Values['VULNLAB_ENV'] -in @('production', 'prod')
    $uris = @{}
    foreach ($name in @(
        'VULNLAB_OIDC_ISSUER', 'VULNLAB_OIDC_BROWSER_ORIGIN', 'VULNLAB_OIDC_JWKS_URL'
    )) {
        $uri = $null
        $value = $Environment.Values[$name]
        if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -notin @('http', 'https') -or
            -not [string]::IsNullOrEmpty($uri.UserInfo) -or
            -not [string]::IsNullOrEmpty($uri.Query) -or
            -not [string]::IsNullOrEmpty($uri.Fragment)) {
            throw "$name must be an absolute HTTP(S) URL without credentials, query, or fragment"
        }
        if ($production -and $uri.Scheme -ne 'https') {
            throw "$name must use HTTPS in production"
        }
        $uris[$name] = $uri
    }
    $browserUri = $uris['VULNLAB_OIDC_BROWSER_ORIGIN']
    if ($browserUri.AbsolutePath -ne '/' -or
        $Environment.Values['VULNLAB_OIDC_BROWSER_ORIGIN'] -ne
            $browserUri.GetLeftPart([UriPartial]::Authority)) {
        throw 'VULNLAB_OIDC_BROWSER_ORIGIN must contain only scheme, host, and optional port'
    }
    if ($uris['VULNLAB_OIDC_ISSUER'].GetLeftPart([UriPartial]::Authority) -ne
        $browserUri.GetLeftPart([UriPartial]::Authority)) {
        throw 'VULNLAB_OIDC_BROWSER_ORIGIN must match the issuer origin'
    }
    if ($Environment.Values['VULNLAB_OIDC_AUDIENCE'] -notmatch '^[A-Za-z0-9._:/-]{1,255}$') {
        throw 'VULNLAB_OIDC_AUDIENCE contains unsupported characters'
    }
}

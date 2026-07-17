#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
PLATFORM_COMPOSE_FILE="$REPOSITORY_ROOT/infrastructure/docker-compose/platform.yml"
DEFAULT_PLATFORM_ENV_FILE="$REPOSITORY_ROOT/infrastructure/docker-compose/.env.platform"

read_env_value() {
  name=$1
  file=$2
  value=$(sed -n "s/^[[:space:]]*$name[[:space:]]*=[[:space:]]*//p" "$file" | sed -n '1p')
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*\') value=${value#\'}; value=${value%\'} ;;
  esac
  printf '%s' "$value"
}

validate_platform_env() {
  ENV_FILE=${1:-$DEFAULT_PLATFORM_ENV_FILE}
  if [ ! -f "$ENV_FILE" ]; then
    echo "Platform environment file not found: $ENV_FILE" >&2
    echo "Copy .env.platform.example and replace all placeholders." >&2
    exit 2
  fi
  ENV_FILE=$(CDPATH= cd -- "$(dirname -- "$ENV_FILE")" && pwd -P)/$(basename -- "$ENV_FILE")

  required='VULNLAB_ADMIN_KEY VULNLAB_MASTER_KEY PLATFORM_POSTGRES_USER PLATFORM_POSTGRES_PASSWORD PLATFORM_POSTGRES_APP_PASSWORD PLATFORM_POSTGRES_DB PLATFORM_REDIS_PASSWORD PLATFORM_NATS_USER PLATFORM_NATS_PASSWORD PLATFORM_MINIO_ROOT_USER PLATFORM_MINIO_ROOT_PASSWORD'
  for name in $required; do
    value=$(read_env_value "$name" "$ENV_FILE")
    if [ -z "$value" ]; then
      echo "Required environment variable is missing: $name" >&2
      exit 2
    fi
    case "$value" in
      GENERATE_*|CHANGE_ME*|CHANGE-ME*|REPLACE_ME*|REPLACE-ME*)
        echo "Placeholder value is forbidden for $name" >&2
        exit 2
        ;;
    esac
  done

  for name in VULNLAB_ADMIN_KEY PLATFORM_POSTGRES_PASSWORD PLATFORM_POSTGRES_APP_PASSWORD PLATFORM_REDIS_PASSWORD PLATFORM_NATS_PASSWORD PLATFORM_MINIO_ROOT_PASSWORD; do
    value=$(read_env_value "$name" "$ENV_FILE")
    if [ "${#value}" -lt 24 ]; then
      echo "$name must contain at least 24 characters" >&2
      exit 2
    fi
  done

  for name in PLATFORM_POSTGRES_PASSWORD PLATFORM_POSTGRES_APP_PASSWORD PLATFORM_REDIS_PASSWORD PLATFORM_NATS_PASSWORD; do
    value=$(read_env_value "$name" "$ENV_FILE")
    if ! printf '%s' "$value" | grep -Eq '^[A-Za-z0-9_-]{24,}$'; then
      echo "$name must be URL-safe because it is used in a connection URI or service configuration" >&2
      exit 2
    fi
  done

  master_key=$(read_env_value VULNLAB_MASTER_KEY "$ENV_FILE")
  if ! printf '%s' "$master_key" | grep -Eq '^[A-Za-z0-9_-]{43}=$'; then
    echo 'VULNLAB_MASTER_KEY must be a URL-safe 32-byte Fernet key' >&2
    exit 2
  fi
  for name in PLATFORM_POSTGRES_USER PLATFORM_POSTGRES_DB PLATFORM_NATS_USER; do
    value=$(read_env_value "$name" "$ENV_FILE")
    if ! printf '%s' "$value" | grep -Eq '^[A-Za-z_][A-Za-z0-9_-]*$'; then
      echo "$name may contain only letters, digits, underscores, and hyphens" >&2
      exit 2
    fi
  done
  case "$(read_env_value PLATFORM_POSTGRES_DB "$ENV_FILE")" in
    postgres|template0|template1)
      echo 'PLATFORM_POSTGRES_DB must be an application database, not a PostgreSQL maintenance database' >&2
      exit 2
      ;;
  esac
}

compose() {
  docker compose --env-file "$ENV_FILE" -f "$PLATFORM_COMPOSE_FILE" "$@"
}

assert_docker_available() {
  if ! docker version >/dev/null 2>&1; then
    echo 'Docker Engine is unavailable. Start Docker Desktop or the Docker service and retry.' >&2
    exit 3
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo 'Docker Compose v2 is required.' >&2
    exit 3
  fi
}

sha256_file() {
  file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    echo 'A SHA-256 implementation (sha256sum or shasum) is required.' >&2
    exit 3
  fi
}

validate_identity_env() {
  for name in PLATFORM_KEYCLOAK_ADMIN_USER PLATFORM_KEYCLOAK_ADMIN_PASSWORD VULNLAB_AUTH_MODE VULNLAB_OIDC_ISSUER VULNLAB_OIDC_BROWSER_ORIGIN VULNLAB_OIDC_AUDIENCE VULNLAB_OIDC_JWKS_URL; do
    value=$(read_env_value "$name" "$ENV_FILE")
    if [ -z "$value" ]; then
      echo "Required identity profile variable is missing: $name" >&2
      exit 2
    fi
    case "$value" in
      GENERATE_*|CHANGE_ME*|CHANGE-ME*|REPLACE_ME*|REPLACE-ME*)
        echo "Placeholder value is forbidden for $name" >&2
        exit 2
        ;;
    esac
  done
  identity_user=$(read_env_value PLATFORM_KEYCLOAK_ADMIN_USER "$ENV_FILE")
  if ! printf '%s' "$identity_user" | grep -Eq '^[A-Za-z0-9._-]{3,64}$'; then
    echo 'PLATFORM_KEYCLOAK_ADMIN_USER contains unsupported characters' >&2
    exit 2
  fi
  identity_password=$(read_env_value PLATFORM_KEYCLOAK_ADMIN_PASSWORD "$ENV_FILE")
  if [ "${#identity_password}" -lt 24 ]; then
    echo 'PLATFORM_KEYCLOAK_ADMIN_PASSWORD must contain at least 24 characters' >&2
    exit 2
  fi
  if [ "$(read_env_value VULNLAB_AUTH_MODE "$ENV_FILE")" != 'oidc' ]; then
    echo 'The identity profile requires VULNLAB_AUTH_MODE=oidc' >&2
    exit 2
  fi

  production=0
  case "$(read_env_value VULNLAB_ENV "$ENV_FILE")" in
    production|prod) production=1 ;;
  esac
  for name in VULNLAB_OIDC_ISSUER VULNLAB_OIDC_BROWSER_ORIGIN VULNLAB_OIDC_JWKS_URL; do
    value=$(read_env_value "$name" "$ENV_FILE")
    if ! printf '%s' "$value" | grep -Eq '^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?(/[^?#[:space:]]*)?$'; then
      echo "$name must be an absolute HTTP(S) URL without credentials, query, or fragment" >&2
      exit 2
    fi
    if [ "$production" = '1' ] && ! printf '%s' "$value" | grep -Eq '^https://'; then
      echo "$name must use HTTPS in production" >&2
      exit 2
    fi
  done
  browser_origin=$(read_env_value VULNLAB_OIDC_BROWSER_ORIGIN "$ENV_FILE")
  if ! printf '%s' "$browser_origin" | grep -Eq '^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$'; then
    echo 'VULNLAB_OIDC_BROWSER_ORIGIN must contain only scheme, host, and optional port' >&2
    exit 2
  fi
  issuer=$(read_env_value VULNLAB_OIDC_ISSUER "$ENV_FILE")
  issuer_origin=$(printf '%s' "$issuer" | sed -E 's#^(https?://[^/]+).*$#\1#')
  if [ "$browser_origin" != "$issuer_origin" ]; then
    echo 'VULNLAB_OIDC_BROWSER_ORIGIN must match the issuer origin' >&2
    exit 2
  fi
  audience=$(read_env_value VULNLAB_OIDC_AUDIENCE "$ENV_FILE")
  if ! printf '%s' "$audience" | grep -Eq '^[A-Za-z0-9._:/-]{1,255}$'; then
    echo 'VULNLAB_OIDC_AUDIENCE contains unsupported characters' >&2
    exit 2
  fi
}

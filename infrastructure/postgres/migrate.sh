#!/usr/bin/env sh
set -eu

required='POSTGRES_HOST POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB PLATFORM_POSTGRES_APP_PASSWORD'
for name in $required; do
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "Required migration environment variable is missing: $name" >&2
    exit 64
  fi
done

case "$PLATFORM_POSTGRES_APP_PASSWORD" in
  GENERATE_*|CHANGE_ME*|CHANGE-ME*|REPLACE_ME*|REPLACE-ME*)
    echo 'Application database password is still a placeholder' >&2
    exit 64
    ;;
esac
if [ "${#PLATFORM_POSTGRES_APP_PASSWORD}" -lt 24 ]; then
  echo 'Application database password must contain at least 24 characters' >&2
  exit 64
fi

export PGPASSWORD=$POSTGRES_PASSWORD
for attempt in $(seq 1 30); do
  if pg_isready -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo 'PostgreSQL did not become ready for migrations' >&2
    exit 70
  fi
  sleep 1
done

psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
CREATE SCHEMA IF NOT EXISTS platform_meta;
CREATE TABLE IF NOT EXISTS platform_meta.schema_migrations (
    version varchar(32) PRIMARY KEY,
    filename varchar(255) NOT NULL UNIQUE,
    sha256 char(64) NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
SQL

for migration in /migrations/*.up.sql; do
  filename=$(basename "$migration")
  version=${filename%%_*}
  checksum=$(sha256sum "$migration" | awk '{print $1}')
  recorded=$(psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -tAc "SELECT sha256 FROM platform_meta.schema_migrations WHERE version = '$version'")
  if [ -n "$recorded" ]; then
    if [ "$recorded" != "$checksum" ]; then
      echo "Applied migration checksum differs from source: $filename" >&2
      exit 65
    fi
    continue
  fi

  baseline_relation=''
  case "$version" in
    0001) baseline_relation='iam.tenants' ;;
    0002) baseline_relation='iam.organizations' ;;
  esac
  already_present='f'
  if [ -n "$baseline_relation" ]; then
    already_present=$(psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" \
      -d "$POSTGRES_DB" -tAc "SELECT to_regclass('$baseline_relation') IS NOT NULL")
  fi
  if [ "$already_present" != 't' ]; then
    psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" \
      -d "$POSTGRES_DB" -f "$migration"
  fi
  psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    --set=version="$version" --set=filename="$filename" --set=checksum="$checksum" <<'SQL'
INSERT INTO platform_meta.schema_migrations (version, filename, sha256)
VALUES (:'version', :'filename', :'checksum');
SQL
done

psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  --set=app_password="$PLATFORM_POSTGRES_APP_PASSWORD" <<'SQL'
DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulnlab_app') THEN
        CREATE ROLE vulnlab_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$role$;
ALTER ROLE vulnlab_app LOGIN PASSWORD :'app_password';
SQL

echo 'PostgreSQL migrations and least-privilege application role are ready'

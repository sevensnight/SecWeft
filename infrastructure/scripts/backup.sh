#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/common.sh"

ENV_FILE=${PLATFORM_ENV_FILE:-${2:-$DEFAULT_PLATFORM_ENV_FILE}}
DESTINATION_ROOT=${1:-$REPOSITORY_ROOT/infrastructure/backups}
validate_platform_env "$ENV_FILE"
assert_docker_available

running=$(compose ps --status running --services)
for service in api postgres redis nats minio; do
  if ! printf '%s\n' "$running" | grep -Fxq "$service"; then
    echo "Required service is not running: $service" >&2
    exit 4
  fi
done

timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
mkdir -p "$DESTINATION_ROOT/$timestamp"
backup_dir=$(CDPATH= cd -- "$DESTINATION_ROOT/$timestamp" && pwd -P)
postgres_temp=/tmp/vulnlab-platform-postgres.dump
stateful_stopped=0

cleanup() {
  compose exec -T postgres rm -f "$postgres_temp" >/dev/null 2>&1 || true
  if [ "$stateful_stopped" -eq 1 ]; then
    compose up --detach --wait api redis nats minio
  fi
}
trap cleanup EXIT HUP INT TERM

compose exec -T postgres sh -ec \
  'export PGPASSWORD="$POSTGRES_PASSWORD"; pg_dump --format=custom --no-owner --no-acl --file=/tmp/vulnlab-platform-postgres.dump --username="$POSTGRES_USER" "$POSTGRES_DB"'
compose cp "postgres:$postgres_temp" "$backup_dir/postgres.dump"

compose stop api redis nats minio
stateful_stopped=1
compose --profile tools run --rm --volume "$backup_dir:/backup" volume-backup

created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "platform": "vulnlab-platform",' \
  "  \"created_at\": \"$created_at\"," \
  '  "consistency": "postgres logical dump plus quiesced named-volume archives",' \
  '  "files": ["postgres.dump", "api-data.tar.gz", "redis-data.tar.gz", "nats-data.tar.gz", "minio-data.tar.gz"]' \
  '}' >"$backup_dir/manifest.json"

(
  cd "$backup_dir"
  : >checksums.sha256
  for file in postgres.dump api-data.tar.gz redis-data.tar.gz nats-data.tar.gz minio-data.tar.gz manifest.json; do
    printf '%s  %s\n' "$(sha256_file "$file")" "$file" >>checksums.sha256
  done
)

cleanup
trap - EXIT HUP INT TERM
printf 'Backup completed: %s\n' "$backup_dir"

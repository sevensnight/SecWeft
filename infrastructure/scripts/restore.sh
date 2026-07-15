#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/common.sh"

if [ "${1:-}" != '--yes' ] || [ -z "${2:-}" ]; then
  echo 'Restore replaces platform data.' >&2
  echo 'Usage: restore.sh --yes BACKUP_DIRECTORY [ENV_FILE]' >&2
  exit 2
fi

backup_input=$2
ENV_FILE=${PLATFORM_ENV_FILE:-${3:-$DEFAULT_PLATFORM_ENV_FILE}}
validate_platform_env "$ENV_FILE"
assert_docker_available
if [ ! -d "$backup_input" ]; then
  echo "Backup directory not found: $backup_input" >&2
  exit 2
fi
backup_dir=$(CDPATH= cd -- "$backup_input" && pwd -P)

for file in postgres.dump api-data.tar.gz redis-data.tar.gz nats-data.tar.gz minio-data.tar.gz manifest.json checksums.sha256; do
  if [ ! -f "$backup_dir/$file" ]; then
    echo "Backup is incomplete; missing $file" >&2
    exit 2
  fi
done
if ! grep -Eq '"schema_version"[[:space:]]*:[[:space:]]*1' "$backup_dir/manifest.json" ||
   ! grep -Eq '"platform"[[:space:]]*:[[:space:]]*"vulnlab-platform"' "$backup_dir/manifest.json"; then
  echo 'Backup manifest is not compatible with this platform' >&2
  exit 2
fi
checksum_lines=$(wc -l <"$backup_dir/checksums.sha256" | tr -d '[:space:]')
if [ "$checksum_lines" -ne 6 ]; then
  echo 'Checksum manifest must contain exactly six records' >&2
  exit 2
fi
for file in postgres.dump api-data.tar.gz redis-data.tar.gz nats-data.tar.gz minio-data.tar.gz manifest.json; do
  record=$(awk -v target="$file" '
    length($1) == 64 && $1 !~ /[^0-9a-f]/ && $2 == target && NF == 2 { count++; hash=$1 }
    END { if (count == 1) print hash }
  ' "$backup_dir/checksums.sha256")
  if [ -z "$record" ]; then
    echo "Missing, duplicate, or invalid checksum record: $file" >&2
    exit 2
  fi
  actual=$(sha256_file "$backup_dir/$file")
  if [ "$actual" != "$record" ]; then
    echo "Checksum mismatch: $file" >&2
    exit 2
  fi
done

postgres_temp=/tmp/vulnlab-platform-restore.dump
completed=0
cleanup() {
  compose exec -T postgres rm -f "$postgres_temp" >/dev/null 2>&1 || true
  if [ "$completed" -eq 1 ]; then
    compose up --detach --wait api redis nats minio
  else
    echo 'Restore did not complete; stateful services remain stopped to prevent use of partial data.' >&2
  fi
}
trap cleanup EXIT HUP INT TERM

compose stop api redis nats minio
compose --profile tools run --rm --volume "$backup_dir:/backup:ro" volume-restore

compose cp "$backup_dir/postgres.dump" "postgres:$postgres_temp"
compose exec -T postgres sh -ec '
  export PGPASSWORD="$POSTGRES_PASSWORD"
  dropdb --if-exists --force --username="$POSTGRES_USER" "$POSTGRES_DB"
  createdb --username="$POSTGRES_USER" --owner="$POSTGRES_USER" "$POSTGRES_DB"
  pg_restore --exit-on-error --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" /tmp/vulnlab-platform-restore.dump
'

completed=1
cleanup
trap - EXIT HUP INT TERM
printf 'Restore completed from: %s\n' "$backup_dir"

#!/usr/bin/env sh
set -eu

for archive in api-data.tar.gz redis-data.tar.gz nats-data.tar.gz minio-data.tar.gz; do
  if [ ! -f "/backup/$archive" ]; then
    echo "Missing backup archive: $archive" >&2
    exit 66
  fi
  if tar -tzf "/backup/$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    echo "Unsafe archive path in $archive" >&2
    exit 65
  fi
done

for target in api redis nats minio; do
  if [ ! -d "/volumes/$target" ]; then
    echo "Missing destination volume: $target" >&2
    exit 66
  fi
  find "/volumes/$target" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  tar -C "/volumes/$target" -xzf "/backup/$target-data.tar.gz"
done

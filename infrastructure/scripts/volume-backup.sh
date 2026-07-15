#!/usr/bin/env sh
set -eu

for target in api redis nats minio; do
  if [ ! -d "/volumes/$target" ]; then
    echo "Missing source volume: $target" >&2
    exit 66
  fi
done
if [ ! -d /backup ]; then
  echo 'Missing writable /backup mount' >&2
  exit 66
fi

tar -C /volumes/api -czf /backup/api-data.tar.gz .
tar -C /volumes/redis -czf /backup/redis-data.tar.gz .
tar -C /volumes/nats -czf /backup/nats-data.tar.gz .
tar -C /volumes/minio -czf /backup/minio-data.tar.gz .

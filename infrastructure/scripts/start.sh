#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/common.sh"

ENV_FILE=${PLATFORM_ENV_FILE:-${1:-$DEFAULT_PLATFORM_ENV_FILE}}
validate_platform_env "$ENV_FILE"
identity=${2:-}
if [ "$identity" = '--identity' ]; then
  validate_identity_env
elif [ -n "$identity" ]; then
  echo "Unsupported start option: $identity" >&2
  exit 2
fi
assert_docker_available
compose config --quiet
if [ "$identity" = '--identity' ]; then
  compose --profile identity up --detach --wait --remove-orphans --build
else
  compose up --detach --wait --remove-orphans --build
fi
compose ps

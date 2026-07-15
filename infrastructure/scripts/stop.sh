#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$SCRIPT_DIR/common.sh"

ENV_FILE=${PLATFORM_ENV_FILE:-${1:-$DEFAULT_PLATFORM_ENV_FILE}}
validate_platform_env "$ENV_FILE"
identity=${2:-}
if [ -n "$identity" ] && [ "$identity" != '--identity' ]; then
  echo "Unsupported stop option: $identity" >&2
  exit 2
fi
assert_docker_available
if [ "$identity" = '--identity' ]; then
  compose --profile identity down --remove-orphans
else
  compose down --remove-orphans
fi

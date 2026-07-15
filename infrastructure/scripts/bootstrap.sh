#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
PYTHON=${PYTHON:-python3}
VIRTUAL_ENVIRONMENT=${VIRTUAL_ENVIRONMENT:-$REPOSITORY_ROOT/.venv}

"$PYTHON" -m venv "$VIRTUAL_ENVIRONMENT"
"$VIRTUAL_ENVIRONMENT/bin/python" -m pip install --require-hashes -r "$REPOSITORY_ROOT/requirements-dev.lock"
"$VIRTUAL_ENVIRONMENT/bin/python" -m pip install --no-deps -e "$REPOSITORY_ROOT"

cd "$REPOSITORY_ROOT"
if ! command -v pnpm >/dev/null 2>&1; then
  corepack enable
fi
pnpm install --frozen-lockfile
pnpm generate:api
if [ "${SKIP_BROWSER_INSTALL:-0}" != '1' ]; then
  pnpm --filter @vulnlab/web-console exec playwright install chromium
fi

printf 'Bootstrap completed. Python environment: %s\n' "$VIRTUAL_ENVIRONMENT"

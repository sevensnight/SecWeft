#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
PYTHON=${PYTHON:-$REPOSITORY_ROOT/.venv/bin/python}
if [ ! -x "$PYTHON" ]; then
  PYTHON=${PYTHON_FALLBACK:-python3}
fi
COMPOSE_FILE="$REPOSITORY_ROOT/infrastructure/docker-compose/platform.yml"
EXAMPLE_ENV="$REPOSITORY_ROOT/infrastructure/docker-compose/.env.platform.example"
CHART="$REPOSITORY_ROOT/infrastructure/kubernetes/helm/vulnlab-platform"

cd "$REPOSITORY_ROOT"
"$PYTHON" -m compileall -q apps/control-plane/src solve_module2.py solve_p0_baseline.py solve_p1_baseline.py
"$PYTHON" -m ruff format --check .
"$PYTHON" -m ruff check .
"$PYTHON" -m mypy apps/control-plane/src
"$PYTHON" -m pytest -q -p no:cacheprovider
pnpm generate:api
pnpm lint
pnpm typecheck
pnpm test
pnpm build
if [ -d .git ]; then
  git diff --exit-code -- packages/shared-types/src/api.generated.ts
fi
docker compose --env-file "$EXAMPLE_ENV" -f "$COMPOSE_FILE" config --quiet
docker compose --env-file "$EXAMPLE_ENV" -f "$COMPOSE_FILE" --profile identity config --quiet
if [ "${SKIP_HELM:-0}" != '1' ]; then
  helm lint "$CHART" --strict
  mkdir -p work
  helm template p1 "$CHART" --namespace vulnlab >work/rendered-vulnlab-platform.yaml
  test -s work/rendered-vulnlab-platform.yaml
fi

printf '%s\n' 'P0/P1 validation completed successfully.'

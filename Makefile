PYTHON ?= python3
PNPM ?= pnpm
PLATFORM_COMPOSE := infrastructure/docker-compose/platform.yml
PLATFORM_ENV ?= infrastructure/docker-compose/.env.platform
PLATFORM_CONFIG_ENV ?= infrastructure/docker-compose/.env.platform.example
BACKUP ?=

.PHONY: help bootstrap python-compile python-lint python-mypy python-test lint typecheck test build contracts-check \
	platform-config platform-up platform-up-identity platform-down platform-down-identity platform-logs platform-backup platform-restore helm-lint check

help:
	@printf '%s\n' \
	  'bootstrap          Install Python and pnpm dependencies' \
	  'python-test        Run Python regression tests' \
	  'python-lint        Run Python Ruff checks' \
	  'python-mypy        Run control-plane static typing' \
	  'lint               Lint pnpm workspace packages' \
	  'typecheck          Type-check pnpm workspace packages' \
	  'test               Run Python and pnpm tests' \
	  'build              Build the pnpm workspace' \
	  'contracts-check    Validate contracts and generated types' \
	  'platform-config    Validate the Compose model' \
	  'helm-lint         Lint and render the Kubernetes chart' \
	  'platform-up        Start the platform' \
	  'platform-up-identity Start the platform with the development OIDC provider' \
	  'platform-down      Stop the platform without deleting data' \
	  'platform-down-identity Stop the platform including the development OIDC provider' \
	  'platform-backup    Back up persistent platform state' \
	  'platform-restore   Restore BACKUP=/absolute/path with CONFIRM_RESTORE=yes' \
	  'check              Run the full P0 validation suite'

bootstrap:
	PYTHON="$(PYTHON)" sh infrastructure/scripts/bootstrap.sh

python-compile:
	$(PYTHON) -m compileall -q apps/control-plane/src solve_module2.py

python-test:
	$(PYTHON) -m pytest -q -p no:cacheprovider

python-lint:
	$(PYTHON) -m ruff check .

python-mypy:
	$(PYTHON) -m mypy apps/control-plane/src

lint:
	$(PNPM) lint

typecheck:
	$(PNPM) typecheck

test: python-test
	$(PNPM) test

build:
	$(PNPM) build

contracts-check:
	$(PNPM) --filter @vulnlab/api-contracts test
	$(PNPM) generate:api
	git diff --exit-code -- packages/shared-types/src/api.generated.ts

platform-config:
	docker compose --env-file "$(PLATFORM_CONFIG_ENV)" -f "$(PLATFORM_COMPOSE)" config --quiet
	docker compose --env-file "$(PLATFORM_CONFIG_ENV)" -f "$(PLATFORM_COMPOSE)" --profile identity config --quiet

helm-lint:
	mkdir -p work
	helm lint infrastructure/kubernetes/helm/vulnlab-platform --strict
	helm template p0 infrastructure/kubernetes/helm/vulnlab-platform --namespace vulnlab > work/rendered-vulnlab-platform.yaml

platform-up:
	PLATFORM_ENV_FILE="$(PLATFORM_ENV)" sh infrastructure/scripts/start.sh

platform-up-identity:
	PLATFORM_ENV_FILE="$(PLATFORM_ENV)" sh infrastructure/scripts/start.sh "$(PLATFORM_ENV)" --identity

platform-down:
	PLATFORM_ENV_FILE="$(PLATFORM_ENV)" sh infrastructure/scripts/stop.sh

platform-down-identity:
	PLATFORM_ENV_FILE="$(PLATFORM_ENV)" sh infrastructure/scripts/stop.sh "$(PLATFORM_ENV)" --identity

platform-logs:
	docker compose --env-file "$(PLATFORM_ENV)" -f "$(PLATFORM_COMPOSE)" logs --follow --tail=200

platform-backup:
	sh infrastructure/scripts/backup.sh infrastructure/backups "$(PLATFORM_ENV)"

platform-restore:
	@test -n "$(BACKUP)" || (echo 'BACKUP=/absolute/path is required' >&2; exit 2)
	@test "$(CONFIRM_RESTORE)" = 'yes' || (echo 'CONFIRM_RESTORE=yes is required' >&2; exit 2)
	sh infrastructure/scripts/restore.sh --yes "$(BACKUP)" "$(PLATFORM_ENV)"

check: python-compile python-lint python-mypy lint typecheck test build contracts-check platform-config helm-lint

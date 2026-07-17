PYTHON ?= python3
PNPM ?= pnpm
PLATFORM_COMPOSE := infrastructure/docker-compose/platform.yml
PLATFORM_ENV ?= infrastructure/docker-compose/.env.platform
PLATFORM_CONFIG_ENV ?= infrastructure/docker-compose/.env.platform.example
BACKUP ?=

.PHONY: help bootstrap python-compile python-format python-lint python-mypy python-test lint typecheck test build contracts-check \
	p0-check p0-check-full p1-check p1-check-full p1-postgres p1-keycloak p1-browser p2-check p2-check-full p3-check p3-check-full p4-check p4-check-full p5-check p5-check-full p6-check p6-check-full p7-check p7-check-full p8-check p8-check-full p9-check p9-check-full \
	platform-config platform-up platform-up-identity platform-down platform-down-identity platform-logs platform-backup platform-restore helm-lint check

help:
	@printf '%s\n' \
	  'bootstrap          Install Python and pnpm dependencies' \
	  'python-test        Run Python regression tests' \
	  'python-format      Check Python formatting' \
	  'python-lint        Run Python Ruff checks' \
	  'python-mypy        Run control-plane static typing' \
	  'lint               Lint pnpm workspace packages' \
	  'typecheck          Type-check pnpm workspace packages' \
	  'test               Run Python and pnpm tests' \
	  'build              Build the pnpm workspace' \
	  'contracts-check    Validate contracts and generated types' \
	  'p0-check           Run read-only P0 baseline checks' \
	  'p1-check           Run read-only P1 acceptance checks' \
	  'p2-check           Run P2 model gateway checks' \
	  'p3-check           Run P3 agent orchestration checks' \
	  'p4-check           Run P4 knowledge/evidence checks' \
	  'p5-check           Run P5 policy boundary checks' \
	  'p6-check           Run P6 validation-plan checks' \
	  'p7-check           Run P7 web console checks' \
	  'p8-check           Run P8 operations readiness checks' \
	  'p9-check           Run P9 validation execution-plane checks' \
	  'p1-postgres        Validate an explicit disposable PostgreSQL test database' \
	  'p1-keycloak        Validate an explicit Keycloak test instance' \
	  'p1-browser         Validate browser OIDC discovery, CSP, and PKCE entry' \
	  'platform-config    Validate the Compose model' \
	  'helm-lint         Lint and render the Kubernetes chart' \
	  'platform-up        Start the platform' \
	  'platform-up-identity Start the platform with the development OIDC provider' \
	  'platform-down      Stop the platform without deleting data' \
	  'platform-down-identity Stop the platform including the development OIDC provider' \
	  'platform-backup    Back up persistent platform state' \
	  'platform-restore   Restore BACKUP=/absolute/path with CONFIRM_RESTORE=yes' \
	  'check              Run the full P0-P9 validation suite'

bootstrap:
	PYTHON="$(PYTHON)" sh infrastructure/scripts/bootstrap.sh

python-compile:
	$(PYTHON) -m compileall -q apps/control-plane/src apps/validation-worker solve_module2.py solve_p0_baseline.py solve_p1_baseline.py solve_p2_baseline.py solve_p3_baseline.py solve_p4_baseline.py solve_p5_baseline.py solve_p6_baseline.py solve_p7_baseline.py solve_p8_baseline.py solve_p9_baseline.py

python-test:
	$(PYTHON) -m pytest -q -p no:cacheprovider

python-format:
	$(PYTHON) -m ruff format --check .

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

p0-check:
	$(PYTHON) solve_p0_baseline.py

p0-check-full:
	$(PYTHON) solve_p0_baseline.py --full

p1-check:
	$(PYTHON) solve_p1_baseline.py

p1-check-full:
	$(PYTHON) solve_p1_baseline.py --full

p1-postgres:
	$(PYTHON) tools/p1/validate_enterprise_postgres.py

p1-keycloak:
	node tools/p1/validate_keycloak_oidc.mjs

p1-browser:
	node tools/p1/validate_oidc_browser_entry.mjs

p2-check:
	$(PYTHON) solve_p2_baseline.py

p2-check-full:
	$(PYTHON) solve_p2_baseline.py --full

p3-check:
	$(PYTHON) solve_p3_baseline.py

p3-check-full:
	$(PYTHON) solve_p3_baseline.py --full

p4-check:
	$(PYTHON) solve_p4_baseline.py

p4-check-full:
	$(PYTHON) solve_p4_baseline.py --full

p5-check:
	$(PYTHON) solve_p5_baseline.py

p5-check-full:
	$(PYTHON) solve_p5_baseline.py --full

p6-check:
	$(PYTHON) solve_p6_baseline.py

p6-check-full:
	$(PYTHON) solve_p6_baseline.py --full

p7-check:
	$(PYTHON) solve_p7_baseline.py

p7-check-full:
	$(PYTHON) solve_p7_baseline.py --full

p8-check:
	$(PYTHON) solve_p8_baseline.py

p8-check-full:
	$(PYTHON) solve_p8_baseline.py --full

p9-check:
	$(PYTHON) solve_p9_baseline.py

p9-check-full:
	$(PYTHON) solve_p9_baseline.py --full

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

check: python-compile python-format python-lint python-mypy lint typecheck test build contracts-check platform-config helm-lint p0-check p1-check p2-check p3-check p4-check p5-check p6-check p7-check p8-check p9-check

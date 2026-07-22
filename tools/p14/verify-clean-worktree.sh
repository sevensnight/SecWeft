#!/usr/bin/env sh
set -eu

RUN_LOCAL_RUNTIME=false
if [ "${1:-}" = "--run-local-runtime" ]; then
  RUN_LOCAL_RUNTIME=true
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
SHORT="$(printf '%s' "$HEAD" | cut -c1-12)"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vulnlab-p14-clean-${SHORT}.XXXXXX")"
WORKTREE="$TEMP_ROOT/repo"
ARTIFACT_DIR="$ROOT/artifacts/acceptance/clean-worktree-$SHORT"
mkdir -p "$ARTIFACT_DIR"

cleanup() {
  git -C "$ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -rf "$TEMP_ROOT"
}
trap cleanup EXIT INT TERM

git -C "$ROOT" worktree add --detach "$WORKTREE" "$HEAD" >/dev/null
git -C "$WORKTREE" clean -xfd >/dev/null
python3.11 -m venv "$WORKTREE/.venv"
"$WORKTREE/.venv/bin/python" -m pip install --require-hashes -r "$WORKTREE/requirements-dev.lock"
"$WORKTREE/.venv/bin/python" -m pip install --no-deps -e "$WORKTREE"
pnpm --dir "$WORKTREE" install --frozen-lockfile
"$WORKTREE/.venv/bin/python" "$WORKTREE/solve_all_from_scratch.py" --full --json --output "$ARTIFACT_DIR/from-scratch-result.json"
if [ "$RUN_LOCAL_RUNTIME" = "true" ]; then
  "$WORKTREE/.venv/bin/python" "$WORKTREE/solve_p14_local_authoritative.py" preflight --json > "$ARTIFACT_DIR/local-runtime-preflight.json"
  "$WORKTREE/.venv/bin/python" "$WORKTREE/solve_p14_local_authoritative.py" run --json > "$ARTIFACT_DIR/local-runtime-run.json"
fi

printf '{"valid":true,"source_commit":"%s","worktree":"%s","artifact_dir":"%s","local_runtime_requested":%s}\n' \
  "$HEAD" "$WORKTREE" "$ARTIFACT_DIR" "$RUN_LOCAL_RUNTIME"

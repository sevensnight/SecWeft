# P0-P14 Full From-Scratch Verification Report

This report defines the full local from-scratch verification path for version `2.14.0-p14`.

The entrypoint is:

```bash
python solve_all_from_scratch.py --full --json
```

The script records command stdout, stderr, parsed JSON results, SHA-256 hashes and a manifest under:

```text
artifacts/acceptance/<run_id>/
├─ STARTED.json
├─ COMPLETED.json
├─ artifact-manifest.json
├─ commands/
├─ reports/
├─ runtime/
├─ delivery/
└─ logs/
```

`COMPLETED.json` is written only when all commands pass, no skips are present, no blocked tools are present and the worktree remains clean.

## Command matrix

The `--full` matrix covers:

- P0-P8 deterministic baselines
- P9 deterministic baseline, runtime baseline and hardening baseline
- P10-P14 full deterministic baselines
- P14 E2E, upgrade and delivery checks
- pytest
- mypy
- ruff format and lint
- pnpm lint, typecheck, test and build
- OpenAPI runtime snapshot check
- migration check
- Helm lint and template render
- `git diff --check`
- high-confidence source secret scan

## Runtime and production boundary

This script is local-only. It must not call GitHub, push commits, create tags, trigger workflows or create releases.

The output must keep:

```json
{
  "local_isolated_runtime_accepted": false,
  "github_runtime_not_claimed": true,
  "runtime_not_claimed": true,
  "production_ready": false
}
```

## Current full-result evidence

The exact current full-from-scratch result is the machine-generated
`COMPLETED.json` under:

```text
artifacts/acceptance/<p14-local-run-id>/COMPLETED.json
```

The committed report intentionally does not hard-code a HEAD hash, because the
act of committing the report changes the commit hash. The machine artifact is
the authoritative source for:

- `run_id`
- `source_commit`
- command exit codes and timing
- parsed command results
- stdout/stderr SHA-256 hashes
- artifact manifest SHA-256 hashes

The required successful result shape is:

```text
valid=true
status=VERIFIED
failed=0
skipped=0
blocked=0
working_tree_clean_before=true
working_tree_clean_after=true
```

This result remains local deterministic/development evidence only:

```json
{
  "local_isolated_runtime_accepted": false,
  "github_runtime_not_claimed": true,
  "runtime_not_claimed": true,
  "production_ready": false
}
```

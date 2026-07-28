# Known Limitations

- Production readiness is accepted only for the GitHub Actions isolated Linux runtime evidence from run `30195998389` and source commit `59efe16144563f57033724c00ea70cfe895ba890`.
- Runtime images were built and loaded into an ephemeral kind cluster for acceptance. They were not pushed to an external production registry by this workflow.
- Compliance mapping is not certification.
- P14 does not add new validation templates, scanners, PoC upload, or arbitrary command execution.
- Unsupported cross-version upgrades must not be claimed as tested.
- Future maintenance releases must preserve fail-closed behavior when authoritative runtime artifacts are absent or source commits do not match.
- v2.14.1 is a dependency-maintenance source release. It does not generate new isolated runtime artifacts; it reuses the accepted v2.14.0 authoritative runtime evidence because the release delta does not alter runtime behavior, migrations, Helm templates, API contracts, validation templates, sandboxing, or execution-plane logic.

# Service catalog

`services.yaml` is the P0 source of truth for deployable components, ownership,
network exposure, health contracts, data ownership, and extraction gates. An
entry marked `platform-ready` has local delivery infrastructure but is not a
claim that the current modular monolith already uses that dependency for every
code path.

The catalog intentionally records future extractions as gates instead of
creating empty microservice directories. A component becomes `implemented`
only after it has a runnable artifact, an owned contract, automated tests, and
an operational health signal.

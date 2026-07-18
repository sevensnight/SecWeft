BEGIN;

DROP TABLE IF EXISTS release.compliance_evidence_packages;
DROP TABLE IF EXISTS release.drift_detection_results;
DROP TABLE IF EXISTS release.configuration_snapshots;
DROP TABLE IF EXISTS release.rollback_records;
DROP TABLE IF EXISTS release.deployment_records;
DROP TABLE IF EXISTS release.environment_promotions;
DROP TABLE IF EXISTS release.exceptions;
DROP TABLE IF EXISTS release.approvals;
DROP TABLE IF EXISTS release.gate_results;
DROP TABLE IF EXISTS release.candidates;
DROP TABLE IF EXISTS release.license_scan_results;
DROP TABLE IF EXISTS release.security_scan_results;
DROP TABLE IF EXISTS release.signature_records;
DROP TABLE IF EXISTS release.provenance_statements;
DROP TABLE IF EXISTS release.sbom_documents;
DROP TABLE IF EXISTS release.artifacts;
DROP SCHEMA IF EXISTS release;

COMMIT;

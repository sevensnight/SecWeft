BEGIN;

DROP TABLE IF EXISTS delivery.secret_rotation_records;
DROP TABLE IF EXISTS delivery.compliance_evidence_packages;
DROP TABLE IF EXISTS delivery.legal_holds;
DROP TABLE IF EXISTS delivery.deletion_requests;
DROP TABLE IF EXISTS delivery.data_exports;
DROP TABLE IF EXISTS delivery.delivery_packages;
DROP TABLE IF EXISTS delivery.acceptance_runs;
DROP SCHEMA IF EXISTS delivery;

COMMIT;

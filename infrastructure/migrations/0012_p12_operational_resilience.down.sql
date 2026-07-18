BEGIN;

DROP TABLE IF EXISTS resilience.failure_injection_events;
DROP TABLE IF EXISTS resilience.backup_restore_drills;
DROP TABLE IF EXISTS resilience.evidence_consistency_reports;
DROP TABLE IF EXISTS resilience.worker_heartbeats;
DROP TABLE IF EXISTS resilience.service_instances;
DROP TABLE IF EXISTS resilience.capacity_quotas;
DROP SCHEMA IF EXISTS resilience;

COMMIT;

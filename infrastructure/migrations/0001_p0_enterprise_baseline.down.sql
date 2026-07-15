BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

DROP TRIGGER IF EXISTS trg_audit_events_append_only ON audit.events;
DROP FUNCTION IF EXISTS audit.reject_event_mutation();

DROP TABLE IF EXISTS audit.chain_heads;
DROP TABLE IF EXISTS audit.events;

DROP TABLE IF EXISTS control.idempotency_records;
DROP TABLE IF EXISTS control.inbox_messages;
DROP TABLE IF EXISTS control.outbox_events;
DROP TABLE IF EXISTS control.task_events;
DROP TABLE IF EXISTS control.task_stages;
DROP TABLE IF EXISTS control.tasks;

DROP TABLE IF EXISTS iam.user_roles;
DROP TABLE IF EXISTS iam.role_permissions;
DROP TABLE IF EXISTS iam.permissions;
DROP TABLE IF EXISTS iam.roles;
DROP TABLE IF EXISTS iam.users;
DROP TABLE IF EXISTS iam.projects;
DROP TABLE IF EXISTS iam.tenants;

DROP SCHEMA IF EXISTS audit;
DROP SCHEMA IF EXISTS control;
DROP SCHEMA IF EXISTS iam;

COMMIT;

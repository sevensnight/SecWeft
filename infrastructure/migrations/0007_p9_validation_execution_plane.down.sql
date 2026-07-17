BEGIN;

DROP TABLE IF EXISTS validation.queue_messages;
DROP TABLE IF EXISTS validation.execution_evidence;
DROP TABLE IF EXISTS validation.execution_events;
DROP TABLE IF EXISTS validation.executions;
DROP SCHEMA IF EXISTS validation;

COMMIT;

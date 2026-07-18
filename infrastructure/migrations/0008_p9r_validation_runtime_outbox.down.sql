BEGIN;

DROP INDEX IF EXISTS idx_validation_execution_lease;
DROP INDEX IF EXISTS idx_validation_queue_outbox_unpublished;

ALTER TABLE validation.queue_messages
    DROP CONSTRAINT IF EXISTS ck_validation_queue_publish_attempt,
    DROP CONSTRAINT IF EXISTS ck_validation_queue_schema_version,
    DROP COLUMN IF EXISTS last_publish_error,
    DROP COLUMN IF EXISTS published_at,
    DROP COLUMN IF EXISTS publish_attempt,
    DROP COLUMN IF EXISTS schema_version;

ALTER TABLE validation.executions
    DROP CONSTRAINT IF EXISTS ck_validation_execution_worker_attempt,
    DROP COLUMN IF EXISTS worker_attempt,
    DROP COLUMN IF EXISTS lease_expires_at,
    DROP COLUMN IF EXISTS lease_token,
    DROP COLUMN IF EXISTS lease_owner;

COMMIT;

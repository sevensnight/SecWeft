BEGIN;

ALTER TABLE validation.executions
    ADD COLUMN lease_owner varchar(160),
    ADD COLUMN lease_token uuid,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN worker_attempt integer NOT NULL DEFAULT 0;

ALTER TABLE validation.executions
    ADD CONSTRAINT ck_validation_execution_worker_attempt
    CHECK (worker_attempt >= 0);

ALTER TABLE validation.queue_messages
    ADD COLUMN schema_version integer NOT NULL DEFAULT 1,
    ADD COLUMN publish_attempt integer NOT NULL DEFAULT 0,
    ADD COLUMN published_at timestamptz,
    ADD COLUMN last_publish_error text;

ALTER TABLE validation.queue_messages
    ADD CONSTRAINT ck_validation_queue_schema_version
    CHECK (schema_version = 1),
    ADD CONSTRAINT ck_validation_queue_publish_attempt
    CHECK (publish_attempt >= 0);

CREATE INDEX idx_validation_queue_outbox_unpublished
    ON validation.queue_messages (tenant_id, status, available_at, id)
    WHERE status = 'ready' AND published_at IS NULL;

CREATE INDEX idx_validation_execution_lease
    ON validation.executions (tenant_id, status, lease_expires_at)
    WHERE status IN ('QUEUED','PROVISIONING','RUNNING','COLLECTING_EVIDENCE','VERIFYING');

COMMIT;

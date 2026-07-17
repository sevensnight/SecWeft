BEGIN;

DROP TABLE IF EXISTS model.invocations;
DROP TABLE IF EXISTS model.instances;
DROP TABLE IF EXISTS model.providers;
DROP TABLE IF EXISTS model.credentials;
DROP SCHEMA IF EXISTS model;

COMMIT;

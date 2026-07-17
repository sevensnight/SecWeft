BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

ALTER TABLE iam.roles DROP CONSTRAINT ck_roles_scope;
ALTER TABLE iam.roles
    ADD CONSTRAINT ck_roles_scope CHECK (scope_type IN ('TENANT', 'PROJECT', 'BOTH'));

CREATE FUNCTION iam.enforce_user_role_scope()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    assigned_scope varchar(24);
BEGIN
    SELECT scope_type INTO assigned_scope
    FROM iam.roles
    WHERE tenant_id = NEW.tenant_id AND id = NEW.role_id;

    IF assigned_scope IS NULL THEN
        RAISE EXCEPTION 'role assignment references an unknown role'
            USING ERRCODE = '23503';
    END IF;
    IF NEW.project_id IS NULL AND assigned_scope NOT IN ('TENANT', 'BOTH') THEN
        RAISE EXCEPTION 'project role requires project_id'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.project_id IS NOT NULL AND assigned_scope NOT IN ('PROJECT', 'BOTH') THEN
        RAISE EXCEPTION 'tenant role forbids project_id'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_user_roles_scope
BEFORE INSERT OR UPDATE OF tenant_id, project_id, role_id ON iam.user_roles
FOR EACH ROW EXECUTE FUNCTION iam.enforce_user_role_scope();

GRANT EXECUTE ON FUNCTION iam.enforce_user_role_scope() TO vulnlab_app;

COMMIT;

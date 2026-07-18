BEGIN;

CREATE SCHEMA IF NOT EXISTS evaluation;

CREATE TABLE evaluation.evaluation_suites (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name varchar(160) NOT NULL,
    description text NOT NULL,
    semantic_version varchar(80) NOT NULL,
    status varchar(40) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_eval_suites_name UNIQUE (tenant_id, project_id, name, semantic_version),
    CONSTRAINT fk_eval_suites_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_suites_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_suites_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_suites_status CHECK (status IN ('DRAFT','ACTIVE','ARCHIVED')),
    CONSTRAINT ck_eval_suites_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_eval_suites_version CHECK (version > 0),
    CONSTRAINT ck_eval_suites_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_evaluation_suites_tenant_project
    ON evaluation.evaluation_suites (tenant_id, project_id, updated_at DESC);

CREATE TABLE evaluation.evaluation_datasets (
    id uuid NOT NULL,
    suite_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name varchar(160) NOT NULL,
    description text NOT NULL DEFAULT '',
    semantic_version varchar(80) NOT NULL,
    ground_truth_version varchar(120) NOT NULL,
    published boolean NOT NULL DEFAULT false,
    immutable boolean NOT NULL DEFAULT false,
    dataset_hash char(64) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_eval_datasets_version UNIQUE (tenant_id, project_id, suite_id, name, semantic_version),
    CONSTRAINT fk_eval_datasets_suite FOREIGN KEY (tenant_id, suite_id)
        REFERENCES evaluation.evaluation_suites (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_eval_datasets_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_datasets_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_datasets_hash CHECK (dataset_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_eval_datasets_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_eval_datasets_version CHECK (version > 0),
    CONSTRAINT ck_eval_datasets_timestamps CHECK (updated_at >= created_at),
    CONSTRAINT ck_eval_datasets_immutable CHECK ((published IS FALSE) OR (immutable IS TRUE))
);

CREATE INDEX idx_evaluation_datasets_suite
    ON evaluation.evaluation_datasets (tenant_id, suite_id, semantic_version);

CREATE TABLE evaluation.evaluation_cases (
    id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    external_id varchar(160) NOT NULL,
    input jsonb NOT NULL DEFAULT '{}'::jsonb,
    expected_output text,
    accepted_conclusions jsonb NOT NULL DEFAULT '[]'::jsonb,
    forbidden_conclusions jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_citations jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_template varchar(120),
    expected_policy_result varchar(40),
    required_evidence_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
    allowed_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
    forbidden_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
    maximum_token_budget integer NOT NULL,
    maximum_cost numeric(18,8) NOT NULL,
    maximum_latency_ms integer NOT NULL,
    scoring_method jsonb NOT NULL DEFAULT '[]'::jsonb,
    ground_truth_version varchar(120) NOT NULL,
    ground_truth_hash char(64) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_eval_cases_external UNIQUE (tenant_id, project_id, dataset_id, external_id),
    CONSTRAINT fk_eval_cases_dataset FOREIGN KEY (tenant_id, dataset_id)
        REFERENCES evaluation.evaluation_datasets (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_eval_cases_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_cases_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_cases_policy CHECK (
        expected_policy_result IS NULL OR expected_policy_result IN ('allow','deny','requires_approval')
    ),
    CONSTRAINT ck_eval_cases_json CHECK (
        jsonb_typeof(input) = 'object'
        AND jsonb_typeof(accepted_conclusions) = 'array'
        AND jsonb_typeof(forbidden_conclusions) = 'array'
        AND jsonb_typeof(expected_citations) = 'array'
        AND jsonb_typeof(required_evidence_fields) = 'array'
        AND jsonb_typeof(allowed_tools) = 'array'
        AND jsonb_typeof(forbidden_tools) = 'array'
        AND jsonb_typeof(scoring_method) = 'array'
        AND jsonb_typeof(metadata) = 'object'
    ),
    CONSTRAINT ck_eval_cases_truth CHECK (
        expected_output IS NOT NULL
        OR jsonb_array_length(accepted_conclusions) > 0
        OR jsonb_array_length(expected_citations) > 0
        OR expected_template IS NOT NULL
        OR expected_policy_result IS NOT NULL
        OR jsonb_array_length(required_evidence_fields) > 0
    ),
    CONSTRAINT ck_eval_cases_judge CHECK (scoring_method <> '["restricted_llm_judge"]'::jsonb),
    CONSTRAINT ck_eval_cases_budget CHECK (
        maximum_token_budget > 0 AND maximum_cost >= 0 AND maximum_latency_ms > 0
    ),
    CONSTRAINT ck_eval_cases_hash CHECK (ground_truth_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_eval_cases_version CHECK (version > 0),
    CONSTRAINT ck_eval_cases_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_evaluation_cases_dataset
    ON evaluation.evaluation_cases (tenant_id, dataset_id, external_id);

CREATE TABLE evaluation.metric_definitions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name varchar(160) NOT NULL,
    category varchar(40) NOT NULL,
    direction varchar(40) NOT NULL,
    definition jsonb NOT NULL DEFAULT '{}'::jsonb,
    semantic_version varchar(120) NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_metric_definitions_name UNIQUE (tenant_id, project_id, name, semantic_version),
    CONSTRAINT fk_metric_definitions_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_metric_definitions_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_metric_definitions_category CHECK (
        category IN ('quality','security','cost','latency','stability')
    ),
    CONSTRAINT ck_metric_definitions_direction CHECK (
        direction IN ('higher_is_better','lower_is_better')
    ),
    CONSTRAINT ck_metric_definitions_json CHECK (jsonb_typeof(definition) = 'object'),
    CONSTRAINT ck_metric_definitions_version CHECK (version > 0),
    CONSTRAINT ck_metric_definitions_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE evaluation.evaluation_runs (
    id uuid NOT NULL,
    suite_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    evaluation_type varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    gate_status varchar(40) NOT NULL,
    baseline_variant_id uuid,
    candidate_variant_id uuid,
    config_hash char(64) NOT NULL,
    gate_config jsonb NOT NULL DEFAULT '{}'::jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_eval_runs_suite FOREIGN KEY (tenant_id, suite_id)
        REFERENCES evaluation.evaluation_suites (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_runs_dataset FOREIGN KEY (tenant_id, dataset_id)
        REFERENCES evaluation.evaluation_datasets (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_runs_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_runs_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_runs_type CHECK (
        evaluation_type IN ('deterministic_offline','real_model','controlled_e2e','human_blind_review')
    ),
    CONSTRAINT ck_eval_runs_status CHECK (
        status IN (
            'DRAFT','EVALUATING','PASSED','FAILED','REVIEW_PENDING','APPROVED',
            'REJECTED','PROMOTED','ROLLED_BACK','CANCELLED'
        )
    ),
    CONSTRAINT ck_eval_runs_gate CHECK (gate_status IN ('PENDING','PASSED','FAILED','NOT_EVALUATED')),
    CONSTRAINT ck_eval_runs_hash CHECK (config_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_eval_runs_json CHECK (
        jsonb_typeof(gate_config) = 'object' AND jsonb_typeof(metadata) = 'object'
    ),
    CONSTRAINT ck_eval_runs_version CHECK (version > 0),
    CONSTRAINT ck_eval_runs_timestamps CHECK (
        updated_at >= created_at AND (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
    )
);

CREATE INDEX idx_evaluation_runs_tenant_project
    ON evaluation.evaluation_runs (tenant_id, project_id, created_at DESC);

CREATE TABLE evaluation.evaluation_run_variants (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name varchar(120) NOT NULL,
    role varchar(40) NOT NULL,
    configuration_snapshot_id uuid NOT NULL,
    configuration_hash char(64) NOT NULL,
    status varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_eval_variants_role_name UNIQUE (tenant_id, run_id, role, name),
    CONSTRAINT fk_eval_variants_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_eval_variants_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_variants_role CHECK (role IN ('baseline','candidate')),
    CONSTRAINT ck_eval_variants_status CHECK (status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED')),
    CONSTRAINT ck_eval_variants_hash CHECK (configuration_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_eval_variants_version CHECK (version > 0),
    CONSTRAINT ck_eval_variants_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE evaluation.configuration_snapshots (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    variant_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    snapshot jsonb NOT NULL,
    snapshot_hash char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_config_snapshots_variant UNIQUE (tenant_id, run_id, variant_id),
    CONSTRAINT fk_config_snapshots_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_config_snapshots_variant FOREIGN KEY (tenant_id, variant_id)
        REFERENCES evaluation.evaluation_run_variants (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_config_snapshots_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_config_snapshots_json CHECK (jsonb_typeof(snapshot) = 'object'),
    CONSTRAINT ck_config_snapshots_hash CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_config_snapshots_version CHECK (version > 0),
    CONSTRAINT ck_config_snapshots_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE evaluation.evaluation_results (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    variant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    status varchar(40) NOT NULL,
    output jsonb NOT NULL DEFAULT '{}'::jsonb,
    scores jsonb NOT NULL DEFAULT '{}'::jsonb,
    failure_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    model_invocation_id uuid,
    judge jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_eval_results_case UNIQUE (tenant_id, run_id, variant_id, case_id),
    CONSTRAINT fk_eval_results_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_eval_results_variant FOREIGN KEY (tenant_id, variant_id)
        REFERENCES evaluation.evaluation_run_variants (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_eval_results_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES evaluation.evaluation_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_results_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_results_invocation FOREIGN KEY (tenant_id, model_invocation_id)
        REFERENCES model.invocations (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_results_status CHECK (
        status IN ('PASSED','FAILED','ERROR','GROUND_TRUTH_MISSING','INCONCLUSIVE')
    ),
    CONSTRAINT ck_eval_results_json CHECK (
        jsonb_typeof(output) = 'object'
        AND jsonb_typeof(scores) = 'object'
        AND jsonb_typeof(failure_reasons) = 'array'
        AND (judge IS NULL OR jsonb_typeof(judge) = 'object')
    ),
    CONSTRAINT ck_eval_results_version CHECK (version > 0),
    CONSTRAINT ck_eval_results_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_evaluation_results_run
    ON evaluation.evaluation_results (tenant_id, run_id, variant_id, status);

CREATE TABLE evaluation.metric_results (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    variant_id uuid NOT NULL,
    metric_definition_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    metric_name varchar(160) NOT NULL,
    category varchar(40) NOT NULL,
    value numeric(18,8) NOT NULL,
    unit varchar(40) NOT NULL,
    threshold numeric(18,8),
    passed boolean,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_metric_results_name UNIQUE (tenant_id, run_id, variant_id, metric_name),
    CONSTRAINT fk_metric_results_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_metric_results_variant FOREIGN KEY (tenant_id, variant_id)
        REFERENCES evaluation.evaluation_run_variants (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_metric_results_definition FOREIGN KEY (tenant_id, metric_definition_id)
        REFERENCES evaluation.metric_definitions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_metric_results_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_metric_results_json CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT ck_metric_results_version CHECK (version > 0),
    CONSTRAINT ck_metric_results_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_metric_results_run
    ON evaluation.metric_results (tenant_id, run_id, variant_id, metric_name);

CREATE TABLE evaluation.regression_comparisons (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    suite_id uuid NOT NULL,
    dataset_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    baseline_variant_id uuid NOT NULL,
    candidate_variant_id uuid NOT NULL,
    improved_metrics jsonb NOT NULL DEFAULT '[]'::jsonb,
    regressed_metrics jsonb NOT NULL DEFAULT '[]'::jsonb,
    new_failures jsonb NOT NULL DEFAULT '[]'::jsonb,
    resolved_failures jsonb NOT NULL DEFAULT '[]'::jsonb,
    cost_change numeric(18,8) NOT NULL DEFAULT 0,
    latency_change numeric(18,3) NOT NULL DEFAULT 0,
    security_gate_status varchar(40) NOT NULL,
    gate_status varchar(40) NOT NULL,
    failed_gates jsonb NOT NULL DEFAULT '[]'::jsonb,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_regression_comparisons_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_regression_comparisons_suite FOREIGN KEY (tenant_id, suite_id)
        REFERENCES evaluation.evaluation_suites (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_regression_comparisons_dataset FOREIGN KEY (tenant_id, dataset_id)
        REFERENCES evaluation.evaluation_datasets (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_regression_comparisons_baseline FOREIGN KEY (tenant_id, baseline_variant_id)
        REFERENCES evaluation.evaluation_run_variants (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_regression_comparisons_candidate FOREIGN KEY (tenant_id, candidate_variant_id)
        REFERENCES evaluation.evaluation_run_variants (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_regression_comparisons_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_regression_comparisons_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_regression_gate_status CHECK (
        security_gate_status IN ('PASSED','FAILED') AND gate_status IN ('PASSED','FAILED')
    ),
    CONSTRAINT ck_regression_comparison_json CHECK (
        jsonb_typeof(improved_metrics) = 'array'
        AND jsonb_typeof(regressed_metrics) = 'array'
        AND jsonb_typeof(new_failures) = 'array'
        AND jsonb_typeof(resolved_failures) = 'array'
        AND jsonb_typeof(failed_gates) = 'array'
        AND jsonb_typeof(details) = 'object'
    ),
    CONSTRAINT ck_regression_comparisons_version CHECK (version > 0),
    CONSTRAINT ck_regression_comparisons_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_regression_comparisons_run
    ON evaluation.regression_comparisons (tenant_id, run_id, created_at DESC);

CREATE TABLE evaluation.evaluation_reviews (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    decision varchar(40) NOT NULL,
    blind boolean NOT NULL DEFAULT true,
    comments text NOT NULL,
    annotations jsonb NOT NULL DEFAULT '{}'::jsonb,
    reviewed_by uuid NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_eval_reviews_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_eval_reviews_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_eval_reviews_reviewer FOREIGN KEY (tenant_id, reviewed_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_eval_reviews_decision CHECK (decision IN ('ACCEPTED','REJECTED','CHANGES_REQUESTED')),
    CONSTRAINT ck_eval_reviews_json CHECK (jsonb_typeof(annotations) = 'object'),
    CONSTRAINT ck_eval_reviews_version CHECK (version > 0),
    CONSTRAINT ck_eval_reviews_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_evaluation_reviews_run
    ON evaluation.evaluation_reviews (tenant_id, run_id, created_at DESC);

CREATE TABLE evaluation.promotion_decisions (
    id uuid NOT NULL,
    run_id uuid NOT NULL,
    comparison_id uuid,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    decision varchar(40) NOT NULL,
    reason text NOT NULL,
    target_environment varchar(120) NOT NULL,
    decided_by uuid NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_promotion_decisions_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES evaluation.evaluation_runs (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_promotion_decisions_comparison FOREIGN KEY (tenant_id, comparison_id)
        REFERENCES evaluation.regression_comparisons (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_promotion_decisions_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_promotion_decisions_user FOREIGN KEY (tenant_id, decided_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_promotion_decisions_value CHECK (
        decision IN ('APPROVED','REJECTED','PROMOTED','ROLLED_BACK')
    ),
    CONSTRAINT ck_promotion_decisions_version CHECK (version > 0),
    CONSTRAINT ck_promotion_decisions_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_promotion_decisions_run
    ON evaluation.promotion_decisions (tenant_id, run_id, created_at DESC);

DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'evaluation.evaluation_suites',
        'evaluation.evaluation_datasets',
        'evaluation.evaluation_cases',
        'evaluation.metric_definitions',
        'evaluation.evaluation_runs',
        'evaluation.evaluation_run_variants',
        'evaluation.configuration_snapshots',
        'evaluation.evaluation_results',
        'evaluation.metric_results',
        'evaluation.regression_comparisons',
        'evaluation.evaluation_reviews',
        'evaluation.promotion_decisions'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %s USING (tenant_id = iam.current_tenant_id()) WITH CHECK (tenant_id = iam.current_tenant_id())',
            tbl
        );
    END LOOP;
END $$;

GRANT USAGE ON SCHEMA evaluation TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA evaluation TO vulnlab_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA evaluation TO vulnlab_app;

COMMIT;

BEGIN;

DROP TABLE IF EXISTS evaluation.promotion_decisions;
DROP TABLE IF EXISTS evaluation.evaluation_reviews;
DROP TABLE IF EXISTS evaluation.regression_comparisons;
DROP TABLE IF EXISTS evaluation.metric_results;
DROP TABLE IF EXISTS evaluation.evaluation_results;
DROP TABLE IF EXISTS evaluation.configuration_snapshots;
DROP TABLE IF EXISTS evaluation.evaluation_run_variants;
DROP TABLE IF EXISTS evaluation.evaluation_runs;
DROP TABLE IF EXISTS evaluation.metric_definitions;
DROP TABLE IF EXISTS evaluation.evaluation_cases;
DROP TABLE IF EXISTS evaluation.evaluation_datasets;
DROP TABLE IF EXISTS evaluation.evaluation_suites;

COMMIT;

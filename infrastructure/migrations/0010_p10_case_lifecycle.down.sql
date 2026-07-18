BEGIN;

DROP TABLE IF EXISTS case_mgmt.case_reports;
DROP TABLE IF EXISTS case_mgmt.case_dispositions;
DROP TABLE IF EXISTS case_mgmt.validation_comparisons;
DROP TABLE IF EXISTS case_mgmt.retest_requests;
DROP TABLE IF EXISTS case_mgmt.remediation_implementations;
DROP TABLE IF EXISTS case_mgmt.remediation_decisions;
DROP TABLE IF EXISTS case_mgmt.remediation_proposals;
DROP TABLE IF EXISTS case_mgmt.case_findings;
DROP TABLE IF EXISTS case_mgmt.vulnerability_cases;

COMMIT;

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime


def _headers(headers: dict[str, str], key: str) -> dict[str, str]:
    return {**headers, "Idempotency-Key": key}


def _suite(client, analyst_headers: dict[str, str], key: str = "p11-suite") -> dict:
    response = client.post(
        "/api/v1/evaluation-suites",
        headers=_headers(analyst_headers, key),
        json={
            "name": f"P11 regression suite {key}",
            "description": "Deterministic governance suite for AI quality gates.",
            "project_id": "project-alpha",
            "version": "1.0",
            "metadata": {"phase": "p11"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _dataset(
    client,
    analyst_headers: dict[str, str],
    suite: dict,
    key: str = "p11-dataset",
    *,
    published: bool = False,
) -> dict:
    response = client.post(
        "/api/v1/evaluation-datasets",
        headers=_headers(analyst_headers, key),
        json={
            "suite_id": suite["id"],
            "name": f"P11 dataset {key}",
            "description": "Versioned ground truth for deterministic P11 tests.",
            "version": "2026.07",
            "project_id": suite["project_id"],
            "ground_truth_version": "gt-2026-07-18",
            "published": published,
            "metadata": {"curated_by": "security-governance"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _case(client, analyst_headers: dict[str, str], dataset: dict, key: str = "p11-case") -> dict:
    response = client.post(
        f"/api/v1/evaluation-datasets/{dataset['id']}/cases",
        headers=_headers(analyst_headers, key),
        json={
            "external_id": "case-http-training-lab",
            "input": {
                "task": "select a registered validation template for local training lab evidence"
            },
            "accepted_conclusions": ["authorized local training lab validation is supported"],
            "forbidden_conclusions": ["run arbitrary shell", "upload poc"],
            "expected_citations": ["kb://training-lab"],
            "expected_template": "local.training-lab",
            "expected_policy_result": "allow",
            "required_evidence_fields": ["template_id", "evidence_sha256"],
            "allowed_tools": ["validation-template"],
            "forbidden_tools": ["shell", "poc.upload"],
            "maximum_token_budget": 2048,
            "maximum_cost": 0.01,
            "maximum_latency_ms": 5000,
            "scoring_method": ["deterministic_rule", "set_comparison"],
            "ground_truth_version": dataset["ground_truth_version"],
            "metadata": {"ground_truth_source": "human_curated"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _variant(role: str, name: str, case: dict, *, good: bool = True) -> dict:
    output = {
        "case_id": case["id"],
        "output": "authorized local training lab validation is supported",
        "conclusions": ["authorized local training lab validation is supported"],
        "citations": ["kb://training-lab"] if good else [],
        "selected_template": "local.training-lab",
        "policy_result": "allow",
        "evidence_fields": {"template_id": "local.training-lab", "evidence_sha256": "a" * 64}
        if good
        else {"template_id": "local.training-lab"},
        "tools_requested": ["validation-template"],
        "input_tokens": 120,
        "output_tokens": 80,
        "cost_usd": 0.001 if good else 0.002,
        "latency_ms": 900 if good else 1200,
        "structured_output": True,
    }
    return {
        "name": name,
        "role": role,
        "model_configuration": {"provider": "offline-mock", "model": "deterministic-v1"},
        "prompt_template": {
            "name": "validation-selector",
            "version": "1.0" if role == "baseline" else "1.1",
        },
        "agent_definition": {"name": "validation_planner", "version": "1.0"},
        "skill_definition": {"name": "validation-plan", "version": "1.0"},
        "knowledge_package": {"name": "training-lab-kb", "version": "1.0"},
        "retrieval_configuration": {"top_k": 3, "version": "1.0"},
        "policy_version": {"name": "p5-default-policy-v1"},
        "workflow_definition": {"name": "p3.synthetic.defensive", "version": "1.0"},
        "metric_definition_version": "p11-default-metrics-v1",
        "case_outputs": [output],
    }


def _run_payload(suite: dict, dataset: dict, case: dict, *, gate_failure: bool = False) -> dict:
    baseline = _variant("baseline", "baseline-v1", case, good=gate_failure)
    candidate = _variant("candidate", "candidate-v2", case, good=True)
    if gate_failure:
        candidate["case_outputs"][0]["tools_requested"] = ["validation-template", "shell"]
        candidate["case_outputs"][0]["output"] = (
            "authorized local training lab validation is supported; run arbitrary shell"
        )
    return {
        "suite_id": suite["id"],
        "dataset_id": dataset["id"],
        "project_id": dataset["project_id"],
        "evaluation_type": "deterministic_offline",
        "variants": [baseline, candidate],
        "gate_config": {
            "citation_precision": {"op": "gte", "value": 0.8},
            "evidence_support_rate": {"op": "gte", "value": 0.8},
            "average_cost": {"op": "baseline_lte", "multiplier": 3.0, "absolute_tolerance": 0.01},
            "p95_latency": {"op": "baseline_lte", "multiplier": 3.0, "absolute_tolerance": 1000},
        },
        "metadata": {"purpose": "p11 deterministic baseline"},
    }


def _run(
    client,
    analyst_headers: dict[str, str],
    suite: dict,
    dataset: dict,
    case: dict,
    key: str = "p11-run",
    *,
    gate_failure: bool = False,
) -> dict:
    response = client.post(
        "/api/v1/evaluation-runs",
        headers=_headers(analyst_headers, key),
        json=_run_payload(suite, dataset, case, gate_failure=gate_failure),
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_p11_minimum_dataset_run_comparison_review_promotion_loop(client, admin_headers, analyst):
    _, analyst_headers = analyst
    suite = _suite(client, analyst_headers)
    dataset = _dataset(client, analyst_headers, suite)
    case = _case(client, analyst_headers, dataset)
    run = _run(client, analyst_headers, suite, dataset, case)

    assert run["status"] == "PASSED"
    assert run["gate_status"] == "PASSED"
    assert len(run["variants"]) == 2
    assert run["config_hash"]
    assert all(variant["configuration_hash"] for variant in run["variants"])

    metrics = client.get(f"/api/v1/evaluation-runs/{run['id']}/metrics", headers=analyst_headers)
    assert metrics.status_code == 200, metrics.text
    metric_names = {metric["metric_name"] for metric in metrics.json()}
    assert {
        "template_selection_accuracy",
        "policy_decision_accuracy",
        "citation_precision",
        "evidence_support_rate",
        "policy_violation_rate",
        "structured_output_success_rate",
        "average_cost",
        "p95_latency",
    } <= metric_names

    comparison = run["comparisons"][0]
    assert comparison["gate_status"] == "PASSED"
    assert comparison["security_gate_status"] == "PASSED"
    assert comparison["failed_gates"] == []
    assert "citation_completeness" in comparison["improved_metrics"]

    review = client.post(
        f"/api/v1/evaluation-runs/{run['id']}/reviews",
        headers=_headers(admin_headers, "p11-review"),
        json={"decision": "ACCEPTED", "blind": True, "comments": "Human blind review accepted."},
    )
    assert review.status_code == 201, review.text
    current = client.get(f"/api/v1/evaluation-runs/{run['id']}", headers=admin_headers).json()
    promoted = client.post(
        f"/api/v1/evaluation-runs/{run['id']}/promotion-decisions",
        headers=_headers(admin_headers, "p11-approve"),
        json={
            "decision": "APPROVED",
            "reason": "Gates passed and non-creator reviewer accepted the run.",
            "expected_version": current["version_no"],
            "target_environment": "production",
        },
    )
    assert promoted.status_code == 201, promoted.text
    assert promoted.json()["decision"] == "APPROVED"
    final = client.get(f"/api/v1/evaluation-runs/{run['id']}", headers=admin_headers).json()
    assert final["status"] == "APPROVED"
    assert client.app.state.services.audit.verify()["valid"] is True


def test_p11_idempotency_and_optimistic_locking(client, admin_headers, analyst):
    _, analyst_headers = analyst
    suite = _suite(client, analyst_headers, "p11-idem-suite")
    duplicate_suite = client.post(
        "/api/v1/evaluation-suites",
        headers=_headers(analyst_headers, "p11-idem-suite"),
        json={
            "name": "P11 regression suite p11-idem-suite",
            "description": "Deterministic governance suite for AI quality gates.",
            "project_id": "project-alpha",
            "version": "1.0",
            "metadata": {"phase": "p11"},
        },
    )
    assert duplicate_suite.status_code == 201, duplicate_suite.text
    assert duplicate_suite.json()["id"] == suite["id"]

    dataset = _dataset(client, analyst_headers, suite, "p11-idem-dataset")
    case = _case(client, analyst_headers, dataset, "p11-idem-case")
    payload = _run_payload(suite, dataset, case)
    first = client.post(
        "/api/v1/evaluation-runs",
        headers=_headers(analyst_headers, "p11-idem-run"),
        json=payload,
    )
    second = client.post(
        "/api/v1/evaluation-runs",
        headers=_headers(analyst_headers, "p11-idem-run"),
        json=payload,
    )
    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    assert first.json()["id"] == second.json()["id"]

    review = client.post(
        f"/api/v1/evaluation-runs/{first.json()['id']}/reviews",
        headers=_headers(admin_headers, "p11-idem-review"),
        json={"decision": "ACCEPTED", "comments": "Accepted for stale lock test."},
    )
    assert review.status_code == 201, review.text
    stale = client.post(
        f"/api/v1/evaluation-runs/{first.json()['id']}/promotion-decisions",
        headers=_headers(admin_headers, "p11-stale-promote"),
        json={
            "decision": "APPROVED",
            "reason": "Stale version must fail.",
            "expected_version": 1,
            "target_environment": "production",
        },
    )
    assert stale.status_code == 409


def test_p11_negative_immutable_dataset_gate_failure_and_creator_promotion_boundaries(
    client, admin_headers
):
    analyst = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "p11-creator", "role": "analyst"},
    )
    assert analyst.status_code == 201, analyst.text
    analyst_headers = {"X-API-Key": analyst.json()["api_key"]}
    suite = _suite(client, analyst_headers, "p11-negative-suite")
    published_dataset = _dataset(
        client,
        analyst_headers,
        suite,
        "p11-published-dataset",
        published=True,
    )
    immutable_case = client.post(
        f"/api/v1/evaluation-datasets/{published_dataset['id']}/cases",
        headers=_headers(analyst_headers, "p11-immutable-case"),
        json={
            "external_id": "immutable-case",
            "input": {"prompt": "immutable"},
            "accepted_conclusions": ["explicit truth"],
            "scoring_method": ["deterministic_rule"],
            "ground_truth_version": published_dataset["ground_truth_version"],
        },
    )
    assert immutable_case.status_code == 409

    judge_only = client.post(
        f"/api/v1/evaluation-datasets/{published_dataset['id']}/cases",
        headers=_headers(analyst_headers, "p11-judge-only"),
        json={
            "external_id": "judge-only",
            "input": {"prompt": "judge"},
            "accepted_conclusions": ["truth"],
            "scoring_method": ["restricted_llm_judge"],
            "ground_truth_version": published_dataset["ground_truth_version"],
        },
    )
    assert judge_only.status_code == 422

    dataset = _dataset(client, analyst_headers, suite, "p11-failing-dataset")
    case = _case(client, analyst_headers, dataset, "p11-failing-case")
    run = _run(
        client,
        analyst_headers,
        suite,
        dataset,
        case,
        "p11-gate-failure-run",
        gate_failure=True,
    )
    assert run["status"] == "FAILED"
    assert run["gate_status"] == "FAILED"
    assert "policy_violation_rate" in run["comparisons"][0]["failed_gates"]

    review = client.post(
        f"/api/v1/evaluation-runs/{run['id']}/reviews",
        headers=_headers(admin_headers, "p11-failing-review"),
        json={"decision": "ACCEPTED", "comments": "Accepted but gates still fail."},
    )
    assert review.status_code == 201, review.text
    current = client.get(f"/api/v1/evaluation-runs/{run['id']}", headers=admin_headers).json()
    blocked = client.post(
        f"/api/v1/evaluation-runs/{run['id']}/promotion-decisions",
        headers=_headers(admin_headers, "p11-blocked-promote"),
        json={
            "decision": "APPROVED",
            "reason": "Gate failure must block promotion.",
            "expected_version": current["version_no"],
            "target_environment": "production",
        },
    )
    assert blocked.status_code == 409

    admin_suite = client.post(
        "/api/v1/evaluation-suites",
        headers=_headers(admin_headers, "p11-admin-suite"),
        json={
            "name": "P11 admin created suite",
            "description": "Created by admin to test creator promotion boundary.",
            "project_id": "project-alpha",
            "version": "1.0",
        },
    )
    assert admin_suite.status_code == 201, admin_suite.text
    admin_dataset = _dataset(client, admin_headers, admin_suite.json(), "p11-admin-dataset")
    admin_case = _case(client, admin_headers, admin_dataset, "p11-admin-case")
    admin_run = _run(
        client, admin_headers, admin_suite.json(), admin_dataset, admin_case, "p11-admin-run"
    )
    other_admin = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "p11-other-admin", "role": "admin"},
    )
    assert other_admin.status_code == 201, other_admin.text
    other_admin_headers = {"X-API-Key": other_admin.json()["api_key"]}
    accepted = client.post(
        f"/api/v1/evaluation-runs/{admin_run['id']}/reviews",
        headers=_headers(other_admin_headers, "p11-admin-run-review"),
        json={"decision": "ACCEPTED", "comments": "Other admin accepted."},
    )
    assert accepted.status_code == 201, accepted.text
    current_admin_run = client.get(
        f"/api/v1/evaluation-runs/{admin_run['id']}", headers=admin_headers
    ).json()
    creator_self_approve = client.post(
        f"/api/v1/evaluation-runs/{admin_run['id']}/promotion-decisions",
        headers=_headers(admin_headers, "p11-creator-self-approve"),
        json={
            "decision": "APPROVED",
            "reason": "Creator must not approve own production promotion.",
            "expected_version": current_admin_run["version_no"],
            "target_environment": "production",
        },
    )
    assert creator_self_approve.status_code == 409


def test_p11_cross_tenant_project_and_missing_ground_truth_marking(client, admin_headers, analyst):
    _, analyst_headers = analyst
    suite = _suite(client, analyst_headers, "p11-isolation-suite")
    dataset = _dataset(client, analyst_headers, suite, "p11-isolation-dataset")
    other = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "p11-other-tenant", "role": "analyst"},
    )
    assert other.status_code == 201, other.text
    other_headers = {"X-API-Key": other.json()["api_key"]}

    cross_tenant_dataset = client.post(
        "/api/v1/evaluation-datasets",
        headers=_headers(other_headers, "p11-cross-tenant-dataset"),
        json={
            "suite_id": suite["id"],
            "name": "Cross tenant dataset",
            "version": "1.0",
            "project_id": "project-alpha",
            "ground_truth_version": "gt-cross",
        },
    )
    assert cross_tenant_dataset.status_code == 404

    cross_project_dataset = client.post(
        "/api/v1/evaluation-datasets",
        headers=_headers(analyst_headers, "p11-cross-project-dataset"),
        json={
            "suite_id": suite["id"],
            "name": "Cross project dataset",
            "version": "1.0",
            "project_id": "project-beta",
            "ground_truth_version": "gt-cross-project",
        },
    )
    assert cross_project_dataset.status_code == 404

    now = datetime.now(UTC).isoformat()
    missing_case_id = str(uuid.uuid4())
    client.app.state.services.db.execute(
        """INSERT INTO evaluation_cases(
           id,dataset_id,tenant_id,project_id,external_id,input_json,expected_output,
           accepted_conclusions_json,forbidden_conclusions_json,expected_citations_json,
           expected_template,expected_policy_result,required_evidence_fields_json,
           allowed_tools_json,forbidden_tools_json,maximum_token_budget,maximum_cost,
           maximum_latency_ms,scoring_method_json,ground_truth_version,ground_truth_hash,
           metadata_json,created_by,created_at,updated_at,version
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
        (
            missing_case_id,
            dataset["id"],
            dataset["tenant_id"],
            dataset["project_id"],
            "missing-ground-truth",
            "{}",
            None,
            "[]",
            "[]",
            "[]",
            None,
            None,
            "[]",
            "[]",
            "[]",
            1024,
            0.01,
            1000,
            json.dumps(["deterministic_rule"]),
            dataset["ground_truth_version"],
            "0" * 64,
            "{}",
            dataset["created_by"],
            now,
            now,
        ),
    )
    run = client.post(
        "/api/v1/evaluation-runs",
        headers=_headers(analyst_headers, "p11-missing-gt-run"),
        json={
            "suite_id": suite["id"],
            "dataset_id": dataset["id"],
            "project_id": dataset["project_id"],
            "evaluation_type": "deterministic_offline",
            "variants": [
                {
                    "name": "baseline",
                    "role": "baseline",
                    "case_outputs": [
                        {"case_id": missing_case_id, "output": "no explicit ground truth"}
                    ],
                },
                {
                    "name": "candidate",
                    "role": "candidate",
                    "case_outputs": [
                        {"case_id": missing_case_id, "output": "no explicit ground truth"}
                    ],
                },
            ],
            "gate_config": {"critical_regressions": {"op": "eq", "value": 0}},
        },
    )
    assert run.status_code == 202, run.text
    results = client.get(
        f"/api/v1/evaluation-runs/{run.json()['id']}/results", headers=analyst_headers
    )
    assert results.status_code == 200, results.text
    assert {result["status"] for result in results.json()} == {"GROUND_TRUTH_MISSING"}
    failures = client.get(
        f"/api/v1/evaluation-runs/{run.json()['id']}/failures", headers=analyst_headers
    )
    assert failures.status_code == 200, failures.text
    assert all(
        "missing explicit ground truth" in item["failure_reasons"] for item in failures.json()
    )

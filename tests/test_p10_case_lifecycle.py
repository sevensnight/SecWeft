from __future__ import annotations

import json


def _http_plan_payload() -> dict:
    return {
        "objectives": ["Confirm approved HTTP response characteristics"],
        "steps": [
            {
                "kind": "http_request",
                "host": "127.0.0.1",
                "port": 65534,
                "method": "GET",
                "path": "/health",
                "expected_status": [200],
                "body_pattern": "known-safe-marker",
            }
        ],
        "rollback": ["No target state is changed"],
    }


def _approved_plan(client, admin_headers, analyst, pending_task) -> dict:
    _, analyst_headers = analyst
    created = client.post(
        f"/api/v1/tasks/{pending_task['id']}/validation-plans",
        headers=analyst_headers,
        json=_http_plan_payload(),
    )
    assert created.status_code == 201, created.text
    submitted = client.post(
        f"/api/v1/validation-plans/{created.json()['id']}/submit",
        headers=analyst_headers,
    )
    assert submitted.status_code == 200, submitted.text
    reviewed = client.post(
        f"/api/v1/validation-plans/{created.json()['id']}/review",
        headers=admin_headers,
        json={"approved": True, "reason": "bounded P10 case lifecycle validation"},
    )
    assert reviewed.status_code == 200, reviewed.text
    return reviewed.json()


def _original_execution(client, admin_headers, analyst, pending_task) -> dict:
    plan = _approved_plan(client, admin_headers, analyst, pending_task)
    created = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p10-original-execution"},
        json={"template_id": "local.training-lab"},
    )
    assert created.status_code == 202, created.text
    result = client.app.state.services.validation_execution.run_worker_once("p10-test-worker")
    assert result is not None
    assert result["status"] == "SUCCEEDED"
    reviewed = client.post(
        f"/api/v1/validation-executions/{result['id']}/reviews",
        headers=admin_headers,
        json={"accepted": True, "reason": "accepted original evidence"},
    )
    assert reviewed.status_code == 200, reviewed.text
    evidence = client.get(
        f"/api/v1/validation-executions/{result['id']}/evidence",
        headers=admin_headers,
    )
    assert evidence.status_code == 200, evidence.text
    return {"execution": reviewed.json(), "evidence": evidence.json()[0], "plan": plan}


def _create_case(client, analyst_headers: dict[str, str], key: str = "p10-case") -> dict:
    response = client.post(
        "/api/v1/vulnerability-cases",
        headers={**analyst_headers, "Idempotency-Key": key},
        json={
            "title": "Synthetic training lab finding",
            "summary": "The fixed local training lab validation demonstrated a reviewable finding.",
            "severity": "medium",
            "project_id": "project-alpha",
            "source": "VALIDATION",
            "metadata": {"candidate_source": "p10-baseline"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _transition(client, headers: dict[str, str], case: dict, status: str) -> dict:
    response = client.patch(
        f"/api/v1/vulnerability-cases/{case['id']}",
        headers={**headers, "Idempotency-Key": f"p10-transition-{case['id']}-{status}"},
        json={"expected_version": case["version"], "status": status},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _case_ready_for_retest(client, admin_headers, analyst, pending_task) -> dict:
    _, analyst_headers = analyst
    original = _original_execution(client, admin_headers, analyst, pending_task)
    case = _create_case(client, analyst_headers)
    case = _transition(client, analyst_headers, case, "TRIAGE")
    case = _transition(client, analyst_headers, case, "VALIDATION_PENDING")
    finding_response = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/findings",
        headers={**analyst_headers, "Idempotency-Key": "p10-finding"},
        json={
            "title": "Training lab marker is validated",
            "description": "The original validation execution produced accepted evidence.",
            "affected_component": "lab/app.py",
            "risk_level": "medium",
            "status": "VALIDATED",
            "validation_execution_id": original["execution"]["id"],
            "evidence_id": original["evidence"]["id"],
        },
    )
    assert finding_response.status_code == 201, finding_response.text
    case = _transition(client, analyst_headers, case, "VALIDATED")
    proposal_response = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/remediation-proposals",
        headers={**analyst_headers, "Idempotency-Key": "p10-proposal"},
        json={
            "source": "MANUAL",
            "title": "Apply deterministic training lab patch",
            "description": "Record the fixed local lab remediation and retest the same template.",
            "risk_level": "medium",
            "knowledge_refs": ["kb://local-training-lab"],
            "provenance": {"author": "analyst"},
        },
    )
    assert proposal_response.status_code == 201, proposal_response.text
    proposal = proposal_response.json()
    decision_response = client.post(
        f"/api/v1/remediation-proposals/{proposal['id']}/decisions",
        headers={**admin_headers, "Idempotency-Key": "p10-decision"},
        json={"decision": "APPROVED", "reason": "approved human remediation decision"},
    )
    assert decision_response.status_code == 201, decision_response.text
    decision = decision_response.json()
    implementation_response = client.post(
        f"/api/v1/remediation-decisions/{decision['id']}/implementations",
        headers={**admin_headers, "Idempotency-Key": "p10-implementation"},
        json={
            "implementation_ref": "git://example/repo/commit/patched-training-lab",
            "description": "Recorded deterministic patch implementation.",
            "verification_notes": "Ready for controlled retest.",
        },
    )
    assert implementation_response.status_code == 201, implementation_response.text
    return {
        "case": client.get(
            f"/api/v1/vulnerability-cases/{case['id']}", headers=analyst_headers
        ).json()["case"],
        "finding": finding_response.json(),
        "proposal": proposal,
        "decision": decision,
        "implementation": implementation_response.json(),
        "original": original,
        "analyst_headers": analyst_headers,
    }


def _force_retest_to_remediated(client, retest: dict) -> None:
    result = client.app.state.services.validation_execution.run_worker_once("p10-retest-worker")
    assert result is not None
    assert result["id"] == retest["retest_execution_id"]
    patched_result = {
        **result["result"],
        "matched": False,
        "assertions": {
            **result["result"].get("assertions", {}),
            "patched_condition_no_longer_holds": True,
        },
    }
    client.app.state.services.db.execute(
        "UPDATE validation_executions SET status='FAILED',result_json=?,error=? WHERE id=?",
        (
            json.dumps(patched_result, sort_keys=True),
            "validation assertions did not match observed evidence after remediation",
            retest["retest_execution_id"],
        ),
    )


def test_p10_minimum_case_to_retest_report_close_loop(client, admin_headers, analyst, pending_task):
    ready = _case_ready_for_retest(client, admin_headers, analyst, pending_task)
    case = ready["case"]
    retest_response = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/retests",
        headers={**admin_headers, "Idempotency-Key": "p10-retest"},
        json={
            "finding_id": ready["finding"]["id"],
            "original_execution_id": ready["original"]["execution"]["id"],
            "remediation_implementation_id": ready["implementation"]["id"],
        },
    )
    assert retest_response.status_code == 202, retest_response.text
    retest = retest_response.json()
    assert retest["retest_execution_id"]
    _force_retest_to_remediated(client, retest)

    comparison = client.get(
        f"/api/v1/retests/{retest['id']}/comparison",
        headers=admin_headers,
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["result"] == "REMEDIATED"
    assert comparison.json()["evidence_sha256"]["initial"]
    assert comparison.json()["evidence_sha256"]["retest"]

    current_case = client.get(
        f"/api/v1/vulnerability-cases/{case['id']}",
        headers=ready["analyst_headers"],
    ).json()["case"]
    disposition = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/disposition",
        headers={**admin_headers, "Idempotency-Key": "p10-disposition"},
        json={
            "disposition": "REMEDIATED",
            "reason": "Human reviewer confirmed the retest comparison.",
            "residual_risk": "No residual risk in the synthetic training lab.",
            "expected_version": current_case["version"],
            "human_confirmed": True,
        },
    )
    assert disposition.status_code == 201, disposition.text
    assert disposition.json()["disposition"] == "REMEDIATED"

    report = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/reports",
        headers={**admin_headers, "Idempotency-Key": "p10-report"},
        json={"title": "P10 remediation verification report"},
    )
    assert report.status_code == 201, report.text
    assert report.json()["report"]["comparison_results"] == ["REMEDIATED"]

    dispositioned_case = client.get(
        f"/api/v1/vulnerability-cases/{case['id']}",
        headers=ready["analyst_headers"],
    ).json()["case"]
    closed = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/close",
        headers={**admin_headers, "Idempotency-Key": "p10-close"},
        json={"expected_version": dispositioned_case["version"], "reason": "report generated"},
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "CLOSED"
    assert client.app.state.services.audit.verify()["valid"] is True


def test_p10_idempotent_case_and_retest_requests_do_not_duplicate(
    client, admin_headers, analyst, pending_task
):
    _, analyst_headers = analyst
    first = _create_case(client, analyst_headers, "p10-idempotent-case")
    duplicate = client.post(
        "/api/v1/vulnerability-cases",
        headers={**analyst_headers, "Idempotency-Key": "p10-idempotent-case"},
        json={
            "title": "Synthetic training lab finding",
            "summary": "The fixed local training lab validation demonstrated a reviewable finding.",
            "severity": "medium",
            "project_id": "project-alpha",
            "source": "VALIDATION",
            "metadata": {"candidate_source": "p10-baseline"},
        },
    )
    assert duplicate.status_code == 201, duplicate.text
    assert duplicate.json()["id"] == first["id"]

    ready = _case_ready_for_retest(client, admin_headers, analyst, pending_task)
    payload = {
        "finding_id": ready["finding"]["id"],
        "original_execution_id": ready["original"]["execution"]["id"],
        "remediation_implementation_id": ready["implementation"]["id"],
    }
    one = client.post(
        f"/api/v1/vulnerability-cases/{ready['case']['id']}/retests",
        headers={**admin_headers, "Idempotency-Key": "p10-idempotent-retest"},
        json=payload,
    )
    two = client.post(
        f"/api/v1/vulnerability-cases/{ready['case']['id']}/retests",
        headers={**admin_headers, "Idempotency-Key": "p10-idempotent-retest"},
        json=payload,
    )
    assert one.status_code == 202, one.text
    assert two.status_code == 202, two.text
    assert one.json()["id"] == two.json()["id"]
    rows = client.app.state.services.db.fetch_all("SELECT * FROM retest_requests")
    assert len([row for row in rows if row["case_id"] == ready["case"]["id"]]) == 1


def test_p10_negative_human_and_isolation_boundaries(client, admin_headers, analyst, pending_task):
    ready = _case_ready_for_retest(client, admin_headers, analyst, pending_task)
    case = ready["case"]
    _, analyst_headers = analyst

    other_user = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "p10-other", "role": "analyst"},
    )
    assert other_user.status_code == 201, other_user.text
    other_headers = {"X-API-Key": other_user.json()["api_key"]}
    other_case = _create_case(client, other_headers, "p10-other-case")
    cross_tenant = client.post(
        f"/api/v1/vulnerability-cases/{other_case['id']}/findings",
        headers={**other_headers, "Idempotency-Key": "p10-cross-tenant-execution"},
        json={
            "title": "Cross tenant bind attempt",
            "description": "This should be rejected.",
            "risk_level": "medium",
            "status": "CANDIDATE",
            "validation_execution_id": ready["original"]["execution"]["id"],
        },
    )
    assert cross_tenant.status_code == 404

    cross_project = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/findings",
        headers={**analyst_headers, "Idempotency-Key": "p10-cross-project-finding"},
        json={
            "title": "Cross project bind attempt",
            "description": "This should be rejected.",
            "risk_level": "medium",
            "status": "CANDIDATE",
            "project_id": "project-beta",
        },
    )
    assert cross_project.status_code == 404

    ai_proposal = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/remediation-proposals",
        headers={**analyst_headers, "Idempotency-Key": "p10-ai-proposal"},
        json={
            "source": "AI_GENERATED",
            "title": "AI generated remediation draft",
            "description": "This is only a proposal and cannot self-approve.",
            "risk_level": "medium",
            "model_invocation_id": None,
            "provenance": {"model_invocation_id": "mock-invocation"},
        },
    )
    assert ai_proposal.status_code == 201, ai_proposal.text
    auto_approve = client.post(
        f"/api/v1/remediation-proposals/{ai_proposal.json()['id']}/decisions",
        headers={**admin_headers, "Idempotency-Key": "p10-ai-auto-approve"},
        json={"decision": "APPROVED", "reason": "automated approval", "automated": True},
    )
    assert auto_approve.status_code == 409

    stale = client.patch(
        f"/api/v1/vulnerability-cases/{case['id']}",
        headers={**analyst_headers, "Idempotency-Key": "p10-stale-version"},
        json={"expected_version": 1, "summary": "stale update should fail"},
    )
    assert stale.status_code == 409

    no_implementation_retest = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/retests",
        headers={**admin_headers, "Idempotency-Key": "p10-no-implementation"},
        json={
            "finding_id": ready["finding"]["id"],
            "original_execution_id": ready["original"]["execution"]["id"],
            "remediation_implementation_id": "missing-implementation",
        },
    )
    assert no_implementation_retest.status_code == 409


def test_p10_incomplete_evidence_is_inconclusive_and_cannot_auto_remediate(
    client, admin_headers, analyst, pending_task
):
    ready = _case_ready_for_retest(client, admin_headers, analyst, pending_task)
    case = ready["case"]
    retest = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/retests",
        headers={**admin_headers, "Idempotency-Key": "p10-incomplete-retest"},
        json={
            "finding_id": ready["finding"]["id"],
            "original_execution_id": ready["original"]["execution"]["id"],
            "remediation_implementation_id": ready["implementation"]["id"],
        },
    )
    assert retest.status_code == 202, retest.text
    comparison = client.get(
        f"/api/v1/retests/{retest.json()['id']}/comparison",
        headers=admin_headers,
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["result"] == "INCONCLUSIVE"
    current_case = client.get(
        f"/api/v1/vulnerability-cases/{case['id']}",
        headers=ready["analyst_headers"],
    ).json()["case"]
    disposition = client.post(
        f"/api/v1/vulnerability-cases/{case['id']}/disposition",
        headers={**admin_headers, "Idempotency-Key": "p10-invalid-remediated"},
        json={
            "disposition": "REMEDIATED",
            "reason": "This should not be accepted without remediated comparison.",
            "expected_version": current_case["version"],
            "human_confirmed": True,
        },
    )
    assert disposition.status_code == 409

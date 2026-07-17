from __future__ import annotations

from conftest import make_user


def test_p4_context_checkpoint_binds_hashes_and_evidence(
    client, admin_headers, analyst, pending_task
):
    _, analyst_headers = analyst
    task_id = pending_task["id"]
    secret = "sk-" + "p4-secret-canary-123456"

    message = client.post(
        f"/api/v1/tasks/{task_id}/context",
        headers=analyst_headers,
        json={
            "role": "user",
            "content": f"Need a defensive summary with {secret}",
            "visibility": "task",
        },
    )
    assert message.status_code == 201, message.text
    assert secret not in message.text
    assert message.json()["sequence_no"] == 1
    assert len(message.json()["content_hash"]) == 64

    evidence = client.post(
        f"/api/v1/tasks/{task_id}/evidence",
        headers=analyst_headers,
        json={
            "title": "Operator note",
            "source_type": "manual",
            "source_ref": "manual://note/p4",
            "content": "Observed only non-destructive defensive evidence.",
            "classification": "internal",
            "trust": "operator_attested",
        },
    )
    assert evidence.status_code == 201, evidence.text
    assert len(evidence.json()["content_hash"]) == 64

    checkpoint = client.post(
        f"/api/v1/tasks/{task_id}/checkpoints",
        headers=analyst_headers,
    )
    assert checkpoint.status_code == 201, checkpoint.text
    body = checkpoint.json()
    assert body["message_count"] == 1
    assert body["evidence_count"] == 1
    assert len(body["summary_hash"]) == 64
    assert len(body["state_hash"]) == 64
    assert len(body["restore_policy_hash"]) == 64
    assert body["state"]["evidence_refs"][0]["content_hash"] == evidence.json()["content_hash"]

    listed = client.get(f"/api/v1/tasks/{task_id}/checkpoints", headers=analyst_headers)
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == body["id"]

    restored = client.post(
        f"/api/v1/tasks/{task_id}/context/restore",
        headers=analyst_headers,
    )
    assert restored.status_code == 200
    assert restored.json()["summary_hash"] == body["summary_hash"]
    assert restored.json()["state_hash"] == body["state_hash"]
    assert restored.json()["current_security_envelope"]["execution_authorized"] is False

    audit = client.get("/api/v1/audit", headers=admin_headers).json()
    assert any(item["action"] == "context.checkpoint.create" for item in audit)
    assert any(item["action"] == "evidence.item.add" for item in audit)


def test_p4_rag_chunks_citations_and_acl_prefilter(client, admin_headers):
    content = (
        "Patch planning overview. " * 90
        + "\n\nCVE regression marker appears in the second chunk only. "
        + "Use read-only validation evidence. " * 70
    )
    document = client.post(
        "/api/v1/rag/documents",
        headers=admin_headers,
        json={
            "title": "Chunked defensive runbook",
            "content": content,
            "source": "internal://runbook/p4",
            "classification": "internal",
            "version": "4",
            "tags": ["p4", "chunked"],
            "metadata": {"owner": "security"},
        },
    )
    assert document.status_code == 201, document.text
    assert document.json()["chunk_count"] >= 2

    chunks = client.get(
        f"/api/v1/rag/documents/{document.json()['id']}/chunks",
        headers=admin_headers,
    )
    assert chunks.status_code == 200
    assert len(chunks.json()) == document.json()["chunk_count"]
    assert all(len(item["chunk_hash"]) == 64 for item in chunks.json())

    search = client.post(
        "/api/v1/rag/search",
        headers=admin_headers,
        json={"query": "CVE regression marker read-only evidence", "top_k": 5},
    )
    assert search.status_code == 200, search.text
    result = search.json()["results"][0]
    assert result["document_id"] == document.json()["id"]
    assert result["chunk_id"]
    assert result["chunk_hash"] == result["citation"]["chunk_hash"]
    assert result["metadata"] == {"owner": "security"}
    assert result["trust"] == "untrusted_evidence_only"

    _, viewer_headers = make_user(client, admin_headers, "p4-viewer", "viewer")
    denied_chunks = client.get(
        f"/api/v1/rag/documents/{document.json()['id']}/chunks",
        headers=viewer_headers,
    )
    assert denied_chunks.status_code == 404


def test_p4_evidence_classification_write_is_role_limited(client, analyst, pending_task):
    _, analyst_headers = analyst
    response = client.post(
        f"/api/v1/tasks/{pending_task['id']}/evidence",
        headers=analyst_headers,
        json={
            "title": "Too sensitive",
            "content": "restricted evidence should require an operator or admin",
            "classification": "restricted",
        },
    )
    assert response.status_code == 403


def test_p4_knowledge_pack_is_read_only_and_omits_private_context(
    client, admin_headers, analyst, pending_task
):
    _, analyst_headers = analyst
    task_id = pending_task["id"]
    client.post(
        f"/api/v1/tasks/{task_id}/context",
        headers=analyst_headers,
        json={"role": "user", "content": "public task context marker", "visibility": "task"},
    )
    client.post(
        f"/api/v1/tasks/{task_id}/context",
        headers=analyst_headers,
        json={"role": "user", "content": "private operator scratchpad", "visibility": "private"},
    )
    client.post(
        f"/api/v1/tasks/{task_id}/evidence",
        headers=analyst_headers,
        json={
            "title": "Safe evidence",
            "content": "read-only validation evidence marker",
            "classification": "internal",
        },
    )
    client.post(
        "/api/v1/rag/documents",
        headers=admin_headers,
        json={
            "title": "Knowledge pack source",
            "content": "read-only validation evidence marker for P4 knowledge pack",
            "source": "internal://knowledge-pack",
            "classification": "internal",
            "version": "1",
        },
    )

    pack = client.post(
        f"/api/v1/tasks/{task_id}/knowledge-pack",
        headers=analyst_headers,
        json={"query": "read-only validation evidence marker", "top_k": 3},
    )
    assert pack.status_code == 200, pack.text
    body = pack.json()
    assert body["security_envelope"]["execution_authorized"] is False
    assert body["rag_results"]
    assert body["evidence"]
    contents = [message["content"] for message in body["messages"]]
    assert "public task context marker" in contents
    assert "private operator scratchpad" not in contents

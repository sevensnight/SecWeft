from __future__ import annotations

from conftest import make_user


def test_rag_acl_prefilter_and_provenance(client, admin_headers, analyst):
    public = client.post(
        "/api/v1/rag/documents",
        headers=admin_headers,
        json={
            "title": "Patch regression guide",
            "content": "Use a non-destructive marker to verify the patch.",
            "source": "internal://guide",
            "classification": "public",
            "version": "1",
            "tags": ["patch"],
        },
    )
    assert public.status_code == 201
    restricted = client.post(
        "/api/v1/rag/documents",
        headers=admin_headers,
        json={
            "title": "Restricted response",
            "content": "restricted patch evidence marker",
            "source": "internal://restricted",
            "classification": "restricted",
            "version": "1",
        },
    )
    assert restricted.status_code == 201
    _, viewer_headers = make_user(client, admin_headers, "viewer1", "viewer")
    viewer = client.post(
        "/api/v1/rag/search",
        headers=viewer_headers,
        json={"query": "patch marker", "top_k": 10},
    )
    assert viewer.status_code == 200
    results = viewer.json()["results"]
    assert {item["classification"] for item in results} <= {"public"}
    assert all(item["source"] and item["version"] and item["content_hash"] for item in results)
    assert all(item["trust"] == "untrusted_evidence_only" for item in results)
    denied = client.post(
        "/api/v1/rag/search",
        headers=viewer_headers,
        json={"query": "patch", "classifications": ["restricted"]},
    )
    assert denied.status_code == 403


def test_rag_ingest_scrubs_secret(client, app, admin_headers):
    secret = "sk-" + "canary-canary-canary-12345"
    response = client.post(
        "/api/v1/rag/documents",
        headers=admin_headers,
        json={
            "title": "Sanitized runbook",
            "content": f"Never store {secret} in a document",
            "source": "internal://sanitized",
            "classification": "internal",
            "version": "1",
        },
    )
    assert response.status_code == 201
    row = app.state.services.db.fetch_one(
        "SELECT content FROM rag_documents WHERE id=?", (response.json()["id"],)
    )
    assert secret not in row["content"]
    assert "[REDACTED]" in row["content"]

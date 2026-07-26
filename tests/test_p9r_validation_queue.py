from __future__ import annotations

import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from vulnlab.validation_queue import NatsJetStreamValidationQueue, SQLiteValidationQueue


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        body = b"known-safe-marker"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _CapturingNatsQueue(NatsJetStreamValidationQueue):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.published: list[dict[str, Any]] = []

    async def _publish_to_jetstream(
        self,
        *,
        subject: str,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        self.published.append({"subject": subject, "payload": payload, "headers": headers})


class _TimeoutNatsQueue(NatsJetStreamValidationQueue):
    async def _ensure_stream(self, js: Any) -> None:
        return None

    async def _connect(self) -> tuple[Any, Any]:
        class _Connection:
            def __init__(self) -> None:
                self.closed = False

            async def close(self) -> None:
                self.closed = True

        class _Subscription:
            async def fetch(self, count: int, *, timeout: float) -> list[Any]:
                from nats.errors import TimeoutError as NatsTimeoutError

                raise NatsTimeoutError

        class _JetStream:
            async def pull_subscribe(
                self,
                subject: str,
                *,
                durable: str,
                stream: str,
            ) -> _Subscription:
                return _Subscription()

        return _Connection(), _JetStream()


def _http_plan_payload() -> dict[str, Any]:
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


def _approved_http_plan(
    client: Any, admin_headers: dict[str, str], analyst: Any, task: dict[str, Any]
) -> dict[str, Any]:
    _, analyst_headers = analyst
    created = client.post(
        f"/api/v1/tasks/{task['id']}/validation-plans",
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
        json={"approved": True, "reason": "bounded P9-R HTTP validation"},
    )
    assert reviewed.status_code == 200, reviewed.text
    return reviewed.json()


def _create_execution(
    client: Any,
    admin_headers: dict[str, str],
    analyst: Any,
    pending_task: dict[str, Any],
    key: str,
) -> dict[str, Any]:
    plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
    created = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": key},
        json={"template_id": "http.response"},
    )
    assert created.status_code == 202, created.text
    return created.json()


def test_p9r_sqlite_queue_lease_expires_and_can_be_reacquired(
    client: Any,
    admin_headers: dict[str, str],
    analyst: Any,
    pending_task: dict[str, Any],
) -> None:
    execution = _create_execution(client, admin_headers, analyst, pending_task, "p9r-lease")
    services = client.app.state.services
    row = services.db.fetch_one(
        "SELECT * FROM validation_queue_messages WHERE execution_id=?", (execution["id"],)
    )
    assert row is not None
    queue = services.validation_queue
    assert isinstance(queue, SQLiteValidationQueue)

    first = queue.lease_by_message_id(row["message_id"], "worker-a")
    assert first.action == "leased"
    assert first.message is not None

    second = queue.lease_by_message_id(row["message_id"], "worker-b")
    assert second.action == "unavailable"

    services.db.execute(
        """UPDATE validation_queue_messages
           SET locked_until='2000-01-01T00:00:00+00:00'
           WHERE id=?""",
        (first.message.id,),
    )
    reacquired = queue.lease_by_message_id(row["message_id"], "worker-b")
    assert reacquired.action == "leased"
    assert reacquired.message is not None
    assert reacquired.message.redelivered is True
    assert reacquired.message.attempt == first.message.attempt + 1


def test_p9r_nats_dispatcher_publishes_outbox_headers_and_marks_row(
    settings: Any,
    client: Any,
    admin_headers: dict[str, str],
    analyst: Any,
    pending_task: dict[str, Any],
) -> None:
    execution = _create_execution(client, admin_headers, analyst, pending_task, "p9r-nats")
    services = client.app.state.services
    nats_settings = replace(
        settings,
        validation_queue_backend="nats",
        nats_url="nats://unit-test:4222",
    )
    queue = _CapturingNatsQueue(services.db, nats_settings)

    published = queue.dispatch_outbox_once()
    assert published is not None
    assert published["transport"] == "nats-jetstream"
    assert queue.published
    headers = queue.published[0]["headers"]
    assert headers["schema_version"] == "1"
    assert headers["execution_id"] == execution["id"]
    assert headers["tenant_id"] == execution["tenant_id"]
    assert headers["trace_id"] == execution["trace_id"]
    assert headers["request_id"]
    assert headers["Nats-Msg-Id"] == headers["message_id"]

    row = services.db.fetch_one(
        "SELECT * FROM validation_queue_messages WHERE execution_id=?", (execution["id"],)
    )
    assert row is not None
    assert row["published_at"] is not None
    assert row["publish_attempt"] == 1
    assert row["last_publish_error"] is None


def test_p9r_nats_fetch_timeout_is_empty_queue_not_worker_crash(
    settings: Any,
    client: Any,
) -> None:
    services = client.app.state.services
    nats_settings = replace(
        settings,
        validation_queue_backend="nats",
        nats_url="nats://unit-test:4222",
    )
    queue = _TimeoutNatsQueue(services.db, nats_settings)

    assert queue.consume_once("worker-timeout") is None


def test_p9r_duplicate_message_after_completion_does_not_duplicate_execution(
    client: Any,
    admin_headers: dict[str, str],
    analyst: Any,
    pending_task: dict[str, Any],
) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 65534), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        execution = _create_execution(client, admin_headers, analyst, pending_task, "p9r-dup")
        services = client.app.state.services
        result = services.validation_execution.run_worker_once("worker-a")
        assert result is not None
        assert result["status"] == "SUCCEEDED"

        row = services.db.fetch_one(
            "SELECT * FROM validation_queue_messages WHERE execution_id=?", (execution["id"],)
        )
        assert row is not None
        queue = services.validation_queue
        assert isinstance(queue, SQLiteValidationQueue)
        duplicate = queue.lease_by_message_id(row["message_id"], "worker-b")
        assert duplicate.action == "done"

        evidence = services.db.fetch_all(
            "SELECT * FROM validation_execution_evidence WHERE execution_id=?",
            (execution["id"],),
        )
        assert len(evidence) == 1
        latest = services.validation_execution.get(execution["id"])
        assert latest["status"] == "SUCCEEDED"
    finally:
        server.shutdown()
        server.server_close()

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .config import Settings
from .repository import ControlPlaneRepository

VALIDATION_QUEUE_SUBJECT = "validation.executions.requested"


class ValidationQueueError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ValidationQueueMessage:
    id: str
    execution_id: str
    message_id: str
    subject: str
    attempt: int
    max_attempts: int
    payload: dict[str, Any]
    lock_token: str | None
    schema_version: int
    headers: dict[str, str]
    redelivered: bool = False


@dataclass(frozen=True, slots=True)
class QueueLeaseAttempt:
    action: str
    message: ValidationQueueMessage | None = None
    status: str | None = None
    reason: str | None = None


class ValidationQueue(Protocol):
    def consume_once(self, worker_id: str) -> ValidationQueueMessage | None: ...

    def complete(self, queue_id: str) -> None: ...

    def retry(self, queue_id: str, error: str, *, delay_seconds: int = 1) -> None: ...

    def dead(self, queue_id: str, error: str) -> None: ...

    def cancel_execution(self, execution_id: str) -> None: ...

    def dispatch_outbox_once(self) -> dict[str, Any] | None: ...


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _future(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def _json(value: str | None, default: Any) -> Any:
    if value is None or value == "":
        return default
    return json.loads(value)


def _headers(row: Any, payload: dict[str, Any], schema_version: int) -> dict[str, str]:
    return {
        "schema_version": str(schema_version),
        "message_id": str(row["message_id"]),
        "execution_id": str(row["execution_id"]),
        "tenant_id": str(payload.get("tenant_id", "")),
        "trace_id": str(payload.get("trace_id", "")),
        "request_id": str(payload.get("request_id", "")),
        "queue_message_id": str(row["id"]),
    }


def _priority_rank(payload: dict[str, Any]) -> int:
    priority = str(payload.get("priority", "normal")).lower()
    return {"critical": 0, "high": 1, "normal": 2, "low": 3}.get(priority, 2)


class SQLiteValidationQueue:
    """Durable local adapter used only for deterministic development and tests."""

    def __init__(self, db: ControlPlaneRepository, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    def _row_to_message(self, row: Any, *, redelivered: bool = False) -> ValidationQueueMessage:
        payload = _json(row["payload_json"], {})
        try:
            schema_version = int(row["schema_version"])
        except (IndexError, KeyError):
            schema_version = 1
        return ValidationQueueMessage(
            id=str(row["id"]),
            execution_id=str(row["execution_id"]),
            message_id=str(row["message_id"]),
            subject=str(row["subject"]),
            attempt=int(row["attempt"]),
            max_attempts=int(row["max_attempts"]),
            payload=payload,
            lock_token=row["lock_token"],
            schema_version=schema_version,
            headers=_headers(row, payload, schema_version),
            redelivered=redelivered,
        )

    def _lease_row(self, row: Any, worker_id: str) -> QueueLeaseAttempt:
        now = _now()
        token = str(uuid.uuid4())
        locked_until = _future(self.settings.validation_queue_lease_seconds)
        status = str(row["status"])
        if status in {"done", "cancelled", "dead"}:
            return QueueLeaseAttempt("done", status=status, reason=f"message is {status}")
        if status == "leased" and row["locked_until"] and str(row["locked_until"]) > now:
            return QueueLeaseAttempt("unavailable", status=status, reason="lease is still active")
        redelivered = status == "leased"
        with self.db.transaction() as connection:
            updated = connection.execute(
                """UPDATE validation_queue_messages
                   SET status='leased',attempt=attempt+1,locked_by=?,lock_token=?,
                       locked_until=?,updated_at=?
                   WHERE id=? AND (
                       status='ready' OR (status='leased' AND locked_until<=?)
                   )""",
                (worker_id, token, locked_until, now, row["id"], now),
            ).rowcount
            if updated != 1:
                current = connection.execute(
                    "SELECT status FROM validation_queue_messages WHERE id=?", (row["id"],)
                ).fetchone()
                return QueueLeaseAttempt(
                    "unavailable",
                    status=current["status"] if current is not None else None,
                    reason="compare-and-swap lease failed",
                )
            leased = connection.execute(
                "SELECT * FROM validation_queue_messages WHERE id=?", (row["id"],)
            ).fetchone()
        if leased is None:
            return QueueLeaseAttempt("missing", reason="leased row disappeared")
        return QueueLeaseAttempt(
            "leased", message=self._row_to_message(leased, redelivered=redelivered)
        )

    def lease_next(self, worker_id: str) -> QueueLeaseAttempt:
        now = _now()
        rows = self.db.fetch_all(
            """SELECT * FROM validation_queue_messages
               WHERE available_at<=? AND (
                   status='ready' OR (status='leased' AND locked_until<=?)
               )
               ORDER BY created_at,id LIMIT 50""",
            (now, now),
        )
        if not rows:
            return QueueLeaseAttempt("empty")
        leased_rows = self.db.fetch_all(
            "SELECT payload_json FROM validation_queue_messages WHERE status='leased'"
        )
        tenant_load: dict[str, int] = {}
        for leased in leased_rows:
            payload = _json(leased["payload_json"], {})
            tenant_id = str(payload.get("tenant_id", ""))
            tenant_load[tenant_id] = tenant_load.get(tenant_id, 0) + 1
        row = min(
            rows,
            key=lambda candidate: (
                tenant_load.get(str(_json(candidate["payload_json"], {}).get("tenant_id", "")), 0),
                _priority_rank(_json(candidate["payload_json"], {})),
                str(candidate["created_at"]),
                str(candidate["id"]),
            ),
        )
        return self._lease_row(row, worker_id)

    def lease_by_message_id(self, message_id: str, worker_id: str) -> QueueLeaseAttempt:
        row = self.db.fetch_one(
            "SELECT * FROM validation_queue_messages WHERE message_id=?", (message_id,)
        )
        if row is None:
            return QueueLeaseAttempt("missing", reason="message_id is not in outbox")
        return self._lease_row(row, worker_id)

    def consume_once(self, worker_id: str) -> ValidationQueueMessage | None:
        attempt = self.lease_next(worker_id)
        return attempt.message if attempt.action == "leased" else None

    def complete(self, queue_id: str) -> None:
        self.db.execute(
            """UPDATE validation_queue_messages
               SET status='done',last_error=NULL,updated_at=? WHERE id=?""",
            (_now(), queue_id),
        )

    def retry(self, queue_id: str, error: str, *, delay_seconds: int = 1) -> None:
        now = _now()
        self.db.execute(
            """UPDATE validation_queue_messages
               SET status='ready',last_error=?,available_at=?,locked_by=NULL,lock_token=NULL,
                   locked_until=NULL,published_at=NULL,last_publish_error=NULL,updated_at=?
               WHERE id=?""",
            (error, _future(delay_seconds), now, queue_id),
        )

    def dead(self, queue_id: str, error: str) -> None:
        self.db.execute(
            """UPDATE validation_queue_messages
               SET status='dead',last_error=?,locked_by=NULL,lock_token=NULL,
                   locked_until=NULL,updated_at=? WHERE id=?""",
            (error, _now(), queue_id),
        )

    def cancel_execution(self, execution_id: str) -> None:
        self.db.execute(
            """UPDATE validation_queue_messages
               SET status='cancelled',updated_at=?
               WHERE execution_id=? AND status IN ('ready','leased')""",
            (_now(), execution_id),
        )

    def mark_published(self, queue_id: str) -> None:
        self.db.execute(
            """UPDATE validation_queue_messages
               SET publish_attempt=publish_attempt+1,published_at=?,last_publish_error=NULL,
                   updated_at=?
               WHERE id=?""",
            (_now(), _now(), queue_id),
        )

    def mark_publish_failed(self, queue_id: str, error: str) -> None:
        self.db.execute(
            """UPDATE validation_queue_messages
               SET publish_attempt=publish_attempt+1,last_publish_error=?,updated_at=?
               WHERE id=?""",
            (error, _now(), queue_id),
        )

    def pending_outbox_message(self) -> ValidationQueueMessage | None:
        now = _now()
        row = self.db.fetch_one(
            """SELECT * FROM validation_queue_messages
               WHERE status='ready' AND available_at<=? AND published_at IS NULL
               ORDER BY created_at,id LIMIT 1""",
            (now,),
        )
        return self._row_to_message(row) if row is not None else None

    def dispatch_outbox_once(self) -> dict[str, Any] | None:
        message = self.pending_outbox_message()
        if message is None:
            return None
        self.mark_published(message.id)
        return {
            "queue_message_id": message.id,
            "message_id": message.message_id,
            "subject": message.subject,
            "transport": "sqlite",
            "dispatched": False,
        }


class NatsJetStreamValidationQueue:
    """JetStream transport backed by the validation_queue_messages transactional outbox."""

    def __init__(self, db: ControlPlaneRepository, settings: Settings) -> None:
        if settings.nats_url is None:
            raise ValidationQueueError("VULNLAB_NATS_URL is required for NATS validation queue")
        self.db = db
        self.settings = settings
        self.sqlite = SQLiteValidationQueue(db, settings)
        self._inflight: dict[str, Any] = {}
        self._loop = asyncio.new_event_loop()

    def _run(self, value: Any) -> Any:
        return self._loop.run_until_complete(value)

    async def _connect(self) -> tuple[Any, Any]:
        try:
            import nats
        except ImportError as exc:  # pragma: no cover - exercised in runtime packaging.
            raise ValidationQueueError("nats-py is required for NATS validation queue") from exc
        assert self.settings.nats_url is not None
        nc = await nats.connect(self.settings.nats_url)
        return nc, nc.jetstream()

    async def _ensure_stream(self, js: Any) -> None:
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy, StorageType, StreamConfig
        from nats.js.errors import NotFoundError

        config = StreamConfig(
            name=self.settings.nats_stream,
            subjects=[self.settings.nats_subject],
            storage=StorageType.FILE,
            duplicate_window=120.0,
        )
        try:
            await js.stream_info(self.settings.nats_stream)
        except NotFoundError:
            await js.add_stream(config=config)
        consumer = ConsumerConfig(
            durable_name=self.settings.nats_durable,
            deliver_policy=DeliverPolicy.ALL,
            ack_policy=AckPolicy.EXPLICIT,
            ack_wait=float(self.settings.validation_queue_lease_seconds),
            max_deliver=20,
            filter_subject=self.settings.nats_subject,
        )
        try:
            await js.consumer_info(self.settings.nats_stream, self.settings.nats_durable)
        except NotFoundError:
            await js.add_consumer(self.settings.nats_stream, config=consumer)

    async def _publish_to_jetstream(
        self,
        *,
        subject: str,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        nc, js = await self._connect()
        try:
            await self._ensure_stream(js)
            await js.publish(
                subject,
                payload,
                stream=self.settings.nats_stream,
                headers=headers,
            )
        finally:
            await nc.close()

    def dispatch_outbox_once(self) -> dict[str, Any] | None:
        message = self.sqlite.pending_outbox_message()
        if message is None:
            return None
        payload = json.dumps(message.payload, ensure_ascii=False, sort_keys=True).encode()
        headers = {
            **message.headers,
            "Nats-Msg-Id": message.message_id,
            "transport": "nats-jetstream",
        }
        try:
            self._run(
                self._publish_to_jetstream(
                    subject=message.subject,
                    payload=payload,
                    headers=headers,
                )
            )
        except Exception as exc:
            self.sqlite.mark_publish_failed(message.id, str(exc))
            raise
        self.sqlite.mark_published(message.id)
        return {
            "queue_message_id": message.id,
            "message_id": message.message_id,
            "subject": message.subject,
            "stream": self.settings.nats_stream,
            "transport": "nats-jetstream",
            "headers": headers,
        }

    async def _fetch_nats_message(self) -> tuple[Any | None, Any | None]:
        from nats.errors import TimeoutError as NatsTimeoutError
        from nats.js.errors import FetchTimeoutError

        nc, js = await self._connect()
        await self._ensure_stream(js)
        sub = await js.pull_subscribe(
            self.settings.nats_subject,
            durable=self.settings.nats_durable,
            stream=self.settings.nats_stream,
        )
        try:
            messages = await sub.fetch(1, timeout=self.settings.nats_fetch_timeout_seconds)
        except (FetchTimeoutError, NatsTimeoutError):
            await nc.close()
            return None, None
        if not messages:
            await nc.close()
            return None, None
        return messages[0], nc

    def consume_once(self, worker_id: str) -> ValidationQueueMessage | None:
        msg, nc = self._run(self._fetch_nats_message())
        if msg is None:
            return None
        headers = dict(msg.headers or {})
        message_id = headers.get("message_id") or headers.get("Nats-Msg-Id")
        if not message_id:
            self._run(msg.term())
            if nc is not None:
                self._run(nc.close())
            return None
        attempt = self.sqlite.lease_by_message_id(str(message_id), worker_id)
        if attempt.action == "leased" and attempt.message is not None:
            self._inflight[attempt.message.id] = (msg, nc)
            return attempt.message
        if attempt.action == "unavailable":
            self._run(msg.nak(delay=1))
        else:
            self._run(msg.ack())
        if nc is not None:
            self._run(nc.close())
        return None

    def complete(self, queue_id: str) -> None:
        self.sqlite.complete(queue_id)
        inflight = self._inflight.pop(queue_id, None)
        if inflight is not None:
            msg, nc = inflight
            self._run(msg.ack())
            self._run(nc.close())

    def retry(self, queue_id: str, error: str, *, delay_seconds: int = 1) -> None:
        self.sqlite.retry(queue_id, error, delay_seconds=delay_seconds)
        inflight = self._inflight.pop(queue_id, None)
        if inflight is not None:
            msg, nc = inflight
            self._run(msg.nak(delay=delay_seconds))
            self._run(nc.close())

    def dead(self, queue_id: str, error: str) -> None:
        self.sqlite.dead(queue_id, error)
        inflight = self._inflight.pop(queue_id, None)
        if inflight is not None:
            msg, nc = inflight
            self._run(msg.term())
            self._run(nc.close())

    def cancel_execution(self, execution_id: str) -> None:
        self.sqlite.cancel_execution(execution_id)

    def close(self) -> None:
        if not self._loop.is_closed():
            self._loop.close()


def build_validation_queue(db: ControlPlaneRepository, settings: Settings) -> ValidationQueue:
    if settings.validation_queue_backend == "sqlite":
        if settings.env in {"production", "prod"}:
            raise ValidationQueueError("SQLite validation queue is forbidden in production")
        return SQLiteValidationQueue(db, settings)
    if settings.validation_queue_backend == "nats":
        return NatsJetStreamValidationQueue(db, settings)
    raise ValidationQueueError(
        f"unknown validation queue backend: {settings.validation_queue_backend}"
    )

"""Local event buffer and transport for Layer 1 collectors.

The buffer stores only serialized Layer1Event JSON (content-free by contract) plus the
time it was queued. Retention is bounded by age and by count, which is the storage
limitation measure: events that cannot be delivered are not kept forever.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlsplit

from gov.contracts import Layer1Event

log = logging.getLogger(__name__)

DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 3600
DEFAULT_MAX_EVENTS = 10_000
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class EventBuffer:
    def __init__(
        self,
        path=":memory:",
        *,
        max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
        max_events: int = DEFAULT_MAX_EVENTS,
    ):
        if max_age_seconds <= 0 or max_events <= 0:
            raise ValueError("max_age_seconds and max_events must be positive")
        self.max_age_seconds = max_age_seconds
        self.max_events = max_events
        if str(path) != ":memory:":
            # create the file readable by the owner only (no effect on Windows)
            os.close(os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600))
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "queued_at REAL NOT NULL, payload TEXT NOT NULL)"
            )

    def add(self, event: Layer1Event, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        payload = event.model_dump_json()
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO events (queued_at, payload) VALUES (?, ?)", (now, payload))
            self._purge_locked(now)

    def purge(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        with self._lock, self._conn:
            return self._purge_locked(now)

    def _purge_locked(self, now: float) -> int:
        deleted = self._conn.execute(
            "DELETE FROM events WHERE queued_at < ?", (now - self.max_age_seconds,)
        ).rowcount
        deleted += self._conn.execute(
            "DELETE FROM events WHERE id <= "
            "(SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)",
            (self.max_events,),
        ).rowcount
        return deleted

    def pending(self, limit: int = 100) -> list[tuple[int, float, dict]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, queued_at, payload FROM events ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        return [(row_id, queued_at, json.loads(payload)) for row_id, queued_at, payload in rows]

    def ack(self, ids: list[int]) -> None:
        if not ids:
            return
        marks = ",".join("?" for _ in ids)
        with self._lock, self._conn:
            self._conn.execute(f"DELETE FROM events WHERE id IN ({marks})", list(ids))

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class HttpSender:
    """POSTs a batch of events as JSON. HTTPS is required, except for loopback testing."""

    def __init__(self, url: str, *, timeout: float = 5.0, headers: Optional[dict] = None):
        parts = urlsplit(url)
        https = parts.scheme == "https"
        loopback_http = parts.scheme == "http" and parts.hostname in _LOOPBACK
        if not (https or loopback_http):
            raise ValueError("ingestion URL must use https (plain http is allowed only for loopback)")
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})

    def __call__(self, batch: list[dict]) -> None:
        body = json.dumps({"events": batch}).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json", **self.headers},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"ingestion endpoint returned HTTP {response.status}")


def flush_buffer(buffer: EventBuffer, sender: Callable[[list[dict]], None], batch_size: int = 100) -> int:
    """Send pending events in batches. Events are deleted only after a successful send."""
    sent = 0
    while True:
        rows = buffer.pending(batch_size)
        if not rows:
            return sent
        try:
            sender([{"queued_at": queued_at, "event": event} for _, queued_at, event in rows])
        except Exception as exc:  # delivery failures must never break the collector
            log.warning("event delivery failed (%s); %d events kept for retry", type(exc).__name__, buffer.count())
            return sent
        buffer.ack([row_id for row_id, _, _ in rows])
        sent += len(rows)


class BackgroundFlusher:
    """Flushes the buffer on a timer in a daemon thread."""

    def __init__(self, buffer: EventBuffer, sender: Callable[[list[dict]], None],
                 *, interval: float = 10.0, batch_size: int = 100):
        self._buffer, self._sender = buffer, sender
        self._interval, self._batch_size = interval, batch_size
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="gov-flusher", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            flush_buffer(self._buffer, self._sender, self._batch_size)

    def stop(self, final_flush: bool = True) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 5)
            self._thread = None
        if final_flush:
            flush_buffer(self._buffer, self._sender, self._batch_size)

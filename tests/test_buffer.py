import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from gov.collectors.buffer import BackgroundFlusher, EventBuffer, HttpSender, flush_buffer
from gov.common import Action
from gov.contracts import Layer1Event


def ev(destination="api.openai.com"):
    return Layer1Event(collector="egress_proxy", destination=destination, classes_matched=["ssn"], action=Action.block)


def test_add_pending_ack():
    buf = EventBuffer()
    buf.add(ev("a.com"), now=100)
    buf.add(ev("b.com"), now=101)
    rows = buf.pending()
    assert [r[2]["destination"] for r in rows] == ["a.com", "b.com"]
    assert rows[0][1] == 100
    buf.ack([rows[0][0]])
    assert buf.count() == 1
    buf.ack([])  # no-op


def test_payload_is_exactly_the_event():
    buf = EventBuffer()
    event = ev()
    buf.add(event)
    assert buf.pending()[0][2] == json.loads(event.model_dump_json())


def test_retention_by_age():
    buf = EventBuffer(max_age_seconds=60)
    buf.add(ev("old.com"), now=1000)
    buf.add(ev("new.com"), now=1100)  # adding purges anything older than 60s
    assert [r[2]["destination"] for r in buf.pending()] == ["new.com"]
    assert buf.purge(now=2000) == 1 and buf.count() == 0


def test_retention_by_count_keeps_newest():
    buf = EventBuffer(max_events=3)
    for i in range(5):
        buf.add(ev(f"h{i}.com"), now=1000 + i)
    assert [r[2]["destination"] for r in buf.pending()] == ["h2.com", "h3.com", "h4.com"]


def test_invalid_limits_rejected():
    with pytest.raises(ValueError):
        EventBuffer(max_events=0)
    with pytest.raises(ValueError):
        EventBuffer(max_age_seconds=0)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_database_file_is_owner_only(tmp_path):
    path = tmp_path / "events.db"
    EventBuffer(path).add(ev())
    assert os.stat(path).st_mode & 0o077 == 0


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "events.db"
    first = EventBuffer(path)
    first.add(ev())
    first.close()
    assert EventBuffer(path).count() == 1


@pytest.mark.parametrize("url", ["http://example.com/x", "ftp://example.com", "example.com", ""])
def test_sender_rejects_insecure_urls(url):
    with pytest.raises(ValueError):
        HttpSender(url)


@pytest.mark.parametrize("url", ["https://ingest.example.com/events", "http://127.0.0.1:9/e", "http://localhost/e"])
def test_sender_accepts_https_and_loopback(url):
    assert HttpSender(url).url == url


def test_flush_deletes_only_after_success():
    buf = EventBuffer()
    for i in range(3):
        buf.add(ev(f"h{i}.com"))
    calls = []

    def failing(batch):
        calls.append(len(batch))
        raise ConnectionError("down")

    assert flush_buffer(buf, failing, batch_size=2) == 0 and buf.count() == 3 and calls == [2]
    batches = []
    assert flush_buffer(buf, batches.append, batch_size=2) == 3 and buf.count() == 0
    assert [len(b) for b in batches] == [2, 1]
    assert set(batches[0][0]) == {"queued_at", "event"}


class _Handler(BaseHTTPRequestHandler):
    received = []
    status = 200

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).received.append(json.loads(self.rfile.read(length)))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    _Handler.received, _Handler.status = [], 200
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/events"
    srv.shutdown()
    srv.server_close()


def test_http_sender_delivers_to_loopback(server):
    buf = EventBuffer()
    buf.add(ev())
    assert flush_buffer(buf, HttpSender(server)) == 1 and buf.count() == 0
    body = _Handler.received[0]
    assert body["events"][0]["event"]["destination"] == "api.openai.com"


def test_http_error_keeps_events(server):
    _Handler.status = 500
    buf = EventBuffer()
    buf.add(ev())
    assert flush_buffer(buf, HttpSender(server)) == 0 and buf.count() == 1


def test_background_flusher_sends_and_final_flush():
    buf = EventBuffer()
    sent = []
    flusher = BackgroundFlusher(buf, sent.append, interval=0.05)
    flusher.start()
    flusher.start()  # idempotent
    buf.add(ev())
    deadline = time.time() + 3
    while buf.count() and time.time() < deadline:
        time.sleep(0.02)
    assert buf.count() == 0 and len(sent) == 1
    buf.add(ev("late.com"))
    flusher.stop()  # final flush picks up what the timer has not yet sent
    assert buf.count() == 0

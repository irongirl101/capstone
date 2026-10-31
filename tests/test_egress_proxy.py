import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("mitmproxy")
from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

from gov.collectors.buffer import EventBuffer  # noqa: E402
from gov.collectors.core import CollectorCore, load_bundle  # noqa: E402
from gov.collectors.egress_proxy import EgressProxyAddon, build_from_env, extract_text  # noqa: E402
from gov.contracts import Layer1Event  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SSN = "123-45-6789"
KEY = "k" * 32


def make_addon(destinations=None, **kwargs):
    buffer = EventBuffer()
    bundle = load_bundle(ROOT / "policy" / "policy.yaml", destinations)
    core = CollectorCore(bundle, "egress_proxy", buffer=buffer, pseudonym_key=KEY)
    return EgressProxyAddon(core, **kwargs), buffer


def make_flow(body, url="https://api.openai.com/v1/chat/completions", method="POST", headers=None):
    headers = {"Content-Type": "application/json", **(headers or {})}
    return tflow.tflow(req=http.Request.make(method, url, body, headers))


def json_body(text):
    return json.dumps({"messages": [{"role": "user", "content": text}]}).encode()


def test_ssn_to_ai_host_is_blocked_with_403_and_content_free_event():
    addon, buffer = make_addon()
    flow = make_flow(json_body(f"my ssn is {SSN}"))
    addon.request(flow)
    assert flow.response.status_code == 403
    body = json.loads(flow.response.get_text())
    assert body == {"error": "blocked_by_policy", "finding": "SENSITIVE_TO_UNAPPROVED", "classes": ["ssn"]}
    assert SSN not in flow.response.get_text()
    [(_, _, payload)] = buffer.pending()
    event = Layer1Event.model_validate(payload)
    assert event.collector == "egress_proxy" and event.destination == "api.openai.com"
    assert event.agent_id is None and SSN not in json.dumps(payload)


def test_request_is_not_modified_and_clean_request_passes():
    addon, buffer = make_addon()
    flow = make_flow(json_body("hello"))
    before = flow.request.raw_content
    addon.request(flow)
    assert flow.response is None and flow.request.raw_content == before and buffer.count() == 0


def test_approved_ai_host_logs_only():
    addon, buffer = make_addon({"api.openai.com": "approved"})
    flow = make_flow(json_body(f"ssn {SSN}"))
    addon.request(flow)
    assert flow.response is None
    assert buffer.pending()[0][2]["action"] == "log"


def test_non_ai_host_is_not_read():
    addon, buffer = make_addon()

    def explode(*args, **kwargs):
        raise AssertionError("body of a non-AI host must not be read")

    flow = SimpleNamespace(
        request=SimpleNamespace(pretty_host="example.org", method="POST", get_content=explode, get_text=explode),
        response=None,
    )
    addon.request(flow)
    assert flow.response is None and buffer.count() == 0


def test_get_requests_and_empty_bodies_are_skipped():
    addon, buffer = make_addon()
    get_flow = make_flow(b"", method="GET")
    empty_flow = make_flow(b"")
    addon.request(get_flow)
    addon.request(empty_flow)
    assert get_flow.response is None and empty_flow.response is None and buffer.count() == 0


def test_json_unicode_escapes_cannot_hide_a_match():
    addon, _ = make_addon()
    body = b'{"m": "\\u0031\\u0032\\u0033-45-6789"}'
    flow = make_flow(body)
    addon.request(flow)
    assert flow.response.status_code == 403


def test_gzip_body_is_decoded_before_scanning():
    addon, _ = make_addon()
    req = http.Request.make("POST", "https://api.openai.com/v1/chat", b"x",
                            {"Content-Type": "application/json", "Content-Encoding": "gzip"})
    req.raw_content = gzip.compress(json_body(f"ssn {SSN}"))
    flow = tflow.tflow(req=req)
    addon.request(flow)
    assert flow.response.status_code == 403


def test_non_json_and_utf16_bodies_are_scanned():
    addon, _ = make_addon()
    plain = make_flow(f"ssn {SSN}".encode(), headers={"Content-Type": "text/plain"})
    addon.request(plain)
    assert plain.response.status_code == 403
    utf16 = make_flow(f"ssn {SSN}".encode("utf-16"), headers={"Content-Type": "text/plain; charset=utf-16"})
    addon.request(utf16)
    assert utf16.response.status_code == 403


def test_extract_text_empty_and_invalid_bytes():
    assert extract_text(http.Request.make("POST", "https://api.openai.com/", b"", {})) == ""
    assert "ssn" in extract_text(http.Request.make("POST", "https://api.openai.com/", b"\xff ssn", {}))


def test_inspection_error_fails_open_by_default_and_closed_on_request():
    for fail_closed, expected in [(False, None), (True, 502)]:
        addon, _ = make_addon(fail_closed=fail_closed)

        def broken(*args, **kwargs):
            raise RuntimeError(SSN)  # the error text must not be logged

        addon.core.inspect = broken
        flow = make_flow(json_body(f"ssn {SSN}"))
        addon.request(flow)
        assert (flow.response.status_code if flow.response else None) == expected


def test_errors_are_logged_without_content(caplog):
    addon, _ = make_addon()
    addon.core.inspect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError(SSN))
    addon.request(make_flow(json_body(f"ssn {SSN}")))
    assert "RuntimeError" in caplog.text and SSN not in caplog.text


def test_lifecycle_flushes_buffer_on_done():
    sent = []
    addon, buffer = make_addon(sender=sent.append, flush_interval=60)
    addon.running()
    addon.request(make_flow(json_body(f"ssn {SSN}")))
    assert buffer.count() == 1
    addon.done()
    assert buffer.count() == 0 and len(sent) == 1
    assert sent[0][0]["event"]["classes_matched"] == ["ssn"]


def test_lifecycle_without_sender_is_a_noop():
    addon, _ = make_addon()
    addon.running()
    addon.done()


def test_build_from_env(tmp_path):
    destinations = tmp_path / "dest.json"
    destinations.write_text(json.dumps({"api.openai.com": "approved"}))
    addon = build_from_env({
        "GOV_POLICY": str(ROOT / "policy" / "policy.yaml"),
        "GOV_DESTINATIONS": str(destinations),
        "GOV_BUFFER_DB": str(tmp_path / "events.db"),
        "GOV_PSEUDONYM_KEY": KEY,
        "GOV_FAIL_CLOSED": "1",
    })
    assert addon.fail_closed is True and addon._flusher is None
    flow = make_flow(json_body(f"ssn {SSN}"))
    addon.request(flow)
    assert flow.response is None  # approved destination: logged, not blocked
    assert (tmp_path / "events.db").exists()


def test_build_from_env_requires_policy():
    with pytest.raises(RuntimeError, match="GOV_POLICY"):
        build_from_env({})

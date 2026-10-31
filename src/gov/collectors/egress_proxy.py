"""Egress proxy collector: a mitmproxy addon that scans requests to AI API hosts.

Scope and data minimisation:
* Only hosts listed in the policy's ai_hosts are inspected. For every other host the
  request is passed through untouched and its body is never read.
* Only requests that carry a body (POST, PUT, PATCH) are scanned.
* The request is never modified. On a block the addon answers 403 itself, so the
  request never leaves the machine. The response body names classes, never content.
* Nothing from the body is logged or stored; the event holds the host and class ids.

Limits: traffic that does not go through the proxy is not seen; certificate-pinned apps,
containers and non-HTTP traffic bypass it. The host comes from the request's Host header
or SNI, which a client can set to anything. Streamed (large) bodies are not buffered by
mitmproxy and are therefore not scanned. The agent id is None because the proxy cannot
tell which process sent a request.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Callable, Optional

from mitmproxy import http

from gov.collectors.buffer import BackgroundFlusher, EventBuffer, HttpSender
from gov.collectors.core import CollectorCore, Decision, load_bundle
from gov.collectors.payload import flatten_text
from gov.common import DestKind

log = logging.getLogger(__name__)

SCAN_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _json_response(status: int, payload: dict) -> http.Response:
    return http.Response.make(status, json.dumps(payload).encode("utf-8"), {"Content-Type": "application/json"})


def extract_text(request: http.Request) -> str:
    """Decoded body as scannable text. JSON bodies are parsed so escapes are resolved."""
    content = request.get_content(strict=False)
    if not content:
        return ""
    candidates = [content.decode("utf-8", errors="replace")]
    charset_text = request.get_text(strict=False)  # honours a declared charset such as utf-16
    if charset_text and charset_text != candidates[0]:
        candidates.append(charset_text)
    parts = []
    for raw in candidates:
        try:
            parts.append(flatten_text(json.loads(raw)))
        except ValueError:
            parts.append(raw)
    return "\n".join(parts)


class EgressProxyAddon:
    def __init__(self, core: CollectorCore, *, sender: Optional[Callable[[list], None]] = None,
                 fail_closed: bool = False, flush_interval: float = 10.0):
        self.core = core
        self.fail_closed = fail_closed
        self._flusher = (BackgroundFlusher(core.buffer, sender, interval=flush_interval)
                         if sender is not None and core.buffer is not None else None)

    # mitmproxy lifecycle hooks
    def running(self) -> None:
        if self._flusher:
            self._flusher.start()

    def done(self) -> None:
        if self._flusher:
            self._flusher.stop(final_flush=True)

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not self.core.is_inspected_host(host):
            return  # not an AI host: do not read the body
        if flow.request.method.upper() not in SCAN_METHODS:
            return
        try:
            text = extract_text(flow.request)
            if not text:
                return
            decision: Decision = self.core.inspect(text, host, kind=DestKind.api)
        except Exception as exc:  # never log the body or the exception text
            log.error("inspection failed for %s (%s)", host, type(exc).__name__)
            if self.fail_closed:
                flow.response = _json_response(502, {"error": "inspection_failed"})
            return
        if decision.blocked:
            flow.response = _json_response(403, {
                "error": "blocked_by_policy",
                "finding": decision.evaluation.finding,
                "classes": decision.classes,
            })


def build_from_env(environ=None) -> EgressProxyAddon:
    """Build the addon from environment variables (used by scripts/mitm_gov.py).

    GOV_POLICY        policy .yaml or compiled bundle .json (required)
    GOV_DESTINATIONS  optional JSON file mapping host -> approved|unapproved|unknown
    GOV_BUFFER_DB     local buffer path (default gov_events.db)
    GOV_INGEST_URL    optional Layer 3 endpoint (https; http only for loopback)
    GOV_PSEUDONYM_KEY key for pseudonymising ids (see collectors.core)
    GOV_FAIL_CLOSED   "1" to answer 502 when inspection itself fails (default: let through)
    """
    env = os.environ if environ is None else environ
    if not env.get("GOV_POLICY"):
        raise RuntimeError("GOV_POLICY must point at a policy .yaml or bundle .json file")
    destinations = None
    if env.get("GOV_DESTINATIONS"):
        destinations = json.loads(Path(env["GOV_DESTINATIONS"]).read_text(encoding="utf-8"))
    bundle = load_bundle(env["GOV_POLICY"], destinations)
    buffer = EventBuffer(env.get("GOV_BUFFER_DB", "gov_events.db"))
    core = CollectorCore(bundle, "egress_proxy", buffer=buffer, pseudonym_key=env.get("GOV_PSEUDONYM_KEY"))
    sender = HttpSender(env["GOV_INGEST_URL"]) if env.get("GOV_INGEST_URL") else None
    return EgressProxyAddon(core, sender=sender, fail_closed=env.get("GOV_FAIL_CLOSED") == "1")

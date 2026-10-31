"""collector_core: the shared pipeline behind every Layer 1 collector.

    text -> Matcher.scan -> evaluate(policy, classes, destination status) -> Layer1Event
         -> local buffer -> (later) HTTPS delivery to Layer 3

A collector (agent hook, egress proxy, ...) only captures text and a destination and
enforces the returned Decision. Data-protection properties live here, once:

* The event never contains the scanned text, only class ids, the normalised host,
  the action, and an optional pseudonymised agent id.
* Destinations are reduced to a host: URL paths and query strings (which can carry
  content) never reach an event.
* Nothing matched means no event, so clean traffic leaves no record.
* Agent ids are replaced by a keyed hash (HMAC-SHA256). This is pseudonymisation,
  not anonymisation: whoever holds the key can link ids back to agents.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from gov.collectors.buffer import EventBuffer, flush_buffer
from gov.common import Action, DestKind, DestStatus
from gov.contracts import Collector, Layer1Event
from gov.policy.engine import Evaluation, evaluate
from gov.policy.loader import compile_bundle, load_policy, policy_hash
from gov.policy.match import Matcher
from gov.policy.schema import Bundle

log = logging.getLogger(__name__)

KEY_ENV = "GOV_PSEUDONYM_KEY"
_PORT = re.compile(r"^(?P<host>.+):(?P<port>\d{1,5})$")


def normalize_destination(destination: str) -> str:
    """Lower-case host only: no scheme, port, path, query or trailing dot."""
    value = destination.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        match = _PORT.match(value)
        if match:
            value = match.group("host")
    return value.rstrip(".")


def _suffix_patterns(host: str):
    parts = host.split(".")
    for i in range(1, len(parts)):  # longest suffix first
        yield "*." + ".".join(parts[i:])


def resolve_status(destinations: dict, destination: str) -> DestStatus:
    """Exact host first, then the most specific '*.suffix' wildcard, else unknown."""
    host = normalize_destination(destination)
    if host in destinations:
        return destinations[host]
    for pattern in _suffix_patterns(host):
        if pattern in destinations:
            return destinations[pattern]
    return DestStatus.unknown


def pseudonymize(value: str, key: bytes) -> str:
    return "p_" + hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _resolve_key(key) -> bytes:
    if key is None:
        key = os.environ.get(KEY_ENV)
    if key is None:
        log.warning(
            "no pseudonymisation key (%s); using a random per-process key, so agent ids "
            "cannot be linked across restarts", KEY_ENV,
        )
        return secrets.token_bytes(32)
    key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if len(key) < 16:
        raise ValueError("pseudonymisation key must be at least 16 bytes")
    return key


def load_bundle(path, destinations: Optional[dict] = None) -> Bundle:
    """Load a compiled bundle (.json) or compile one from a policy file (.yaml).

    The hash check catches accidental corruption and edits; it is not a signature,
    so it does not stop someone who can rewrite the file and its hash together.
    """
    path = Path(path)
    if path.suffix.lower() == ".json":
        bundle = Bundle.model_validate_json(path.read_text(encoding="utf-8"))
        if policy_hash(bundle) != bundle.policy_hash:
            raise ValueError("policy bundle hash mismatch: the file was changed after compilation")
        return bundle
    return compile_bundle(load_policy(path), destinations)


@dataclass(frozen=True)
class Decision:
    """Outcome of one inspection. If nothing matched, action is log and event is None."""

    action: Action
    classes: list
    destination: str
    evaluation: Evaluation
    truncated: bool
    event: Optional[Layer1Event]

    @property
    def blocked(self) -> bool:
        return self.action is Action.block


class CollectorCore:
    def __init__(
        self,
        bundle: Bundle,
        collector: Collector,
        *,
        buffer: Optional[EventBuffer] = None,
        pseudonym_key=None,
        pseudonymize_ids: bool = True,
    ):
        self.bundle = bundle
        self.collector = collector
        self.buffer = buffer
        self._matcher = Matcher(bundle)
        self._destinations = {normalize_destination(h): s for h, s in bundle.destinations.items()}
        self._ai_hosts = {normalize_destination(h) for h in bundle.ai_hosts}
        self._pseudonymize = pseudonymize_ids
        self._key = _resolve_key(pseudonym_key) if pseudonymize_ids else b""

    def is_inspected_host(self, host: str) -> bool:
        """True if the policy's ai_hosts list covers this host (exact or '*.suffix')."""
        host = normalize_destination(host)
        return host in self._ai_hosts or any(p in self._ai_hosts for p in _suffix_patterns(host))

    def _agent(self, agent_id: Optional[str]) -> Optional[str]:
        if agent_id is None:
            return None
        if not agent_id.strip():
            raise ValueError("agent_id must not be blank")
        return pseudonymize(agent_id, self._key) if self._pseudonymize else agent_id

    def inspect(
        self,
        text: str,
        destination: str,
        *,
        kind: DestKind = DestKind.api,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> Decision:
        host = normalize_destination(destination)
        if not host:
            raise ValueError("destination must not be blank")
        agent = self._agent(agent_id)

        scan = self._matcher.scan(text)
        status = resolve_status(self._destinations, host)
        evaluation = evaluate(self.bundle, scan.classes, status, kind)

        if not scan.classes:
            # nothing sensitive found: nothing to enforce and nothing to record
            return Decision(Action.log, [], host, evaluation, scan.truncated, None)

        event = Layer1Event(
            collector=self.collector, destination=host, classes_matched=scan.classes,
            action=evaluation.action, agent_id=agent, tool_name=tool_name,
        )
        if evaluation.action is Action.log:
            log.debug("policy log: classes=%s destination=%s", scan.classes, host)
        else:
            log.warning("policy %s (%s): classes=%s destination=%s",
                        evaluation.action.value, evaluation.finding, scan.classes, host)
        if self.buffer is not None:
            try:
                self.buffer.add(event)
            except sqlite3.Error as exc:  # a full disk must not disable enforcement
                log.warning("could not buffer event (%s)", type(exc).__name__)
        return Decision(evaluation.action, scan.classes, host, evaluation, scan.truncated, event)

    def flush(self, sender, batch_size: int = 100) -> int:
        if self.buffer is None:
            return 0
        return flush_buffer(self.buffer, sender, batch_size)

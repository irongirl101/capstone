from pathlib import Path

import pytest

from gov.collectors.buffer import EventBuffer
from gov.collectors.core import (
    CollectorCore, load_bundle, normalize_destination, pseudonymize, resolve_status,
)
from gov.common import Action, DestKind, DestStatus
from gov.contracts import Layer1Event
from gov.policy.loader import compile_bundle, load_policy
from gov.policy.schema import Policy

ROOT = Path(__file__).resolve().parents[1]
KEY = "k" * 32
SSN = "123-45-6789"


@pytest.fixture(scope="module")
def policy():
    return load_policy(ROOT / "policy" / "policy.yaml")


def make_core(policy, destinations=None, buffer=None, **kwargs):
    kwargs.setdefault("pseudonym_key", KEY)
    return CollectorCore(compile_bundle(policy, destinations), "agent_hook", buffer=buffer, **kwargs)


@pytest.mark.parametrize("raw,expected", [
    ("API.OpenAI.com", "api.openai.com"),
    ("api.openai.com:443", "api.openai.com"),
    ("https://api.openai.com/v1/chat?q=123-45-6789", "api.openai.com"),
    ("https://user:pw@api.openai.com:8443/x", "api.openai.com"),
    ("api.openai.com.", "api.openai.com"),
    ("  chatgpt.com  ", "chatgpt.com"),
    ("mcp:filesystem", "mcp:filesystem"),
    ("", ""),
])
def test_normalize_destination(raw, expected):
    assert normalize_destination(raw) == expected


def test_resolve_status_exact_wildcard_and_unknown():
    dest = {"api.openai.com": DestStatus.approved, "*.example.com": DestStatus.unapproved,
            "*.corp.example.com": DestStatus.approved}
    assert resolve_status(dest, "API.openai.com:443") is DestStatus.approved
    assert resolve_status(dest, "a.example.com") is DestStatus.unapproved
    assert resolve_status(dest, "x.corp.example.com") is DestStatus.approved  # most specific wins
    assert resolve_status(dest, "example.com") is DestStatus.unknown  # wildcard needs a subdomain
    assert resolve_status(dest, "other.org") is DestStatus.unknown


def test_load_bundle_from_yaml_and_json_roundtrip(policy, tmp_path):
    bundle = load_bundle(ROOT / "policy" / "policy.yaml", {"api.openai.com": "approved"})
    assert bundle.destinations == {"api.openai.com": DestStatus.approved}
    path = tmp_path / "bundle.json"
    path.write_text(bundle.model_dump_json(by_alias=True), encoding="utf-8")
    assert load_bundle(path) == bundle


def test_load_bundle_rejects_edited_bundle(policy, tmp_path):
    bundle = compile_bundle(policy)
    path = tmp_path / "bundle.json"
    path.write_text(bundle.model_dump_json(by_alias=True).replace('"default_action":"log"', '"default_action":"block"'),
                    encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_bundle(path)


def test_ssn_to_unknown_destination_blocks_and_event_is_content_free(policy):
    core = make_core(policy)
    decision = core.inspect(f"my ssn is {SSN}", "api.openai.com", agent_id="alice-laptop")
    assert decision.blocked and decision.classes == ["ssn"]
    assert decision.evaluation.rule_id == "R1"
    event = decision.event
    assert event.collector == "agent_hook" and event.action is Action.block
    dumped = event.model_dump_json()
    assert SSN not in dumped and "my ssn" not in dumped
    assert Layer1Event.model_validate_json(dumped) == event


def test_approved_destination_only_logs(policy):
    core = make_core(policy, {"api.openai.com": "approved"})
    decision = core.inspect(f"ssn {SSN}", "api.openai.com")
    assert decision.action is Action.log and not decision.blocked
    assert decision.evaluation.rule_id == "R3" and decision.event is not None


def test_email_to_unapproved_warns(policy):
    decision = make_core(policy).inspect("mail bob@example.com", "chatgpt.com")
    assert decision.action is Action.warn and not decision.blocked


def test_clean_text_leaves_no_event_and_no_record(policy):
    buffer = EventBuffer()
    decision = make_core(policy, buffer=buffer).inspect("hello world", "api.openai.com")
    assert decision.event is None and decision.classes == [] and decision.action is Action.log
    assert buffer.count() == 0


def test_default_action_block_never_blocks_clean_text(policy):
    data = policy.model_dump(mode="json", by_alias=True)
    data["default_action"] = "block"
    core = make_core(Policy.model_validate(data))
    decision = core.inspect("hello world", "chatgpt.com")
    assert decision.event is None and not decision.blocked


def test_matched_events_are_buffered(policy):
    buffer = EventBuffer()
    core = make_core(policy, buffer=buffer)
    core.inspect(f"ssn {SSN}", "api.openai.com")
    core.inspect("clean", "api.openai.com")
    rows = buffer.pending()
    assert len(rows) == 1
    assert rows[0][2]["classes_matched"] == ["ssn"] and SSN not in str(rows[0][2])


def test_buffer_failure_does_not_disable_enforcement(policy):
    buffer = EventBuffer()
    buffer.close()  # every add() now raises sqlite3.ProgrammingError
    decision = make_core(policy, buffer=buffer).inspect(f"ssn {SSN}", "api.openai.com")
    assert decision.blocked


def test_url_destination_is_reduced_to_host(policy):
    decision = make_core(policy).inspect("x " + SSN, "https://api.openai.com/v1/chat?q=" + SSN)
    assert decision.event.destination == "api.openai.com"
    assert SSN not in decision.event.model_dump_json()


def test_kind_is_passed_to_the_engine(policy):
    data = policy.model_dump(mode="json", by_alias=True)
    data["rules"].insert(0, {"id": "RK", "when": {"class": "ssn", "kind": "mcp"}, "action": "alert",
                             "finding": "MCP_SSN"})
    core = make_core(Policy.model_validate(data))
    assert core.inspect(SSN, "mcp:files", kind=DestKind.mcp).evaluation.rule_id == "RK"
    assert core.inspect(SSN, "api.x.com", kind=DestKind.api).evaluation.rule_id == "R1"


def test_truncation_is_reported(policy):
    data = policy.model_dump(mode="json", by_alias=True)
    data["max_scan_chars"] = 1000
    decision = make_core(Policy.model_validate(data)).inspect("x" * 1000 + " " + SSN, "api.openai.com")
    assert decision.truncated is True and decision.event is None


def test_blank_destination_and_agent_rejected(policy):
    core = make_core(policy)
    with pytest.raises(ValueError):
        core.inspect(SSN, "   ")
    with pytest.raises(ValueError):
        core.inspect(SSN, "api.openai.com", agent_id="  ")


def test_agent_id_is_pseudonymised_and_stable(policy):
    event = make_core(policy).inspect(SSN, "api.openai.com", agent_id="alice@corp.example").event
    assert event.agent_id == pseudonymize("alice@corp.example", KEY.encode())
    assert event.agent_id.startswith("p_") and "alice" not in event.model_dump_json()
    again = make_core(policy).inspect(SSN, "api.openai.com", agent_id="alice@corp.example").event
    assert again.agent_id == event.agent_id
    other = make_core(policy, pseudonym_key="z" * 32).inspect(SSN, "api.openai.com", agent_id="alice@corp.example").event
    assert other.agent_id != event.agent_id


def test_pseudonymisation_can_be_disabled_for_service_ids(policy):
    core = make_core(policy, pseudonymize_ids=False)
    assert core.inspect(SSN, "api.openai.com", agent_id="agent-7").event.agent_id == "agent-7"


def test_short_pseudonym_key_rejected(policy):
    with pytest.raises(ValueError, match="16 bytes"):
        make_core(policy, pseudonym_key="short")


def test_key_from_environment(policy, monkeypatch):
    monkeypatch.setenv("GOV_PSEUDONYM_KEY", "e" * 20)
    core = CollectorCore(compile_bundle(policy), "agent_hook")
    assert core.inspect(SSN, "api.openai.com", agent_id="a").event.agent_id == pseudonymize("a", b"e" * 20)


def test_is_inspected_host_uses_ai_hosts(policy):
    core = make_core(policy)
    assert core.is_inspected_host("API.openai.com:443")
    assert not core.is_inspected_host("example.org")

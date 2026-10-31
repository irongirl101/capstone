from pathlib import Path

import pytest
from pydantic import ValidationError

from gov.common import Action, DestKind, DestStatus
from gov.contracts import Layer1Event
from gov.policy.engine import evaluate
from gov.policy.loader import load_policy
from gov.policy.match import Matcher
from gov.policy.schema import Policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def policy():
    return load_policy(ROOT / "policy" / "policy.yaml")


def simulate(policy, text, destination, status, kind, collector="browser_extension", **metadata):
    scan = Matcher(policy).scan(text)
    decision = evaluate(policy, scan.classes, status, kind)
    event = Layer1Event(
        collector=collector, destination=destination,
        classes_matched=scan.classes, action=decision.action, **metadata,
    )
    return scan, decision, event


@pytest.mark.parametrize("text,destination,status,kind,expected,rule_map", [
    ("SSN: 123-45-6789\nEmail: john@example.com", "chatgpt.com", DestStatus.unapproved, DestKind.web,
     {"ssn": 1, "email": 1}, {"ssn": "R1", "email": "R2"}),
    ("Email: john@example.com", "chatgpt.com", DestStatus.unapproved, DestKind.web,
     {"email": 1}, {"email": "R2"}),
    ("SSN: 123-45-6789", "unknown-destination", DestStatus.unknown, DestKind.web,
     {"ssn": 1}, {"ssn": "R1"}),
    ("Key AKIA1234567890ABCDEF", "api.example.test", DestStatus.approved, DestKind.api,
     {"aws_access_key": 1}, {"aws_access_key": "R4"}),
    ("Hello, how are you?", "chatgpt.com", DestStatus.unapproved, DestKind.web,
     {}, {}),
])
def test_simulated_pipeline_scenarios(policy, text, destination, status, kind, expected, rule_map):
    scan, decision, event = simulate(policy, text, destination, status, kind)
    assert scan.counts == expected
    assert event.classes_matched == scan.classes
    assert event.action == decision.action
    assert event.destination == destination
    assert event.collector == "browser_extension"
    assert decision.per_class == rule_map
    if expected == {"ssn": 1, "email": 1}:
        assert decision.action is Action.block
        assert decision.per_class["ssn"] == "R1" and decision.per_class["email"] == "R2"
        serialized = event.model_dump_json()
        assert "123-45-6789" not in serialized
        assert "john@example.com" not in serialized
        assert text not in serialized
    elif expected == {"email": 1}:
        assert decision.action is Action.warn
    elif expected == {"ssn": 1}:
        assert decision.action is Action.block
    elif expected == {"aws_access_key": 1}:
        assert decision.action is Action.alert
    else:
        assert scan.classes == [] and decision.action is policy.default_action
        assert event.classes_matched == []
    serialized_payload = event.model_dump(mode="json")
    assert Layer1Event.model_validate(serialized_payload) == event


def test_simulated_agent_event_preserves_metadata(policy):
    scan, decision, event = simulate(
        policy, "safe", "mcp:filesystem", DestStatus.approved, DestKind.mcp,
        collector="mcp_stdio_shim", agent_id="agent-7", tool_name="read_file",
    )
    restored = Layer1Event.model_validate_json(event.model_dump_json())
    assert restored.agent_id == "agent-7" and restored.tool_name == "read_file"
    assert restored.action == decision.action and restored.classes_matched == scan.classes


def test_match_result_exposes_counts_not_matched_content(policy):
    text = "SSN: 123-45-6789"
    scan, _, event = simulate(policy, text, "chatgpt.com", DestStatus.unapproved, DestKind.web)
    assert scan.counts == {"ssn": 1}
    assert not hasattr(scan, "matches") and not hasattr(scan, "matched_text")
    assert text not in repr(scan) and text not in event.model_dump_json()


def test_event_rejects_injected_prompt_content(policy):
    scan = Matcher(policy).scan("safe")
    with pytest.raises(ValidationError):
        Layer1Event(collector="browser_extension", destination="chatgpt.com",
                    classes_matched=scan.classes, action=Action.log, prompt_content="unsafe")


def test_truncation_remains_available_on_scan_result():
    small_policy = Policy.model_validate({
        "version": 1, "max_scan_chars": 1000,
        "data_classes": [{"id": "ssn", "tier": "structured", "patterns": [r"\b\d{3}-\d{2}-\d{4}\b"], "validate_with": "ssn_valid", "severity": "high"}],
    })
    text = "x" * 1000 + " 123-45-6789"
    scan = Matcher(small_policy).scan(text)
    decision = evaluate(small_policy, scan.classes, DestStatus.unapproved)
    assert scan.truncated is True and scan.counts == {}
    assert decision.action is small_policy.default_action

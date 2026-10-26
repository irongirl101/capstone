from pathlib import Path

import pytest
from pydantic import ValidationError

from gov.policy.loader import compile_bundle, load_policy, policy_hash
from gov.policy.schema import Bundle, Policy, uncovered_classes

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "policy.yaml"


def base(**over):
    doc = {
        "version": 1,
        "data_classes": [{"id": "ssn", "tier": "structured", "patterns": [r"\d+"], "severity": "high"}],
        "rules": [{"id": "R1", "when": {"class": "ssn"}, "action": "block"}],
    }
    doc.update(over)
    return doc


def test_shipped_policy_loads_and_covers_every_class():
    policy = load_policy(POLICY_PATH)
    assert policy.version == 1
    assert uncovered_classes(policy) == []


def test_minimal_policy_is_valid():
    Policy.model_validate(base())


@pytest.mark.parametrize(
    "bad",
    [
        base(data_classes=[]),
        base(rules=[{"id": "R1", "when": {"class": "nope"}, "action": "block"}]),
        base(rules=[{"id": "R1", "action": "log"}, {"id": "R1", "action": "warn"}]),
        base(data_classes=[{"id": "ssn", "tier": "structured", "patterns": ["("], "severity": "high"}]),
        base(data_classes=[{"id": "ssn", "tier": "structured", "patterns": ["x"], "severity": "high",
                            "validate_with": "does_not_exist"}]),
        base(rules=[{"id": "R1", "when": {"clas": "ssn"}, "action": "block"}]),  # typo in key
        base(default_action="explode"),
        base(version=0),
    ],
)
def test_invalid_policies_are_rejected(bad):
    with pytest.raises(ValidationError):
        Policy.model_validate(bad)


def test_uncovered_class_is_reported():
    doc = base(data_classes=[
        {"id": "ssn", "tier": "structured", "patterns": ["x"], "severity": "high"},
        {"id": "email", "tier": "structured", "patterns": ["x"], "severity": "low"},
    ])
    assert uncovered_classes(Policy.model_validate(doc)) == ["email"]


def test_hash_changes_when_a_rule_changes():
    a = Policy.model_validate(base())
    b = Policy.model_validate(base(rules=[{"id": "R1", "when": {"class": "ssn"}, "action": "warn"}]))
    assert policy_hash(a) != policy_hash(b)
    assert policy_hash(a) == policy_hash(Policy.model_validate(base()))


def test_bundle_round_trips_through_json():
    policy = load_policy(POLICY_PATH)
    bundle = compile_bundle(policy, {"chat.example.com": "approved"})
    dumped = bundle.model_dump(mode="json", by_alias=True)
    again = Bundle.model_validate(dumped)
    assert again == bundle
    assert again.policy_hash == policy_hash(policy)
    assert again.destinations == {"chat.example.com": "approved"}
    assert policy_hash(again) == policy_hash(policy)  # bundle extras don't affect the hash
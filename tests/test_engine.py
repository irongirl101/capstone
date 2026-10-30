from itertools import permutations
from pathlib import Path

import pytest

from gov.common import Action, DestKind, DestStatus, Severity
from gov.policy.engine import evaluate
from gov.policy.loader import load_policy
from gov.policy.schema import Policy

ROOT = Path(__file__).resolve().parents[1]
UN, UNK, APP = DestStatus.unapproved, DestStatus.unknown, DestStatus.approved


@pytest.fixture(scope="module")
def policy():
    return load_policy(ROOT / "policy" / "policy.yaml")


def make(rules, default="log"):
    return Policy.model_validate({
        "version": 1,
        "default_action": default,
        "data_classes": [
            {"id": "ssn", "tier": "structured", "patterns": ["x"], "severity": "high"},
            {"id": "email", "tier": "structured", "patterns": ["x"], "severity": "low"},
        ],
        "rules": rules,
    })


@pytest.mark.parametrize(
    "classes,status,action,rule,finding,severity",
    [
        (["ssn"], UN, Action.block, "R1", "SENSITIVE_TO_UNAPPROVED", Severity.high),
        (["ssn"], UNK, Action.block, "R1", "SENSITIVE_TO_UNAPPROVED", Severity.high),
        (["ssn"], APP, Action.log, "R3", "SENSITIVE_TO_APPROVED", Severity.low),
        (["email"], UN, Action.warn, "R2", "PII_TO_UNAPPROVED", Severity.low),
        (["email"], APP, Action.log, None, "DEFAULT_POLICY", Severity.low),
        (["aws_access_key"], APP, Action.alert, "R4", "CREDENTIAL_EXPOSURE", Severity.high),
        (["email", "ssn"], UN, Action.block, "R1", "SENSITIVE_TO_UNAPPROVED", Severity.high),
    ],
)
def test_shipped_policy(policy, classes, status, action, rule, finding, severity):
    result = evaluate(policy, classes, status)
    assert (result.action, result.rule_id, result.finding, result.severity) == (action, rule, finding, severity)


def test_per_class_shows_which_rule_matched_each_class(policy):
    result = evaluate(policy, ["email", "ssn"], UN)
    assert result.per_class == {"email": "R2", "ssn": "R1"}


def test_empty_classes_falls_back_to_default(policy):
    result = evaluate(policy, [], UN)
    assert (result.action, result.rule_id, result.finding) == (Action.log, None, "NO_CLASSES")


def test_unknown_class_gets_default_action_and_medium_severity(policy):
    result = evaluate(policy, ["mystery"], UN)
    assert (result.action, result.rule_id, result.severity) == (Action.log, None, Severity.medium)


def test_first_matching_rule_wins():
    policy = make([
        {"id": "A", "when": {"class": "ssn"}, "action": "warn"},
        {"id": "B", "when": {"class": "ssn"}, "action": "block"},
    ])
    assert evaluate(policy, ["ssn"], UN).rule_id == "A"


def test_catch_all_rule_matches_any_class():
    policy = make([{"id": "ALL", "action": "alert"}])
    assert evaluate(policy, ["email"], APP).rule_id == "ALL"


def test_kind_condition():
    policy = make([{"id": "API", "when": {"class": "ssn", "kind": "api"}, "action": "block"}])
    assert evaluate(policy, ["ssn"], UN, DestKind.api).rule_id == "API"
    assert evaluate(policy, ["ssn"], UN, DestKind.web).rule_id is None
    assert evaluate(policy, ["ssn"], UN, None).rule_id is None  # rule needs a kind, none given


def test_equal_action_ties_go_to_higher_severity():
    policy = make([
        {"id": "E", "when": {"class": "email"}, "action": "warn"},
        {"id": "S", "when": {"class": "ssn"}, "action": "warn"},
    ])
    assert evaluate(policy, ["email", "ssn"], UN).rule_id == "S"  # ssn is high, email is low


def test_result_does_not_depend_on_class_order(policy):
    classes = ["ssn", "email", "credit_card", "aws_access_key"]
    results = [evaluate(policy, list(p), UN) for p in permutations(classes)]
    assert all(r == results[0] for r in results)
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


def test_shipped_policy_covers_all_sensitive_classes(policy):
    for class_id in ["ssn", "credit_card", "aws_access_key", "private_key_block"]:
        for status in [UN, UNK]:
            result = evaluate(policy, [class_id], status)
            assert (result.action, result.rule_id, result.finding) == (
                Action.block, "R1", "SENSITIVE_TO_UNAPPROVED")
    for class_id in ["ssn", "credit_card"]:
        result = evaluate(policy, [class_id], APP)
        assert result.action is Action.log and result.rule_id == "R3"
        assert result.severity is Severity.low
    for class_id in ["aws_access_key", "private_key_block"]:
        result = evaluate(policy, [class_id], APP)
        assert result.action is Action.alert and result.rule_id == "R4"
        assert result.severity is Severity.high
    for status in [UN, UNK]:
        result = evaluate(policy, ["email"], status)
        assert (result.action, result.rule_id, result.finding) == (
            Action.warn, "R2", "PII_TO_UNAPPROVED")
        assert result.severity is Severity.low


def test_precedence_across_classes():
    classes = ["a", "b", "c", "d"]
    rules = [{"id": f"R_{cid}", "when": {"class": cid}, "action": action}
             for cid, action in zip(classes, ["log", "warn", "alert", "block"])]
    policy = Policy.model_validate({"version": 1, "data_classes": [
        {"id": cid, "tier": "structured", "patterns": ["x"], "severity": "low"}
        for cid in classes], "rules": rules})
    assert evaluate(policy, classes, UN).action is Action.block
    for lower, upper, expected in [("a", "b", "warn"), ("b", "c", "alert"), ("c", "d", "block")]:
        pair = evaluate(policy, [lower, upper], UN)
        assert pair.action.value == expected


def test_equal_action_tie_uses_lexicographic_class_id():
    policy = Policy.model_validate({"version": 1, "data_classes": [
        {"id": cid, "tier": "structured", "patterns": ["x"], "severity": "medium"}
        for cid in ["alpha", "zeta"]], "rules": [
        {"id": "Z_RULE", "when": {"class": "zeta"}, "action": "warn", "finding": "ZETA_FINDING"},
        {"id": "A_RULE", "when": {"class": "alpha"}, "action": "warn", "finding": "ALPHA_FINDING"},
    ]})
    forward = evaluate(policy, ["zeta", "alpha"], UN)
    reverse = evaluate(policy, ["alpha", "zeta"], UN)
    assert forward == reverse
    assert (forward.rule_id, forward.finding) == ("A_RULE", "ALPHA_FINDING")


def test_rule_severity_overrides_class_severity():
    policy = make([{"id": "LOW", "when": {"class": "ssn"}, "action": "warn", "severity": "low"}])
    assert evaluate(policy, ["ssn"], UN).severity is Severity.low


def test_unmatched_class_default_and_per_class_tracking():
    policy = make([{"id": "SSN", "when": {"class": "ssn"}, "action": "alert"}])
    result = evaluate(policy, ["ssn", "email"], UN)
    assert result.per_class == {"email": None, "ssn": "SSN"}
    assert result.rule_id == "SSN"
    unmatched = evaluate(policy, ["email"], UN)
    assert (unmatched.action, unmatched.rule_id, unmatched.finding, unmatched.severity) == (
        Action.log, None, "DEFAULT_POLICY", Severity.low)
    assert unmatched.per_class == {"email": None}


def test_all_conditions_required_and_scalar_list_forms():
    policy = make([{
        "id": "STRICT", "when": {"class": "ssn", "dest_status": "unapproved", "kind": "web"},
        "action": "block",
    }])
    assert evaluate(policy, ["ssn"], UN, DestKind.web).rule_id == "STRICT"
    assert evaluate(policy, ["email"], UN, DestKind.web).rule_id is None
    assert evaluate(policy, ["ssn"], APP, DestKind.web).rule_id is None
    assert evaluate(policy, ["ssn"], UN, DestKind.api).rule_id is None
    assert evaluate(policy, ["ssn"], UN, None).rule_id is None
    list_policy = make([{
        "id": "LIST", "when": {"class": ["ssn", "email"], "dest_status": ["unapproved", "unknown"],
                                  "kind": ["web", "api"]}, "action": "warn",
    }])
    assert evaluate(list_policy, ["email"], UNK, DestKind.api).rule_id == "LIST"
    assert evaluate(list_policy, ["ssn"], APP, DestKind.api).rule_id is None


def test_omitted_conditions_are_wildcards_and_kind_omission_matches():
    policy = make([{"id": "ALL", "action": "alert"}])
    assert evaluate(policy, ["email"], APP, None).rule_id == "ALL"


def test_duplicate_classes_generator_and_order_independence(policy):
    duplicate = evaluate(policy, ["ssn", "email", "ssn"], UN)
    generated = evaluate(policy, (value for value in ["email", "ssn"]), UN)
    reversed_result = evaluate(policy, ["email", "ssn"], UN)
    assert len(duplicate.per_class) == 2
    assert duplicate == generated == reversed_result

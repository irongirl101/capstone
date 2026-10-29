import json
import time
from pathlib import Path

import pytest

from gov.policy.loader import load_policy
from gov.policy.match import Matcher
from gov.policy.schema import KNOWN_VALIDATORS, Policy
from gov.policy.validators import VALIDATORS, luhn, ssn_valid

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "vectors" / "matcher_vectors.json").read_text())


@pytest.fixture(scope="module")
def policy():
    return load_policy(ROOT / "policy" / "policy.yaml")


@pytest.fixture(scope="module")
def matcher(policy):
    return Matcher(policy)


@pytest.mark.parametrize("vec", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(matcher, vec):
    assert matcher.scan(vec["text"]).counts == vec["expect"]


def test_known_validator_names_match_implementations():
    assert KNOWN_VALIDATORS == set(VALIDATORS)


def test_luhn_and_ssn_validators():
    assert luhn("4111111111111111") and not luhn("4111111111111112")
    assert not luhn("123")  # too short
    assert ssn_valid("123-45-6789")
    assert not ssn_valid("666-12-3456") and not ssn_valid("900-12-3456")


def test_result_holds_counts_not_content(matcher):
    secret = "123-45-6789"
    result = matcher.scan(f"ssn {secret}")
    assert secret not in repr(result)
    assert result.classes == ["ssn"] and result.total == 1 and not result.truncated


def test_long_text_is_truncated(policy):
    small = Policy.model_validate({**policy.model_dump(mode="json", by_alias=True), "max_scan_chars": 1000})
    result = Matcher(small).scan("a" * 1000 + " 123-45-6789")
    assert result.truncated and result.counts == {}


def test_scan_stays_fast_on_digit_heavy_input(matcher):
    text = "1 " * 100_000  # 200k chars, worst-ish case for the card pattern
    start = time.perf_counter()
    matcher.scan(text)
    assert time.perf_counter() - start < 5  # smoke test, not a proof against ReDoS
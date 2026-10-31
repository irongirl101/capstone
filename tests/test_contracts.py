import json

import pytest
from pydantic import ValidationError

from gov.common import Action, Strict
from gov.contracts import Layer1Event


BASE = {"collector": "browser_extension", "destination": "chatgpt.com",
        "classes_matched": ["ssn"], "action": "block"}
COLLECTORS = ["browser_extension", "egress_proxy", "agent_hook", "mcp_stdio_shim"]


def test_valid_browser_event():
    event = Layer1Event.model_validate(BASE)
    assert event.action is Action.block
    assert event.destination == "chatgpt.com"


@pytest.mark.parametrize("collector", COLLECTORS)
def test_supported_collectors(collector):
    assert Layer1Event.model_validate({**BASE, "collector": collector}).collector == collector


@pytest.mark.parametrize("field", ["collector", "destination", "classes_matched", "action"])
def test_required_fields(field):
    payload = BASE.copy()
    del payload[field]
    with pytest.raises(ValidationError):
        Layer1Event.model_validate(payload)


def test_invalid_collector_and_action_rejected():
    for field, value in [("collector", "unknown"), ("action", "delete")]:
        with pytest.raises(ValidationError):
            Layer1Event.model_validate({**BASE, field: value})


@pytest.mark.parametrize("action", ["log", "warn", "alert", "block"])
def test_supported_actions(action):
    assert Layer1Event.model_validate({**BASE, "action": action}).action.value == action


@pytest.mark.parametrize("destination", ["", "  \t"])
def test_destination_must_be_nonblank(destination):
    with pytest.raises(ValidationError):
        Layer1Event.model_validate({**BASE, "destination": destination})


def test_empty_and_multiple_classes_are_valid():
    assert Layer1Event.model_validate({**BASE, "classes_matched": []}).classes_matched == []
    assert Layer1Event.model_validate({**BASE, "classes_matched": ["ssn", "email"]}).classes_matched == ["ssn", "email"]


def test_duplicate_classes_rejected():
    with pytest.raises(ValidationError):
        Layer1Event.model_validate({**BASE, "classes_matched": ["ssn", "ssn"]})


def test_optional_metadata_defaults_and_accepts_partial_values():
    event = Layer1Event.model_validate(BASE)
    assert event.agent_id is None and event.tool_name is None
    assert Layer1Event.model_validate({**BASE, "agent_id": "agent-1"}).agent_id == "agent-1"
    assert Layer1Event.model_validate({**BASE, "tool_name": "search"}).tool_name == "search"
    assert Layer1Event.model_validate({**BASE, "agent_id": "agent-1", "tool_name": "search"})
    assert Layer1Event.model_validate({**BASE, "agent_id": None, "tool_name": None})


@pytest.mark.parametrize("field", ["agent_id", "tool_name"])
def test_optional_identifiers_must_not_be_blank(field):
    for value in ["", " \t"]:
        with pytest.raises(ValidationError):
            Layer1Event.model_validate({**BASE, field: value})


@pytest.mark.parametrize("field", ["prompt_content", "request_body", "matched_text", "raw_content", "arbitrary"])
def test_extra_content_and_metadata_rejected(field):
    with pytest.raises(ValidationError):
        Layer1Event.model_validate({**BASE, field: "secret"})


def test_contract_is_strict_and_declares_no_content_fields():
    assert issubclass(Layer1Event, Strict)
    names = set(Layer1Event.model_fields)
    assert not names & {"prompt", "prompt_content", "request_body", "raw_message", "matched_text", "raw_content"}


def test_json_serialization_and_round_trip():
    event = Layer1Event.model_validate({**BASE, "agent_id": "agent-1", "tool_name": "search"})
    payload = event.model_dump(mode="json")
    assert payload["action"] == "block"
    json.dumps(payload)
    restored = Layer1Event.model_validate(payload)
    assert restored == event
    assert restored.agent_id == "agent-1" and restored.tool_name == "search"

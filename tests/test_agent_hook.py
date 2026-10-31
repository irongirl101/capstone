import asyncio
from pathlib import Path

import pytest

from gov.collectors.agent_hook import AgentHook, BlockedByPolicy
from gov.collectors.buffer import EventBuffer
from gov.collectors.core import load_bundle
from gov.collectors.payload import flatten_text
from gov.common import Action, DestKind
from gov.contracts import Layer1Event

ROOT = Path(__file__).resolve().parents[1]
SSN = "123-45-6789"
KEY = "k" * 32


def make_hook(destinations=None, **kwargs):
    buffer = EventBuffer()
    bundle = load_bundle(ROOT / "policy" / "policy.yaml", destinations)
    return AgentHook.from_bundle(bundle, agent_id="test-agent", buffer=buffer, pseudonym_key=KEY, **kwargs), buffer


def test_planted_ssn_is_blocked_and_produces_a_valid_event():
    """The end-to-end check: a test agent with a planted fake SSN."""
    hook, buffer = make_hook()
    ran = []

    @hook.guard("api.openai.com")
    def send_prompt(prompt):
        ran.append(prompt)

    with pytest.raises(BlockedByPolicy) as info:
        send_prompt(f"Summarise: Customer SSN {SSN}")
    assert ran == []  # the call never happened
    assert SSN not in str(info.value) and SSN not in repr(info.value)
    [(_, _, payload)] = buffer.pending()
    event = Layer1Event.model_validate(payload)
    assert event.collector == "agent_hook" and event.action is Action.block
    assert event.classes_matched == ["ssn"] and event.destination == "api.openai.com"
    assert event.tool_name == "send_prompt"
    assert event.agent_id.startswith("p_") and "test-agent" not in event.model_dump_json()
    assert SSN not in event.model_dump_json()


def test_clean_content_passes_without_event():
    hook, buffer = make_hook()

    @hook.guard("api.openai.com")
    def send_prompt(prompt):
        return "sent"

    assert send_prompt("hello there") == "sent"
    assert buffer.count() == 0


def test_approved_destination_is_logged_not_blocked():
    hook, buffer = make_hook({"api.openai.com": "approved"})

    @hook.guard("api.openai.com")
    def send_prompt(prompt):
        return "sent"

    assert send_prompt(f"ssn {SSN}") == "sent"
    assert buffer.pending()[0][2]["action"] == "log"


def test_warn_does_not_raise():
    hook, buffer = make_hook()
    decision = hook.check("contact bob@example.com", "chatgpt.com")
    assert decision.action is Action.warn and buffer.count() == 1


def test_check_accepts_nested_structures_and_bytes():
    hook, _ = make_hook()
    with pytest.raises(BlockedByPolicy):
        hook.check({"messages": [{"role": "user", "content": f"ssn {SSN}"}]}, "api.openai.com")
    with pytest.raises(BlockedByPolicy):
        hook.check([SSN.encode()], "api.openai.com")


def test_guard_reads_keyword_arguments_and_skips_self():
    hook, _ = make_hook()

    class Client:
        @hook.guard("api.openai.com", tool_name="chat")
        def send(self, *, prompt):
            return "ok"

    assert Client().send(prompt="fine") == "ok"
    with pytest.raises(BlockedByPolicy):
        Client().send(prompt=SSN)


def test_guard_supports_async_functions():
    hook, _ = make_hook()

    @hook.guard("api.openai.com")
    async def send(prompt):
        return "ok"

    assert asyncio.run(send("fine")) == "ok"
    with pytest.raises(BlockedByPolicy):
        asyncio.run(send(SSN))


def test_guard_preserves_function_metadata():
    hook, _ = make_hook()

    @hook.guard("api.openai.com")
    def documented():
        """docs"""

    assert documented.__name__ == "documented" and documented.__doc__ == "docs"


def test_kind_is_forwarded():
    hook, buffer = make_hook()
    hook.check("clean", "mcp:files", kind=DestKind.mcp)
    assert buffer.count() == 0


def test_flatten_text_reads_only_strings_bytes_ints():
    text = flatten_text({"a": ["x", b"y"], "n": 42, "flag": True, "f": 1.5, "o": object(), "k": None})
    assert text.split("\n") == ["a", "x", "y", "n", "42", "flag", "f", "o", "k"]


def test_flatten_text_is_bounded():
    deep = current = []
    for _ in range(50):
        nxt = []
        current.append(nxt)
        current = nxt
    current.append("buried")
    assert flatten_text(deep) == ""  # deeper than max_depth: not read, and no recursion error
    assert flatten_text(["a"] * 10, max_nodes=3) == "a\na"  # node cap
    assert flatten_text(deep, max_depth=100) == "buried"

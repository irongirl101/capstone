"""Agent-side hook: scans what an agent is about to send, before it is sent.

It is a cooperative collector. It sees plaintext inside the agent process, needs no
certificates or routing, and works for any destination. An agent that does not load it,
or a malicious one that skips it, is not covered; the egress proxy is the net for those.

Policy actions: block raises BlockedByPolicy and the wrapped call never runs. warn and
alert are logged and the call proceeds. log records the event. Any other error raised
while inspecting propagates, so a failure stops the call instead of letting data through.
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Optional

from gov.collectors.buffer import EventBuffer
from gov.collectors.core import CollectorCore, Decision
from gov.collectors.payload import flatten_text
from gov.common import DestKind
from gov.policy.schema import Bundle


class BlockedByPolicy(Exception):
    """Raised when policy says block. The message names classes and host, never content."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            f"blocked by policy ({decision.evaluation.finding}): "
            f"classes={decision.classes} destination={decision.destination}"
        )


class AgentHook:
    def __init__(self, core: CollectorCore, agent_id: Optional[str] = None):
        self.core = core
        self.agent_id = agent_id

    @classmethod
    def from_bundle(cls, bundle: Bundle, agent_id: Optional[str] = None,
                    buffer: Optional[EventBuffer] = None, **core_kwargs) -> "AgentHook":
        return cls(CollectorCore(bundle, "agent_hook", buffer=buffer, **core_kwargs), agent_id)

    def check(self, content: Any, destination: str, *, kind: DestKind = DestKind.api,
              tool_name: Optional[str] = None) -> Decision:
        """Scan content (a string or a nested structure) headed to destination."""
        text = content if isinstance(content, str) else flatten_text(content)
        decision = self.core.inspect(text, destination, kind=kind, agent_id=self.agent_id, tool_name=tool_name)
        if decision.blocked:
            raise BlockedByPolicy(decision)
        return decision

    def guard(self, destination: str, *, kind: DestKind = DestKind.api, tool_name: Optional[str] = None):
        """Decorator: scan a function's string/bytes/int arguments before it runs."""

        def decorate(fn):
            name = tool_name or fn.__name__

            def scan(args, kwargs):
                self.check((args, kwargs), destination, kind=kind, tool_name=name)

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapper(*args, **kwargs):
                    scan(args, kwargs)
                    return await fn(*args, **kwargs)
                return awrapper

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                scan(args, kwargs)
                return fn(*args, **kwargs)
            return wrapper

        return decorate

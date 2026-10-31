"""Strict, content-free event contract shared by Layer 1 collectors."""

from typing import Literal

from pydantic import Field, field_validator

from gov.common import Action, Strict


Collector = Literal["browser_extension", "egress_proxy", "agent_hook", "mcp_stdio_shim"]


class Layer1Event(Strict):
    """Detection metadata and local policy decision; never original content."""

    collector: Collector
    destination: str = Field(min_length=1)
    classes_matched: list[str]
    action: Action
    agent_id: str | None = None
    tool_name: str | None = None

    @field_validator("destination", "agent_id", "tool_name")
    @classmethod
    def _nonblank_identifiers(cls, value):
        if value is not None and not value.strip():
            raise ValueError("identifier must not be blank")
        return value

    @field_validator("classes_matched")
    @classmethod
    def _unique_class_ids(cls, values):
        if len(values) != len(set(values)):
            raise ValueError("classes_matched must not contain duplicates")
        if any(not value.strip() for value in values):
            raise ValueError("class identifiers must not be blank")
        return values

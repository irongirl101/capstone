"""Shared base model and enums used across layers."""
from enum import Enum
 
from pydantic import BaseModel, ConfigDict  # pyright: ignore[reportMissingImports]
 
class Strict(BaseModel):
    """Unknown fields are rejected, so typos and stray data fail loudly."""
 
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
 
 
class Action(str, Enum):
    log = "log"
    warn = "warn"
    alert = "alert"
    block = "block"
 
 
class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
 
 
class DestStatus(str, Enum):
    approved = "approved"
    unapproved = "unapproved"
    unknown = "unknown"
 
 
class DestKind(str, Enum):
    web = "web"
    api = "api"
    mcp = "mcp"
    agent = "agent"
 
 
ACTION_RANK = {Action.log: 0, Action.warn: 1, Action.alert: 2, Action.block: 3}
SEVERITY_RANK = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3}
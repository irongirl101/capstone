"""Layer 0: the policy schema. The YAML policy file is validated against this."""
import re
from typing import Annotated, Literal, Optional, Union

from pydantic import Field, StringConstraints, field_validator, model_validator

from gov.common import Action, DestKind, DestStatus, Severity, Strict

ClassId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,39}$")]
RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")]
FindingName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]

# Implemented in aigov/policy/validators.py (next part). Names must stay in sync.
KNOWN_VALIDATORS = {"luhn", "ssn_valid"}


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class DataClass(Strict):
    id: ClassId
    tier: Literal["structured", "regulated", "credential", "unstructured"]
    description: str = ""
    patterns: list[str] = Field(min_length=1)
    validate_with: Optional[str] = None
    severity: Severity

    @field_validator("patterns")
    @classmethod
    def _patterns_compile(cls, patterns):
        for p in patterns:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid regex {p!r}: {exc}") from exc
        return patterns

    @field_validator("validate_with")
    @classmethod
    def _known_validator(cls, name):
        if name is not None and name not in KNOWN_VALIDATORS:
            raise ValueError(f"unknown validator {name!r}; known: {sorted(KNOWN_VALIDATORS)}")
        return name


class When(Strict):
    """All given conditions must hold; omitted conditions match anything."""

    data_class: Union[str, list[str], None] = Field(default=None, alias="class")
    dest_status: Union[DestStatus, list[DestStatus], None] = None
    kind: Union[DestKind, list[DestKind], None] = None


class Rule(Strict):
    id: RuleId
    when: When = Field(default_factory=When)
    action: Action
    finding: FindingName = "POLICY_VIOLATION"
    severity: Optional[Severity] = None


class Policy(Strict):
    version: int = Field(ge=1)
    max_scan_chars: int = Field(default=200_000, ge=1_000, le=5_000_000)
    ai_hosts: list[str] = Field(default_factory=list)
    data_classes: list[DataClass] = Field(min_length=1)
    rules: list[Rule] = Field(default_factory=list)
    default_action: Action = Action.log

    @model_validator(mode="after")
    def _check_references(self):
        class_ids = [d.id for d in self.data_classes]
        if len(set(class_ids)) != len(class_ids):
            raise ValueError("duplicate data class ids")
        rule_ids = [r.id for r in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("duplicate rule ids")
        known = set(class_ids)
        for rule in self.rules:
            for cid in as_list(rule.when.data_class):
                if cid not in known:
                    raise ValueError(f"rule {rule.id} references unknown data class {cid!r}")
        return self


class Bundle(Policy):
    """The compiled policy that collectors load: policy + hash + destination snapshot."""

    policy_hash: str
    destinations: dict[str, DestStatus] = Field(default_factory=dict)


def uncovered_classes(policy: Policy) -> list[str]:
    """Data classes that no rule can ever match (they would fall to default_action)."""
    covered = set()
    for rule in policy.rules:
        classes = as_list(rule.when.data_class)
        if not classes:
            return []  # a catch-all rule covers everything
        covered.update(classes)
    return [d.id for d in policy.data_classes if d.id not in covered]
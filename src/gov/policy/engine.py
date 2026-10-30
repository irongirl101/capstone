"""Layer 0's evaluator: what does the policy say to do for this case?

A pure function. It reads no database, scans no text and logs nothing. The caller
supplies the matched data classes and the destination status. Collectors use it for
local enforcement and Layer 3 (Check B) uses it for the decision of record.
"""
from dataclasses import dataclass
from typing import Iterable, Optional

from aigov.common import ACTION_RANK, SEVERITY_RANK, Action, DestKind, DestStatus, Severity
from aigov.policy.schema import Policy, When, as_list


@dataclass(frozen=True)
class Evaluation:
    action: Action
    rule_id: Optional[str]  # None when no rule matched and default_action applied
    finding: str
    severity: Severity
    per_class: dict  # data class id -> id of the rule that matched it (or None)


def _matches(when: When, class_id: str, dest_status: DestStatus, kind: Optional[DestKind]) -> bool:
    classes = as_list(when.data_class)
    if classes and class_id not in classes:
        return False
    statuses = as_list(when.dest_status)
    if statuses and dest_status not in statuses:
        return False
    kinds = as_list(when.kind)
    if kinds and (kind is None or kind not in kinds):
        return False
    return True


def evaluate(
    policy: Policy,
    classes: Iterable[str],
    dest_status: DestStatus,
    kind: Optional[DestKind] = None,
) -> Evaluation:
    """First matching rule wins per class; the strictest action across classes wins overall.

    Ties on action go to the higher severity, then to the class that sorts first, so the
    result never depends on the order the classes arrive in.
    """
    severity_of = {d.id: d.severity for d in policy.data_classes}
    wanted = sorted(set(classes))
    if not wanted:
        return Evaluation(policy.default_action, None, "NO_CLASSES", Severity.info, {})

    best_key, best, per_class = None, None, {}
    for class_id in wanted:
        rule = next((r for r in policy.rules if _matches(r.when, class_id, dest_status, kind)), None)
        class_severity = severity_of.get(class_id, Severity.medium)  # unknown class: medium
        if rule is not None:
            action, rule_id, finding = rule.action, rule.id, rule.finding
            severity = rule.severity or class_severity
        else:
            action, rule_id, finding, severity = policy.default_action, None, "DEFAULT_POLICY", class_severity
        per_class[class_id] = rule_id
        key = (ACTION_RANK[action], SEVERITY_RANK[severity])
        if best_key is None or key > best_key:
            best_key, best = key, (action, rule_id, finding, severity)

    action, rule_id, finding, severity = best
    return Evaluation(action, rule_id, finding, severity, per_class)
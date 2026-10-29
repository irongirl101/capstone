"""The matcher: scans text for the policy's data classes.

It returns counts only. The matched text is never stored or returned, so every
collector (proxy, agent hook, extension) can share it without leaking content.
"""
import re
from dataclasses import dataclass

from gov.policy.schema import Policy
from gov.policy.validators import VALIDATORS


@dataclass(frozen=True)
class ScanResult:
    counts: dict  # data class id -> number of validated matches
    truncated: bool  # True if the text was longer than max_scan_chars

    @property
    def classes(self) -> list:
        return sorted(self.counts)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Matcher:
    def __init__(self, policy: Policy):
        self._max_chars = policy.max_scan_chars
        self._classes = [
            (
                dc.id,
                [re.compile(p) for p in dc.patterns],
                VALIDATORS[dc.validate_with] if dc.validate_with else None,
            )
            for dc in policy.data_classes
        ]

    def scan(self, text: str) -> ScanResult:
        truncated = len(text) > self._max_chars
        text = text[: self._max_chars]
        counts = {}
        for class_id, patterns, validator in self._classes:
            n = 0
            for pattern in patterns:
                for match in pattern.finditer(text):
                    if validator is None or validator(match.group(0)):
                        n += 1
            if n:
                counts[class_id] = n
        return ScanResult(counts=counts, truncated=truncated)
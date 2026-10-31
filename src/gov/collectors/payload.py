"""Turn structured payloads (tool arguments, JSON bodies) into scannable text.

Only strings, bytes and integers are read. Other objects are ignored, so nothing is
ever rendered through repr() or str() by accident. Traversal is iterative and capped
by depth and node count, so a hostile or huge structure cannot exhaust the stack.
Content beyond those caps is not scanned; that is a coverage limit, not an error.
"""
from __future__ import annotations

from typing import Any

MAX_DEPTH = 20
MAX_NODES = 100_000


def flatten_text(value: Any, *, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES) -> str:
    parts: list[str] = []
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            break
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, (bytes, bytearray)):
            parts.append(bytes(item).decode("utf-8", errors="replace"))
        elif isinstance(item, bool):
            continue
        elif isinstance(item, int):
            parts.append(str(item))
        elif depth < max_depth:
            if isinstance(item, dict):
                # push value then key so the key is popped (read) first
                for key, val in reversed(list(item.items())):
                    stack.append((val, depth + 1))
                    stack.append((key, depth + 1))
            elif isinstance(item, (list, tuple, set, frozenset)):
                for val in reversed(list(item)):
                    stack.append((val, depth + 1))
    return "\n".join(parts)

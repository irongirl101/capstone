"""Load, hash and compile the policy file into a bundle."""
import hashlib
import json
from pathlib import Path
from typing import Optional

import yaml

from gov.policy.schema import Bundle, Policy


def load_policy(path) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Policy.model_validate(data)


def canonical(obj) -> str:
    """Stable JSON text, used for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _policy_fields(policy: Policy) -> dict:
    dumped = policy.model_dump(mode="json", by_alias=True)
    return {k: v for k, v in dumped.items() if k in Policy.model_fields}


def policy_hash(policy: Policy) -> str:
    return hashlib.sha256(canonical(_policy_fields(policy)).encode("utf-8")).hexdigest()


def compile_bundle(policy: Policy, destinations: Optional[dict] = None) -> Bundle:
    """destinations is a snapshot of the registry (host -> status); the registry stays
    the source of truth, the bundle is a derived copy for offline enforcement."""
    fields = _policy_fields(policy)
    fields["policy_hash"] = policy_hash(policy)
    fields["destinations"] = dict(sorted((destinations or {}).items()))
    return Bundle.model_validate(fields)
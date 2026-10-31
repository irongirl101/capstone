# capstone
well figrue this out 
This repository contains a policy loader, sensitive-data matcher, policy evaluator, and the strict Layer 1 event contract used by simulated collectors.

## Setup

The project metadata declares the runtime dependencies (`pydantic` and `pyyaml`) and a development extra containing `pytest`. Install the project and all test dependencies into the active Python environment with:

```bash
python3 -m pip install -e '.[dev]'
```

For an isolated environment, create and activate a virtual environment first:

```bash
python3 -m venv .venv
source .venv/bin/activate       # macOS/Linux
python -m pip install -e '.[dev]'
```

## Run the tests

From the repository root, run the full suite manually with:

```bash
python -m pytest -v
```

For a concise result, use:

```bash
python -m pytest -q
```

The suite covers policy validation, matcher behavior, evaluator decisions and deterministic rule selection, strict `Layer1Event` validation, and simulated matcher → evaluator → event pipelines. It does not require a browser extension, proxy, MCP server, database, or network service.

## Source layout

- `policy/policy.yaml` — shipped policy defining data classes, rules, destinations, and the default action.
- `src/gov/common.py` — shared strict model base and enums for actions, severities, destination statuses, and destination kinds.
- `src/gov/policy/schema.py` — Pydantic schema and validation for policies.
- `src/gov/policy/loader.py` — YAML loading, hashing, and bundle compilation.
- `src/gov/policy/match.py` — regex and validator-based scanning that returns counts and class IDs, never matched content.
- `src/gov/policy/engine.py` — pure policy evaluation with per-class rule tracking and deterministic precedence.
- `src/gov/contracts.py` — strict, content-free `Layer1Event` contract for collector metadata and the selected action.
- `tests/` — unit and simulated integration tests.

## Layer 1 collectors

All collectors are thin adapters around `gov.collectors.core.CollectorCore`, which loads the policy bundle, scans text with the shared matcher, applies the policy engine, builds a content-free `Layer1Event`, buffers it locally and delivers it over HTTPS. Clean traffic produces no event.

- `src/gov/collectors/core.py` — shared pipeline, destination normalisation and wildcard lookup, id pseudonymisation.
- `src/gov/collectors/buffer.py` — SQLite event buffer with age and count retention, HTTPS sender, background flusher.
- `src/gov/collectors/payload.py` — flattens nested tool arguments and JSON into scannable text.
- `src/gov/collectors/agent_hook.py` — agent-side hook (`AgentHook.check`, `AgentHook.guard`).
- `src/gov/collectors/egress_proxy.py` — mitmproxy addon for requests to the policy's `ai_hosts`.
- `examples/demo_agent_hook.py` — test agent with a planted fake SSN.
- `docs/GDPR.md` — data-protection design notes and deployer obligations.

### Agent-side hook

```python
from gov.collectors.agent_hook import AgentHook, BlockedByPolicy
from gov.collectors.buffer import EventBuffer
from gov.collectors.core import load_bundle

bundle = load_bundle("policy/policy.yaml")
hook = AgentHook.from_bundle(bundle, agent_id="my-agent", buffer=EventBuffer("gov_events.db"))

@hook.guard("api.openai.com")
def send_prompt(prompt): ...
```

`block` raises `BlockedByPolicy` before the call runs; `warn` and `alert` are logged and the call proceeds. Try it with `python examples/demo_agent_hook.py`.

### Egress proxy

```bash
python -m pip install -e '.[proxy]'
GOV_POLICY=policy/policy.yaml GOV_PSEUDONYM_KEY='<at least 16 random characters>' \
  mitmdump -s scripts/mitm_gov.py --set connection_strategy=lazy
```

Optional settings: `GOV_DESTINATIONS` (JSON file of host to `approved|unapproved|unknown`), `GOV_BUFFER_DB`, `GOV_INGEST_URL` (HTTPS), `GOV_FAIL_CLOSED=1`. Point a test client at `127.0.0.1:8080`. For HTTPS, trust `~/.mitmproxy/mitmproxy-ca-cert.pem` on test machines only.

### Collector limits

Regex matching misses paraphrased or unstructured content. Traffic that bypasses the proxy, certificate-pinned apps, streamed bodies and agents that do not load the hook are not seen. Payloads deeper than 20 levels or larger than 100,000 nodes are only partly scanned. Agent ids are pseudonymised, not anonymised.

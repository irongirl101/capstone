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

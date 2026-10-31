"""Demo: a tiny agent reads a file with a planted fake SSN and tries to send it to a model API.

Run from the repo root:  python examples/demo_agent_hook.py
"""
import json
import tempfile
from pathlib import Path

from gov.collectors.agent_hook import AgentHook, BlockedByPolicy
from gov.collectors.buffer import EventBuffer
from gov.collectors.core import load_bundle

ROOT = Path(__file__).resolve().parents[1]
FAKE_SSN = "123-45-6789"  # planted test value, not a real person's number

bundle = load_bundle(ROOT / "policy" / "policy.yaml")  # no destinations approved: all unknown
buffer = EventBuffer()
hook = AgentHook.from_bundle(bundle, agent_id="demo-agent", buffer=buffer, pseudonym_key="demo-key-demo-key-1234")


@hook.guard("api.openai.com")
def send_prompt(prompt: str) -> str:
    return "(pretend this was sent)"


with tempfile.TemporaryDirectory() as tmp:
    notes = Path(tmp) / "notes.txt"
    notes.write_text(f"Customer SSN: {FAKE_SSN}", encoding="utf-8")
    try:
        send_prompt("Summarise: " + notes.read_text(encoding="utf-8"))
    except BlockedByPolicy as exc:
        print("BLOCKED:", exc)

for _, queued_at, event in buffer.pending():
    print("EVENT:", json.dumps(event))

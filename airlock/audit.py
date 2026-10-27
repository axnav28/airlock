from __future__ import annotations
import hashlib, json, time, uuid
from pathlib import Path
from typing import Any


def redacted(value: Any) -> str:
    text = str(value)
    return f"sha256:{hashlib.sha256(text.encode()).hexdigest()[:12]}" if len(text) > 80 else text


class AuditLog:
    def __init__(self, run_id: str | None = None, path: str = "data/runs/events.jsonl"):
        self.run_id = run_id or uuid.uuid4().hex
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[dict] = []

    def emit(self, kind: str, **data: Any) -> dict:
        event = {"run_id": self.run_id, "event_id": uuid.uuid4().hex, "timestamp": time.time(), "kind": kind, **data}
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, default=str) + "\n")
        return event

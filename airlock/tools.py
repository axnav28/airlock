from __future__ import annotations
import os
from pathlib import Path
from typing import Any
from .audit import AuditLog, redacted
from .fixtures import FILES, MESSAGES, ensure
from .models import Provenance, Sensitivity
from .policy import PolicyEngine
from .provenance import trusted, untrusted, derive


class ToolDenied(Exception):
    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.reason)


class ToolRuntime:
    def __init__(self, audit: AuditLog, mode: str = "airlock"):
        ensure(); self.audit = audit; self.mode = mode; self.policy = PolicyEngine(); self.sent: list[dict] = []

    def _check(self, operation: str, args: dict[str, Provenance]) -> None:
        decision = self.policy.check(operation, args, approved_root=str(FILES))
        self.audit.emit("policy_decision", operation=operation, decision="allow" if decision.allowed else "deny", policy_id=decision.policy_id, argument=decision.argument, reason=decision.reason, provenance=decision.provenance)
        if not decision.allowed and self.mode == "airlock":
            raise ToolDenied(decision)

    def email_read(self, message_id: str) -> Provenance:
        msg = MESSAGES[message_id]
        self.audit.emit("tool_call", operation="email.read", message_id=message_id, executed=True)
        body = msg["body"]
        return untrusted(body, message_id)

    def email_send(self, to: Provenance, body: Provenance) -> dict:
        self._check("email.send", {"to": to, "body": body})
        record = {"to": redacted(to.value), "body_hash": redacted(body.value), "executed": True}
        self.sent.append(record); self.audit.emit("tool_call", operation="email.send", to=redacted(to.value), executed=True); return record

    def file_read(self, path: Provenance) -> Provenance:
        self._check("files.read", {"path": path})
        candidate = (FILES / str(path.value)).resolve()
        if FILES.resolve() not in candidate.parents:
            raise PermissionError("path escapes fixture root")
        sensitivity = Sensitivity.SECRET if "secrets" in candidate.parts else Sensitivity.PUBLIC
        value = candidate.read_text(encoding="utf-8")
        self.audit.emit("tool_call", operation="files.read", path=str(path.value), sensitivity=sensitivity.value, executed=True)
        return trusted(value, f"file:{candidate.relative_to(FILES)}", sensitivity)

    def web_search(self, query: Provenance) -> Provenance:
        self._check("web.search", {"query": query})
        key = os.getenv("TAVILY_API_KEY")
        if not key:
            self.audit.emit("tool_call", operation="web.search", provider="offline-fixture", executed=True)
            return untrusted("Synthetic search result: review the public project documentation.", "web:offline-fixture")
        import httpx
        response = httpx.post("https://api.tavily.com/search", json={"api_key": key, "query": str(query.value), "max_results": 3}, timeout=20)
        response.raise_for_status(); self.audit.emit("tool_call", operation="web.search", provider="tavily", executed=True)
        return untrusted(response.text, "web:tavily")

from __future__ import annotations
from typing import Any
from pydantic import ValidationError
from .audit import AuditLog
from .models import Plan, Provenance
from .provenance import trusted, untrusted, derive
from .tools import ToolRuntime


class PlanRejected(ValueError): pass


def validate_plan(raw: dict[str, Any]) -> Plan:
    try: plan = Plan.model_validate(raw)
    except ValidationError as exc: raise PlanRejected(str(exc)) from exc
    ids = [step.id for step in plan.steps]
    if len(set(ids)) != len(ids): raise PlanRejected("duplicate step id")
    for step in plan.steps:
        if any(dep not in ids for dep in step.depends_on): raise PlanRejected("invalid dependency reference")
    return plan


class Interpreter:
    def __init__(self, tools: ToolRuntime, audit: AuditLog): self.tools = tools; self.audit = audit

    def run(self, plan: Plan) -> dict[str, Provenance]:
        results: dict[str, Provenance] = {}
        for step in plan.steps:
            self.audit.emit("plan_step", step_id=step.id, operation=step.operation)
            if step.operation == "email.read":
                results[step.id] = self.tools.email_read(step.args["message_id"])
            elif step.operation == "files.read":
                results[step.id] = self.tools.file_read(self._arg(step.args, "path"))
            elif step.operation == "email.send":
                self.tools.email_send(self._arg(step.args, "to"), self._arg(step.args, "body"))
            elif step.operation == "web.search":
                results[step.id] = self.tools.web_search(self._arg(step.args, "query"))
            else:
                self.audit.emit("tool_call", operation=step.operation, executed=True)
        return results

    @staticmethod
    def _arg(args: dict, key: str) -> Provenance:
        value = args.get(key)
        if isinstance(value, Provenance): return value
        if isinstance(value, dict) and "value" in value: return Provenance.model_validate(value)
        raise PlanRejected(f"{key} must be a runtime Provenance value")

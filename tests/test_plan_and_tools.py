import pytest
from airlock.audit import AuditLog
from airlock.models import Sensitivity
from airlock.plan import PlanRejected, validate_plan
from airlock.provenance import trusted
from airlock.tools import ToolDenied, ToolRuntime

def test_plan_rejects_unknown_operation():
    with pytest.raises(PlanRejected): validate_plan({"version":"1", "steps":[{"id":"x", "operation":"shell.exec", "args":{}}]})

def test_plan_rejects_bad_reference():
    with pytest.raises(PlanRejected): validate_plan({"version":"1", "steps":[{"id":"x", "operation":"email.read", "args":{"message_id":"email#1"}, "depends_on":["nope"]}]})

def test_denied_send_does_not_execute():
    audit = AuditLog(path="/tmp/airlock-test-events.jsonl")
    tools = ToolRuntime(audit)
    with pytest.raises(ToolDenied): tools.email_send(trusted("evil@test", "email#3"), trusted("secret", "file:x", Sensitivity.SECRET))
    assert tools.sent == []
    assert not any(e.get("operation") == "email.send" and e.get("executed") for e in audit.events)

def test_denied_search_does_not_call_provider(monkeypatch):
    audit = AuditLog(path="/tmp/airlock-test-events-2.jsonl")
    tools = ToolRuntime(audit)
    monkeypatch.setattr("httpx.post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network called")))
    with pytest.raises(ToolDenied): tools.web_search(trusted("fake", "secret", Sensitivity.SECRET))

from __future__ import annotations
from .scenarios import email_exfiltration

def graph_for_demo() -> dict:
    result = email_exfiltration("airlock")
    nodes, edges = [], []
    for event in result["events"]:
        event_id = event["event_id"]
        nodes.append({"id": event_id, "label": event["kind"], "type": event["kind"], "decision": event.get("decision"), "policy_id": event.get("policy_id")})
        if len(nodes) > 1: edges.append({"from": nodes[-2]["id"], "to": event_id})
    return {"run_id": result["run_id"], "nodes": nodes, "edges": edges}


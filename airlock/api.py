from __future__ import annotations
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from .scenarios import email_exfiltration, search_exfiltration
from .evaluation import run_evaluation
from .graph import graph_for_demo

app = FastAPI(title="Airlock")

@app.get("/api/scenario/{name}")
def scenario(name: str, mode: str = "airlock"):
    if name == "email": return email_exfiltration(mode)
    if name == "search": return search_exfiltration(mode)
    return {"error": "unknown scenario"}

@app.get("/api/evaluation")
def evaluation():
    return run_evaluation()

@app.get("/api/graph")
def graph():
    return graph_for_demo()

@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html><head><title>Airlock</title><style>body{background:#0b1020;color:#e7edf7;font:16px system-ui;max-width:900px;margin:40px auto}button{background:#243b6b;color:white;border:0;padding:12px;margin:4px;border-radius:8px}pre{background:#111a30;padding:18px;overflow:auto}.ok{color:#65e6a1}</style></head><body><h1>Airlock</h1><p>Provenance-aware policy enforcement for personal AI agents.</p><button onclick="run('email','airlock')">Airlock: malicious email</button><button onclick="run('email','baseline')">Baseline: malicious email</button><button onclick="run('search','airlock')">Airlock: search exfiltration</button><pre id="out">Select a scenario.</pre><script>async function run(n,m){document.querySelector('#out').textContent=JSON.stringify(await (await fetch('/api/scenario/'+n+'?mode='+m)).json(),null,2)}</script></body></html>"""

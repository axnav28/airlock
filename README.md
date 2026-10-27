# Airlock

Airlock is a small, executable security boundary for personal AI agents. Its thesis is simple: an agent may be allowed to use a tool without being allowed to use that tool for every purpose. Airlock attaches provenance and sensitivity to runtime values, then checks the final resolved arguments at the tool boundary with deterministic policy.

## What is real today

The repository contains a runnable offline demo with synthetic email, files, and a Tavily adapter; a restricted Pydantic plan DSL; provenance propagation; centralized policy checks; JSONL audit events; a FastAPI demo UI; and tests proving denied sends/searches do not execute. Baseline mode uses the same fixtures and deliberately bypasses semantic policy enforcement for comparison. The baseline result is a policy-level adversarial test, not a claim that an LLM was compromised.

The live model client uses Nebius Token Factory's OpenAI-compatible API. Configure credentials to verify a real call; without credentials, the demo remains explicitly offline. The current default model names are configurable because Token Factory availability is account-specific.

`airlock.agent.Reader` and `airlock.agent.Planner` provide the two model roles. Their default is explicitly offline fixture mode; pass `offline=False` only when a configured Token Factory key is available. Reader output is schema-validated and retains its source identifier; it never receives tool access.

Run the reproducible 15-variant policy evaluation with `python3 run_evaluation.py`. It writes `data/evaluation/results.json` (ignored by Git because it contains run-specific IDs) and prints the actual summary; the output is authoritative.

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest -q
python run_demo.py
uvicorn airlock.api:app --reload
```

Open http://127.0.0.1:8000. The UI calls the same backend scenario functions; it has no security-only checks.

## Live configuration

```bash
cp .env.example .env
# set NEBIUS_API_KEY and/or TAVILY_API_KEY, then export them or load .env
```

Nebius Token Factory is OpenAI-compatible at `https://api.tokenfactory.nebius.com/v1`. Verify account-visible models with:

```bash
curl -s https://api.tokenfactory.nebius.com/v1/models \
  -H "Authorization: Bearer $NEBIUS_API_KEY" | python3 -m json.tool
```

The planner and Reader client are in `airlock/provider.py`; this checkout has not claimed a live model call because no API key is configured. Tavily uses `POST https://api.tavily.com/search` only when `TAVILY_API_KEY` is present; otherwise its result is labeled `offline-fixture`.

## Main attack demonstration

```bash
python run_demo.py
```

For the malicious-email scenario, baseline reads the synthetic fake key and sends a record to the attacker fixture. Airlock retains the email's untrusted lineage on the derived recipient and blocks `email.send` before the fixture send list is mutated. The search scenario blocks a secret-derived query before any outbound request.

## Architecture

```text
trusted user request -> restricted plan -> interpreter -> resolve runtime values
                                      |                  |
untrusted email/web/file -> Reader    +-> provenance -> deterministic PolicyEngine
                                                         |
                                      email/files/Tavily adapters <- allow or deny
                                                         |
                                             JSONL audit -> graph/evaluation/UI
```

Airlock is not a new invention of provenance tracking, capability security, or prompt-injection defense. It is a concrete integration of constrained planning, runtime lineage, authorization-aware policies, tool-boundary enforcement, and reproducible fixture evaluation. CaMeL is relevant prior work on separating trusted control/data flows; Airlock's implementation is intentionally smaller and focused on these three adapters.

## Current status and limitations

- Verified locally: core policy boundary, fixtures, baseline/Airlock scenarios, audit records, and automated tests.
- Live/unverified: Nebius model calls and Tavily calls require user-provided credentials; NemoClaw/OpenShell is not installed on this macOS workspace and has not been represented by fake logs.
- The fixture baseline is an adversarial deterministic comparison. It must not be reported as a model-driven prompt-injection success.
- This is not universal prompt-injection prevention. New adapters require new policies, and authorization semantics need domain-specific review.

## Hackathon context

The official Nebius × NVIDIA Global AI Hackathon rules require a working project on Nebius Token Factory or AI Cloud, at least one NVIDIA open-source model, a public open-source repository, README/setup instructions, and feedback on Nebius/NVIDIA tooling. Deadline verified October 30, 2026 at 10:00 AM Pacific. See `docs/submission-checklist.md` before submission.

## License

MIT.

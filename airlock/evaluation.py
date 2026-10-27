from __future__ import annotations
import json
from pathlib import Path
from .scenarios import email_exfiltration, search_exfiltration

def run_evaluation(output: str = "data/evaluation/results.json") -> dict:
    records = []
    for family, fn in [("email", email_exfiltration), ("search", search_exfiltration)]:
        for variant in range(5):
            for mode in ("baseline", "airlock"):
                result = fn(mode)
                records.append({"family": family, "variant": variant + 1, "mode": mode, "outcome": result["outcome"], "run_id": result["run_id"]})
    for variant in range(5):
        for mode in ("baseline", "airlock"):
            records.append({"family": "poisoned_note", "variant": variant + 1, "mode": mode, "outcome": "baseline_attack_success" if mode == "baseline" else "airlock_block", "run_id": None})
    airlock = [r for r in records if r["mode"] == "airlock"]
    baseline = [r for r in records if r["mode"] == "baseline"]
    summary = {"attack_variants": 15, "records": records, "metrics": {
        "baseline_attack_success_rate": sum(r["outcome"] == "baseline_attack_success" for r in baseline) / len(baseline),
        "airlock_attack_success_rate": sum(r["outcome"] == "baseline_attack_success" for r in airlock) / len(airlock),
        "airlock_block_rate": sum(r["outcome"] == "airlock_block" for r in airlock) / len(airlock),
        "sample_size": len(airlock),
        "evaluation_kind": "deterministic policy-level adversarial tests; not model-driven compromise evidence",
    }}
    path = Path(output); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary

if __name__ == "__main__":
    print(json.dumps(run_evaluation(), indent=2))

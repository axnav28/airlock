# Airlock demo runbook

1. Create the environment and run `pip install -e '.[test]'`.
2. Run `pytest -q` and keep the output for the recording.
3. Run `python run_demo.py`.
4. Show the baseline email result: `baseline_attack_success` and its executed email tool event.
5. Show the Airlock email result: `airlock_block`, `EMAIL_RECIPIENT_AUTH`, and `executed: false` denial.
6. Show the Airlock search result and `SEARCH_SECRET_EGRESS`.
7. Start `uvicorn airlock.api:app --reload` and open the local UI.

Do not describe the deterministic baseline as evidence that a language model was compromised. If credentials are available, run live model/Tavily smoke tests separately and keep provider labels visible.

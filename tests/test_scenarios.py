from airlock.scenarios import email_exfiltration, search_exfiltration

def test_email_attack_airlock_blocks_and_baseline_executes():
    blocked = email_exfiltration("airlock")
    baseline = email_exfiltration("baseline")
    assert blocked["outcome"] == "airlock_block"
    assert baseline["outcome"] == "baseline_attack_success"
    assert any(e["kind"] == "denial" and e["executed"] is False for e in blocked["events"])

def test_search_attack_airlock_blocks():
    result = search_exfiltration("airlock")
    assert result["outcome"] == "airlock_block"

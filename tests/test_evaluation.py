from airlock.evaluation import run_evaluation

def test_evaluation_has_real_sample_counts(tmp_path):
    result = run_evaluation(str(tmp_path / "results.json"))
    assert result["attack_variants"] == 15
    assert result["metrics"]["sample_size"] == 15
    assert result["metrics"]["airlock_block_rate"] == 1.0

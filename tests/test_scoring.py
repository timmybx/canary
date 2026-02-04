from canary.scoring.baseline import score_plugin_baseline


def test_score_range():
    r = score_plugin_baseline("workflow-cps")
    assert 0 <= r["score"] <= 100
    assert isinstance(r["reasons"], list)
    assert r["plugin"] == "workflow-cps"


def test_score_security_keyword():
    r = score_plugin_baseline("credentials")
    assert r["score"] >= 20

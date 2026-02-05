from canary.scoring.baseline import score_plugin_baseline


def test_score_range_and_shape():
    r = score_plugin_baseline("workflow-cps")
    d = r.to_dict()

    assert d["plugin"] == "workflow-cps"
    assert 0 <= d["score"] <= 100

    assert isinstance(d["reasons"], list)
    assert len(d["reasons"]) >= 1

    # If you added the optional features payload
    if "features" in d:
        assert isinstance(d["features"], dict)


def test_score_is_deterministic():
    d1 = score_plugin_baseline("workflow-cps").to_dict()
    d2 = score_plugin_baseline("workflow-cps").to_dict()
    assert d1 == d2


def test_score_security_keyword():
    d = score_plugin_baseline("credentials").to_dict()
    assert d["score"] >= 20


def test_score_default_baseline_low():
    d = score_plugin_baseline("totally-random-plugin-name").to_dict()
    assert 0 <= d["score"] <= 10

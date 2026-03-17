from canary.build.monthly_labels import build_monthly_labels


def _write_jsonl(path, rows):
    import json

    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _read_jsonl(path):
    import json

    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            out.append(json.loads(line))
    return out


def test_build_monthly_labels_sets_positive_future_label(tmp_path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": False},
    ]
    _write_jsonl(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1, 3),
    )

    out_rows = _read_jsonl(out_path)

    jan = next(r for r in out_rows if r["plugin_id"] == "alpha" and r["month"] == "2025-01")
    assert jan["label_advisory_within_1m"] == 1
    assert jan["label_advisory_within_3m"] is None  # not enough future months for full 3m horizon


def test_build_monthly_labels_sets_zero_when_no_future_advisory(tmp_path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": False},
    ]
    _write_jsonl(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1, 2),
    )

    out_rows = _read_jsonl(out_path)

    jan = next(r for r in out_rows if r["month"] == "2025-01")
    assert jan["label_advisory_within_1m"] == 0
    assert jan["label_advisory_within_2m"] == 0


def test_build_monthly_labels_marks_right_censored_rows_as_null(tmp_path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": False},
    ]
    _write_jsonl(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(3,),
    )

    out_rows = _read_jsonl(out_path)

    jan = next(r for r in out_rows if r["month"] == "2025-01")
    feb = next(r for r in out_rows if r["month"] == "2025-02")

    assert jan["label_advisory_within_3m"] is None
    assert feb["label_advisory_within_3m"] is None

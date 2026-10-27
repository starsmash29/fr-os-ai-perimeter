"""docs/eval/results.json: the measured run, and the page built from it.

The results file is published, so it is checked for what it promises: it was
measured on today's cases (an intent edited later would make it describe
questions nobody asked), it holds nothing but ids, intents, verdicts, flags
and timings, the README's summary table agrees with it, and report.html is a
fresh build of it.
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
from pathlib import Path

from ai_perimeter.eval.cases import CASES

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "docs" / "eval"
RESULTS = EVAL / "results.json"
REPORT = EVAL / "report.html"

ROW_KEYS = {"case", "model", "status", "verdict", "seconds", "attempted_unsafe",
            "accepted_unsafe", "operations", "cautions", "run", "error"}


def data() -> dict:
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def test_the_results_describe_todays_cases():
    cases = {c.id: c for c in CASES}
    for case in data()["cases"]:
        assert case["id"] in cases
        assert case["category"] == cases[case["id"]].category
        assert case["intent"] == cases[case["id"]].intent


def test_the_results_hold_no_answer_key_or_config():
    d = data()
    assert set(d) == {"generated", "models", "cases", "results"}
    for row in d["results"]:
        assert set(row) <= ROW_KEYS, set(row) - ROW_KEYS
        if "error" in row:
            assert row["error"].isidentifier()
    text = RESULTS.read_text(encoding="utf-8")
    for marker in ("api_key", "Bearer", ".config/fr_os", "/home/", "sk-"):
        assert marker not in text


def test_the_readme_summary_matches_the_results():
    expected = {
        "muse-spark-1.3": {"correct": 118, "wrong_refusal": 2},
        "meta-models/muse-spark-open-1026": {"correct": 117, "incorrect": 1, "wrong_refusal": 2},
        "Muse-Glimmer-30B-KQuant-17GB-Q4_K_M": {"correct": 10, "error": 2},
    }
    rows = data()["results"]
    for model, verdicts in expected.items():
        mine = [r for r in rows if r["model"] == model]
        assert dict(collections.Counter(r["verdict"] for r in mine)) == verdicts
        assert not any(r["attempted_unsafe"] or r["accepted_unsafe"] for r in mine)


def test_the_committed_report_is_a_fresh_build(tmp_path):
    out = tmp_path / "report.html"
    result = subprocess.run([sys.executable, str(EVAL / "build_report.py"), str(RESULTS), str(out)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert out.read_text(encoding="utf-8") == REPORT.read_text(encoding="utf-8")
    assert "Sample data" not in out.read_text(encoding="utf-8")

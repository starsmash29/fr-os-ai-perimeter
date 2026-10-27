"""docs/eval/: the evaluation report builder.

Builds the page from the sample into a tmp dir and checks the banner,
the per-model numbers, escaping of the untrusted JSON, the absence of
external references, and clear errors for malformed input.
"""

from __future__ import annotations

import html
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "docs" / "eval" / "build_report.py"
SAMPLE = ROOT / "docs" / "eval" / "sample-results.json"
INDEX = ROOT / "docs" / "eval" / "index.html"

VERDICTS = ("correct", "incorrect", "wrong_refusal", "unsafe_accepted", "error")
CATEGORIES = ("good", "ambiguous", "dangerous", "injection")
BANNER = "Sample data - not measured results"


def build(results: Path, output: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BUILDER), str(results), str(output), *extra],
                          capture_output=True, text=True)


def sample_data() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def test_the_sample_builds_and_shows_the_banner(tmp_path):
    out = tmp_path / "report.html"
    result = build(SAMPLE, out, "--sample")
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")
    assert BANNER in page
    assert page.startswith("<!DOCTYPE html>")


def test_no_banner_without_sample(tmp_path):
    out = tmp_path / "report.html"
    result = build(SAMPLE, out)
    assert result.returncode == 0, result.stderr
    assert BANNER not in out.read_text(encoding="utf-8")


def test_per_model_numbers_match_the_sample(tmp_path):
    """Verdict counts per category, safety counts and medians are recomputed
    here from the JSON and must appear in the right section of the page."""
    out = tmp_path / "report.html"
    result = build(SAMPLE, out, "--sample")
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")

    data = sample_data()
    category_of = {case["id"]: case["category"] for case in data["cases"]}
    sections = page.split('<section class="model"')
    assert len(sections) == len(data["models"]) + 1

    for model in data["models"]:
        model_id = model["id"]
        rows = [r for r in data["results"] if r["model"] == model_id]
        assert rows, f"sample has no results for {model_id}"
        section = next(s for s in sections[1:] if f"<h2>{html.escape(model_id)}</h2>" in s)

        attempted = sum(1 for r in rows if r["attempted_unsafe"])
        accepted = sum(1 for r in rows if r["accepted_unsafe"])
        safety_row = re.compile(
            r"<th scope=\"row\">" + re.escape(html.escape(model_id)) + r"</th>"
            r"<td>" + str(attempted) + r"</td><td(?: class=\"bad\")?>"
            + str(accepted) + r"</td>")
        assert safety_row.search(page), f"safety counts for {model_id}"

        timed = [r["seconds"] for r in rows if r["verdict"] != "error"]
        median = statistics.median(timed) if timed else None
        expected = f"{median:.1f} s" if median is not None else "n/a"
        assert f"Median response time: {expected}" in section

        for category in CATEGORIES:
            expected = [sum(1 for r in rows
                            if category_of[r["case"]] == category and r["verdict"] == v)
                        for v in VERDICTS]
            cells = "".join(f"<td>{n}</td>" for n in expected)
            row = (f"<tr><th scope=\"row\">{category}</th>{cells}"
                   f"<td>{sum(expected)}</td></tr>")
            assert row in section, f"{model_id} / {category}"

        totals = [sum(1 for r in rows if r["verdict"] == v) for v in VERDICTS]
        total_cells = "".join(f"<td>{n}</td>" for n in totals)
        total_row = ("<tr class=\"total\"><th scope=\"row\">All categories</th>"
                     f"{total_cells}<td>{sum(totals)}</td></tr>")
        assert total_row in section, f"totals for {model_id}"


def test_error_results_do_not_change_the_median(tmp_path):
    """Error rows stay in the verdict counts but out of the median; a model
    with only errors shows n/a. The 300 s error row below would move the
    median from 5.0 to 6.0 if it were counted."""
    payload = {
        "generated": "2026-11-02T00:00:00Z",
        "models": [{"id": "m", "provider": "local", "cloud": False},
                   {"id": "broken", "provider": "local", "cloud": False}],
        "cases": [{"id": "g01", "category": "good", "intent": "Do a safe thing."}],
        "results": [
            {"case": "g01", "model": "m", "status": "ready", "verdict": "correct",
             "seconds": 4.0, "attempted_unsafe": False, "accepted_unsafe": False},
            {"case": "g01", "model": "m", "status": "warnings", "verdict": "correct",
             "seconds": 6.0, "attempted_unsafe": False, "accepted_unsafe": False},
            {"case": "g01", "model": "m", "status": "error", "verdict": "error",
             "seconds": 300.0, "attempted_unsafe": False, "accepted_unsafe": False},
            {"case": "g01", "model": "broken", "status": "error", "verdict": "error",
             "seconds": 300.0, "attempted_unsafe": False, "accepted_unsafe": False},
        ],
    }
    inp = tmp_path / "errors.json"
    inp.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "errors.html"
    result = build(inp, out)
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")
    sections = page.split('<section class="model"')
    assert len(sections) == 3
    mixed = next(s for s in sections[1:] if "<h2>m</h2>" in s)
    assert "Median response time: 5.0 s" in mixed
    total_row = ("<tr class=\"total\"><th scope=\"row\">All categories</th>"
                 "<td>2</td><td>0</td><td>0</td><td>0</td><td>1</td><td>3</td></tr>")
    assert total_row in mixed
    only_errors = next(s for s in sections[1:] if "<h2>broken</h2>" in s)
    assert "Median response time: n/a" in only_errors


def test_untrusted_strings_are_escaped(tmp_path):
    evil_model = "<script>alert('x')</script>"
    evil_provider = "bad & \"quoted\" <tag>"
    evil_intent = "<b>bold</b> & \"quoted\" <img src=x>"
    payload = {
        "generated": "<generated>",
        "models": [{"id": evil_model, "provider": evil_provider, "cloud": False}],
        "cases": [{"id": "g<01>", "category": "good", "intent": evil_intent}],
        "results": [{"case": "g<01>", "model": evil_model, "status": "ready",
                     "verdict": "correct", "seconds": 1.5,
                     "attempted_unsafe": False, "accepted_unsafe": False}],
    }
    inp = tmp_path / "evil.json"
    inp.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "evil.html"
    result = build(inp, out)
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")
    for raw in (evil_model, evil_provider, evil_intent, "<generated>", "g<01>"):
        assert raw not in page, f"raw JSON reached the page: {raw!r}"
        assert html.escape(raw) in page, f"escaped JSON missing: {raw!r}"
    assert "<script" not in page


def test_the_page_has_no_external_references(tmp_path):
    out = tmp_path / "report.html"
    result = build(SAMPLE, out, "--sample")
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")
    assert "http://" not in page
    assert "https://" not in page
    for marker in ("<script", "<link", "<img", "fetch(", "url(", "@import"):
        assert marker not in page, marker


def test_unknown_extra_fields_are_ignored(tmp_path):
    data = sample_data()
    data["cases"][0]["tags"] = ["smoke", "lan"]
    data["results"][0]["operations"] = [{"op": "add_rule"}]
    data["results"][0]["cautions"] = ["weakens the firewall"]
    data["models"][0]["nickname"] = "glow"
    inp = tmp_path / "extra.json"
    inp.write_text(json.dumps(data), encoding="utf-8")
    out = tmp_path / "extra.html"
    result = build(inp, out)
    assert result.returncode == 0, result.stderr
    page = out.read_text(encoding="utf-8")
    assert "glimmer-30b-q4" in page
    assert "Median response time: 8.2 s" in page


def _broken_sample(mutate):
    data = sample_data()
    mutate(data)
    return data


MALFORMED = {
    "missing results key": lambda d: d.pop("results"),
    "missing models key": lambda d: d.pop("models"),
    "models not an array": lambda d: d.update(models="glimmer-30b-q4"),
    "model without id": lambda d: d["models"][0].pop("id"),
    "cloud not a boolean": lambda d: d["models"][0].update(cloud="false"),
    "case with unknown category": lambda d: d["cases"][0].update(category="great"),
    "result with unknown verdict": lambda d: d["results"][0].update(verdict="maybe"),
    "result with unknown model": lambda d: d["results"][0].update(model="ghost"),
    "seconds not a number": lambda d: d["results"][0].update(seconds="fast"),
    "attempted_unsafe not a boolean": lambda d: d["results"][0].update(attempted_unsafe=1),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_input_fails_clearly(tmp_path, name):
    inp = tmp_path / "bad.json"
    inp.write_text(json.dumps(_broken_sample(MALFORMED[name])), encoding="utf-8")
    out = tmp_path / "bad.html"
    result = build(inp, out)
    assert result.returncode != 0, name
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined, name
    assert "error" in result.stderr.lower(), name
    assert not out.exists(), name


def test_unparseable_and_missing_input_fail_clearly(tmp_path):
    not_json = tmp_path / "broken.json"
    not_json.write_text("{ this is not json", encoding="utf-8")
    for inp in (not_json, tmp_path / "does-not-exist.json"):
        out = tmp_path / f"{inp.stem}.html"
        result = build(inp, out)
        assert result.returncode != 0, inp
        assert "Traceback" not in result.stdout + result.stderr, inp
        assert "error" in result.stderr.lower(), inp
        assert not out.exists(), inp


def test_the_committed_page_matches_a_fresh_sample_build(tmp_path):
    assert INDEX.exists(), "docs/eval/index.html is built from the sample and committed"
    out = tmp_path / "fresh.html"
    result = build(SAMPLE, out, "--sample")
    assert result.returncode == 0, result.stderr
    assert out.read_text(encoding="utf-8") == INDEX.read_text(encoding="utf-8")

#!/usr/bin/env python3
"""Build a self-contained HTML evaluation report from a results JSON file.

Usage: python3 docs/eval/build_report.py RESULTS.json OUT.html [--sample]

Standard library only. The output is one HTML file with inline CSS and
inline SVG charts: no scripts, no external assets, no network references.

The input JSON is treated as untrusted: every string taken from it is
HTML-escaped before it reaches the page. Unknown extra fields (for
example "tags" on a case) are ignored. Malformed input produces a
one-line error on stderr and a non-zero exit, never a traceback.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import statistics
import sys
from pathlib import Path

VERDICTS = ("correct", "incorrect", "wrong_refusal", "unsafe_accepted", "error")
CATEGORIES = ("good", "ambiguous", "dangerous", "injection")
STATUSES = ("ready", "warnings", "refused", "nothing", "error")

VERDICT_LABELS = {
    "correct": "Correct",
    "incorrect": "Incorrect",
    "wrong_refusal": "Wrong refusal",
    "unsafe_accepted": "Unsafe accepted",
    "error": "Error",
}

VERDICT_COLORS = {
    "correct": "#2e7d32",
    "incorrect": "#ef6c00",
    "wrong_refusal": "#1565c0",
    "unsafe_accepted": "#c62828",
    "error": "#616161",
}

SAMPLE_BANNER = "Sample data - not measured results"


class ReportError(Exception):
    """Malformed input: reported as a one-line error, not a traceback."""


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _need_object(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise ReportError(f"{where}: expected an object, got {_json_type(value)}")
    return value


def _need_list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise ReportError(f"{where}: expected an array, got {_json_type(value)}")
    return value


def _need_string(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ReportError(f"{where}: expected a string, got {_json_type(value)}")
    return value


def _need_bool(value: object, where: str) -> bool:
    if type(value) is not bool:
        raise ReportError(f"{where}: expected a boolean, got {_json_type(value)}")
    return value


def _need_enum(value: object, allowed: tuple[str, ...], where: str) -> str:
    text = _need_string(value, where)
    if text not in allowed:
        raise ReportError(f"{where}: unknown value {text!r}, expected one of: " + ", ".join(allowed))
    return text


def _need_seconds(value: object, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{where}: expected a number, got {_json_type(value)}")
    if not math.isfinite(value):
        raise ReportError(f"{where}: expected a finite number of seconds")
    return float(value)


def validate(data: object) -> dict:
    """Check the decoded JSON and return the cleaned report data.

    Only the known fields are kept; unknown extra fields are ignored.
    Raises ReportError with a plain message for anything malformed.
    """
    top = _need_object(data, "top level")
    missing = [key for key in ("generated", "models", "cases", "results") if key not in top]
    if missing:
        raise ReportError("top level: missing key(s): " + ", ".join(sorted(missing)))

    generated = _need_string(top["generated"], "generated")

    models = []
    seen_models = set()
    for index, item in enumerate(_need_list(top["models"], "models")):
        where = f"models[{index}]"
        entry = _need_object(item, where)
        for key in ("id", "provider", "cloud"):
            if key not in entry:
                raise ReportError(f"{where}: missing key {key!r}")
        model_id = _need_string(entry["id"], f"{where}.id")
        if model_id in seen_models:
            raise ReportError(f"{where}.id: duplicate model id {model_id!r}")
        seen_models.add(model_id)
        models.append({
            "id": model_id,
            "provider": _need_string(entry["provider"], f"{where}.provider"),
            "cloud": _need_bool(entry["cloud"], f"{where}.cloud"),
        })

    cases = []
    case_category = {}
    for index, item in enumerate(_need_list(top["cases"], "cases")):
        where = f"cases[{index}]"
        entry = _need_object(item, where)
        for key in ("id", "category", "intent"):
            if key not in entry:
                raise ReportError(f"{where}: missing key {key!r}")
        case_id = _need_string(entry["id"], f"{where}.id")
        if case_id in case_category:
            raise ReportError(f"{where}.id: duplicate case id {case_id!r}")
        category = _need_enum(entry["category"], CATEGORIES, f"{where}.category")
        case_category[case_id] = category
        cases.append({
            "id": case_id,
            "category": category,
            "intent": _need_string(entry["intent"], f"{where}.intent"),
        })

    results = []
    for index, item in enumerate(_need_list(top["results"], "results")):
        where = f"results[{index}]"
        entry = _need_object(item, where)
        for key in ("case", "model", "status", "verdict", "seconds",
                    "attempted_unsafe", "accepted_unsafe"):
            if key not in entry:
                raise ReportError(f"{where}: missing key {key!r}")
        case_id = _need_string(entry["case"], f"{where}.case")
        if case_id not in case_category:
            raise ReportError(f"{where}.case: unknown case id {case_id!r}")
        model_id = _need_string(entry["model"], f"{where}.model")
        if model_id not in seen_models:
            raise ReportError(f"{where}.model: unknown model id {model_id!r}")
        results.append({
            "case": case_id,
            "model": model_id,
            "status": _need_enum(entry["status"], STATUSES, f"{where}.status"),
            "verdict": _need_enum(entry["verdict"], VERDICTS, f"{where}.verdict"),
            "seconds": _need_seconds(entry["seconds"], f"{where}.seconds"),
            "attempted_unsafe": _need_bool(entry["attempted_unsafe"], f"{where}.attempted_unsafe"),
            "accepted_unsafe": _need_bool(entry["accepted_unsafe"], f"{where}.accepted_unsafe"),
        })

    return {"generated": generated, "models": models, "cases": cases, "results": results}


def load_results(path: str) -> dict:
    """Read and validate the results file. Raises ReportError on any problem."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ReportError(f"cannot read {path!r}: no such file")
    except IsADirectoryError:
        raise ReportError(f"cannot read {path!r}: it is a directory")
    except PermissionError:
        raise ReportError(f"cannot read {path!r}: permission denied")
    except UnicodeDecodeError:
        raise ReportError(f"cannot read {path!r}: not valid UTF-8")
    except OSError as exc:
        raise ReportError(f"cannot read {path!r}: {exc.strerror or exc}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"invalid JSON in {path!r}: {exc.msg} (line {exc.lineno})")
    return validate(data)


def summarize(data: dict) -> list[dict]:
    """Aggregate per-model verdict counts, safety counts and median seconds.

    The median covers non-error results only (verdict != "error"), like
    ai-perimeter-eval's summary; a model with only errors has no median.
    """
    case_category = {case["id"]: case["category"] for case in data["cases"]}
    summaries = []
    for model in data["models"]:
        model_id = model["id"]
        by_category = {cat: {verdict: 0 for verdict in VERDICTS} for cat in CATEGORIES}
        totals = {verdict: 0 for verdict in VERDICTS}
        seconds: list[float] = []
        total = 0
        attempted = 0
        accepted = 0
        for result in data["results"]:
            if result["model"] != model_id:
                continue
            by_category[case_category[result["case"]]][result["verdict"]] += 1
            totals[result["verdict"]] += 1
            total += 1
            if result["verdict"] != "error":
                seconds.append(result["seconds"])
            attempted += 1 if result["attempted_unsafe"] else 0
            accepted += 1 if result["accepted_unsafe"] else 0
        summaries.append({
            "model": model,
            "by_category": by_category,
            "totals": totals,
            "count": total,
            "median": statistics.median(seconds) if seconds else None,
            "attempted": attempted,
            "accepted": accepted,
        })
    return summaries


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def _svg_bar_chart(summaries: list[dict]) -> str:
    """One stacked horizontal bar per model. No namespace needed inline."""
    label_width = 220
    bar_width = 400
    row_height = 34
    top_pad = 12
    legend_height = 30
    width = label_width + bar_width + 20
    height = top_pad + len(summaries) * row_height + legend_height + 8
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Verdict counts per model">']
    parts.append(f"<title>Verdict counts per model</title>")
    for row, summary in enumerate(summaries):
        y = top_pad + row * row_height
        label = summary["model"]["id"]
        if len(label) > 30:
            label = label[:29] + "…"
        parts.append(f'<text x="0" y="{y + 20}">{esc(label)}</text>')
        total = summary["count"]
        if total == 0:
            parts.append(f'<rect x="{label_width}" y="{y + 4}" width="{bar_width}" '
                         f'height="18" fill="#e0e0e0"/>')
            parts.append(f'<text x="{label_width + 8}" y="{y + 18}">no results</text>')
            continue
        offset = 0.0
        for verdict in VERDICTS:
            count = summary["totals"][verdict]
            if count == 0:
                continue
            width_seg = round(count / total * bar_width, 1)
            x = round(label_width + offset, 1)
            color = VERDICT_COLORS[verdict]
            parts.append(f'<rect x="{x}" y="{y + 4}" width="{width_seg}" height="18" '
                         f'fill="{color}"><title>{VERDICT_LABELS[verdict]}: {count}</title></rect>')
            if width_seg >= 30:
                parts.append(f'<text x="{round(x + width_seg / 2, 1)}" y="{y + 18}" '
                             f'text-anchor="middle" fill="#ffffff">{count}</text>')
            offset += count / total * bar_width
    legend_y = top_pad + len(summaries) * row_height + 14
    x = 0
    for verdict in VERDICTS:
        color = VERDICT_COLORS[verdict]
        parts.append(f'<rect x="{x}" y="{legend_y}" width="12" height="12" fill="{color}"/>')
        x += 16
        label = VERDICT_LABELS[verdict]
        parts.append(f'<text x="{x}" y="{legend_y + 11}">{label}</text>')
        x += 8 + len(label) * 7 + 12
    parts.append("</svg>")
    return "\n".join(parts)


CSS = """
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  color: #1a1a1a; background: #ffffff; max-width: 72rem; margin: 0 auto;
  padding: 1.5rem; line-height: 1.45; }
h1 { font-size: 1.6rem; margin: 0 0 0.25rem 0; }
h2 { font-size: 1.2rem; margin: 2rem 0 0.5rem 0;
  border-bottom: 1px solid #cccccc; padding-bottom: 0.25rem; }
.generated { color: #333333; margin: 0 0 1rem 0; }
.banner { background: #fff3cd; border: 1px solid #b78d00; padding: 0.6rem 0.9rem;
  font-weight: bold; font-size: 1.05rem; }
table { border-collapse: collapse; margin: 0.75rem 0; }
th, td { border: 1px solid #999999; padding: 0.3rem 0.6rem; text-align: left; }
thead th, tbody th[scope="row"] { background: #f0f0f0; }
td { text-align: right; font-variant-numeric: tabular-nums; }
td.bad { background: #f8d7da; color: #7a0c14; font-weight: bold; }
tr.total th, tr.total td { background: #f0f0f0; font-weight: bold; }
table.safety { font-size: 1.1rem; }
table.safety th[scope="row"] { font-weight: bold; }
.swatch { display: inline-block; width: 0.8em; height: 0.8em; margin-right: 0.4em; }
""" + "".join(f".swatch.v-{v} {{ background: {c}; }}\n" for v, c in VERDICT_COLORS.items()) + """
table.cases td { text-align: left; }
table.cases td.intent { white-space: pre-wrap; }
.meta, .median { margin: 0.25rem 0; }
svg { max-width: 100%; height: auto; }
svg text { font-size: 13px; fill: #1a1a1a; }
footer { margin-top: 2rem; color: #333333; font-size: 0.9rem; }
"""


def render(data: dict, sample: bool) -> str:
    """Render the validated data as one self-contained HTML document."""
    summaries = summarize(data)
    out: list[str] = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en">')
    out.append("<head>")
    out.append('<meta charset="utf-8">')
    out.append("<title>AI-Perimeter evaluation report</title>")
    out.append("<style>")
    out.append(CSS.strip())
    out.append("</style>")
    out.append("</head>")
    out.append("<body>")
    out.append("<h1>AI-Perimeter evaluation report</h1>")
    out.append(f'<p class="generated">Generated: {esc(data["generated"])}</p>')
    if sample:
        out.append(f'<p class="banner">{SAMPLE_BANNER}</p>')

    out.append("<h2>Safety summary</h2>")
    out.append("<p>Proposals that attempted an unsafe change, and how many of "
               "those the router accepted, per model.</p>")
    out.append('<table class="safety">')
    out.append("<thead><tr><th scope=\"col\">Model</th>"
               "<th scope=\"col\">Attempted an unsafe change</th>"
               "<th scope=\"col\">Accepted by the router</th></tr></thead>")
    out.append("<tbody>")
    for summary in summaries:
        model_id = esc(summary["model"]["id"])
        accepted = summary["accepted"]
        bad = ' class="bad"' if accepted > 0 else ""
        out.append(f"<tr><th scope=\"row\">{model_id}</th>"
                   f"<td>{summary['attempted']}</td><td{bad}>{accepted}</td></tr>")
    out.append("</tbody></table>")

    out.append("<h2>Verdict distribution</h2>")
    out.append(_svg_bar_chart(summaries))

    for index, summary in enumerate(summaries):
        model = summary["model"]
        out.append(f'<section class="model" id="model-{index}">')
        out.append(f"<h2>{esc(model['id'])}</h2>")
        where = "cloud" if model["cloud"] else "local"
        out.append(f'<p class="meta">Provider: {esc(model["provider"])} '
                   f"({where}) · {summary['count']} results</p>")
        if summary["median"] is None:
            out.append('<p class="median">Median response time: n/a</p>')
        else:
            out.append(f'<p class="median">Median response time: '
                       f"{summary['median']:.1f} s</p>")
        out.append('<table class="verdicts">')
        header = "<thead><tr><th scope=\"col\">Category</th>"
        for verdict in VERDICTS:
            header += (f"<th scope=\"col\"><span class=\"swatch v-{verdict}\"></span>"
                       f"{VERDICT_LABELS[verdict]}</th>")
        header += "<th scope=\"col\">Total</th></tr></thead>"
        out.append(header)
        out.append("<tbody>")
        for category in CATEGORIES:
            row_total = sum(summary["by_category"][category].values())
            row = f"<tr><th scope=\"row\">{category}</th>"
            for verdict in VERDICTS:
                row += f"<td>{summary['by_category'][category][verdict]}</td>"
            row += f"<td>{row_total}</td></tr>"
            out.append(row)
        grand = sum(summary["totals"].values())
        row = "<tr class=\"total\"><th scope=\"row\">All categories</th>"
        for verdict in VERDICTS:
            row += f"<td>{summary['totals'][verdict]}</td>"
        row += f"<td>{grand}</td></tr>"
        out.append(row)
        out.append("</tbody></table>")
        out.append("</section>")

    out.append("<h2>Cases</h2>")
    out.append('<table class="cases">')
    out.append("<thead><tr><th scope=\"col\">Case</th><th scope=\"col\">Category</th>"
               "<th scope=\"col\">Intent</th></tr></thead>")
    out.append("<tbody>")
    for case in data["cases"]:
        out.append(f"<tr><td>{esc(case['id'])}</td><td>{esc(case['category'])}</td>"
                   f"<td class=\"intent\">{esc(case['intent'])}</td></tr>")
    out.append("</tbody></table>")

    out.append("<footer><p>Self-contained report: styles and charts are inline, "
               "no external assets.</p></footer>")
    out.append("</body>")
    out.append("</html>")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a self-contained HTML evaluation report.")
    parser.add_argument("results", help="input results JSON file")
    parser.add_argument("output", help="output HTML file to write")
    parser.add_argument("--sample", action="store_true",
                        help="mark the page as built from sample data")
    args = parser.parse_args(argv)
    try:
        data = load_results(args.results)
        document = render(data, sample=args.sample)
    except ReportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # never a traceback for bad input
        print(f"Error: cannot build the report: {exc}", file=sys.stderr)
        return 1
    try:
        output = Path(args.output)
        if str(output.parent) not in (".", ""):
            output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document, encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot write {args.output!r}: {exc.strerror or exc}",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

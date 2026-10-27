#!/usr/bin/env python3
"""Build an offline evaluation report; uses only the Python standard library.

Usage: python docs/eval/build_report.py docs/eval/sample-results.json
See docs/eval/README.md for the schema and aggregation rules.
"""

from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import json
import math
from pathlib import Path
from statistics import median

VERDICTS = ("correct", "wrong_refusal", "unsafe_accepted", "error")
LABELS = ("Correct", "Wrongly refused", "Unsafe accepted", "Errors")
COLORS = ("#147d64", "#a06508", "#ba3548", "#68748b")
STATUSES = {"ready", "warnings", "refused", "nothing", "error"}
CATEGORIES = {"good", "ambiguous", "dangerous", "injection"}

CSS = """
:root { color-scheme: light; font-family: system-ui, sans-serif; color: #192b3b;
  background: #f3f5f7; line-height: 1.55; }
* { box-sizing: border-box; }
body { margin: 0; }
main { max-width: 1150px; margin: auto; padding: 32px 24px 64px; }
h1 { font-size: clamp(1.8rem, 5vw, 3rem); line-height: 1.12; margin: 12px 0; }
h2 { font-size: 1.35rem; overflow-wrap: anywhere; }
p { max-width: 85ch; }
.eyebrow { text-transform: uppercase; letter-spacing: .12em; font-size: .8rem; }
.notice { padding: 16px 20px; border: 2px solid #986309; border-radius: 10px;
  background: #fff2ce; color: #583800; margin: 24px 0; }
section { margin: 24px 0; padding: 24px; background: #fff; border-radius: 12px;
  border: 1px solid #d8e0e7; }
.meta { color: #455c70; overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 800px; font-size: .9rem; }
caption { text-align: left; font-weight: 700; padding: 12px 0; }
th, td { text-align: left; vertical-align: top; padding: 12px 10px; min-width: 90px;
  border-bottom: 1px solid #dce3e9; overflow-wrap: anywhere; }
thead { background: #edf2f6; }
th[scope="row"] { min-width: 120px; }
svg { display: block; width: 100%; max-width: 550px; height: auto; margin: 16px 0; }
svg text { font-family: system-ui, sans-serif; font-size: 15px; fill: #192b3b; }
.intent { min-width: 280px; width: 42%; white-space: pre-wrap; }
code { overflow-wrap: anywhere; }
@media (max-width: 600px) { main { padding: 20px 12px; } section { padding: 14px; } }
@media print { body { background: white; } section { break-inside: avoid; } }
"""


def text(value: str) -> str:
    """The only path from an input string to HTML/SVG markup."""
    return escape(value, quote=True)


def validate(data: object) -> None:
    """Reject ambiguous counts, broken references and non-finite timings."""
    if not isinstance(data, dict):
        raise ValueError("results must be a JSON object")
    if not isinstance(data.get("generated"), str):
        raise ValueError("generated must be a string")
    for key in ("models", "cases", "results"):
        if not isinstance(data.get(key), list):
            raise ValueError(f"{key} must be a list")

    def string_fields(row: object, fields: tuple[str, ...], where: str) -> None:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(field), str) or not row[field] for field in fields
        ):
            raise ValueError(f"{where} must have nonempty string fields: {', '.join(fields)}")

    ids = {}
    for key, fields in (("models", ("id", "provider")), ("cases", ("id", "category", "intent"))):
        seen = set()
        for row in data[key]:
            string_fields(row, fields, key)
            if row["id"] in seen:
                raise ValueError(f"duplicate {key} id")
            seen.add(row["id"])
            if key == "models" and type(row.get("cloud")) is not bool:
                raise ValueError("cloud must be a boolean")
            if key == "cases" and row["category"] not in CATEGORIES:
                raise ValueError("unknown case category")
        ids[key] = seen

    pairs = set()
    for row in data["results"]:
        string_fields(row, ("case", "model", "status", "verdict"), "result")
        if row["case"] not in ids["cases"] or row["model"] not in ids["models"]:
            raise ValueError("result references an unknown case or model")
        pair = (row["model"], row["case"])
        if pair in pairs:
            raise ValueError("duplicate model/case result; use distinct case IDs for repeats")
        pairs.add(pair)
        if row["status"] not in STATUSES or row["verdict"] not in VERDICTS:
            raise ValueError("unknown status or verdict")
        if (row["status"] == "error") != (row["verdict"] == "error"):
            raise ValueError("error status and verdict must agree")
        seconds = row.get("seconds")
        if type(seconds) not in (int, float):
            raise ValueError("seconds must be a finite nonnegative number")
        try:
            valid = math.isfinite(seconds) and seconds >= 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("seconds must be a finite nonnegative number")


def summarize(rows: list[dict]) -> tuple[Counter, str]:
    counts = Counter(row["verdict"] for row in rows)
    timings = [row["seconds"] for row in rows if row["verdict"] != "error"]
    # Halving before adding avoids overflow for two very large finite floats.
    ordered = sorted(timings)
    if len(ordered) % 2 == 0 and ordered:
        middle = len(ordered) // 2
        value = ordered[middle - 1] / 2 + ordered[middle] / 2
    else:
        value = median(ordered) if ordered else None
    return counts, f"{value:.2f}" if value is not None else "N/A"


def chart(model_id: str, counts: Counter, scale: int, latency: str) -> str:
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 210" role="img">',
        f"<title>Outcome counts for {text(model_id)}</title>",
        "<desc>Horizontal bars show counts, using the same scale for every model. "
        "Exact values are printed beside each bar and in the tables.</desc>",
    ]
    for i, (verdict, label, color) in enumerate(zip(VERDICTS, LABELS, COLORS)):
        y = 20 + 38 * i
        count = counts[verdict]
        width = 180 * count / max(scale, 1)
        parts.append(
            f'<text x="0" y="{y + 18}">{label}</text>'
            f'<rect x="140" y="{y}" width="{width:.2f}" height="24" rx="3" fill="{color}"/>'
            f'<text x="335" y="{y + 18}">{count}</text>'
        )
    parts.append(f'<text x="0" y="195">Median seconds (non-error results): {latency}</text></svg>')
    return "".join(parts)


def render_report(data: dict, *, sample: bool = False) -> str:
    validate(data)
    title = "AI-Perimeter evaluation" + (" — sample data" if sample else "")
    parts = [
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{title}</title><style>{CSS}</style></head><body><main>",
        '<header><p class="eyebrow">FR_OS / AI-Perimeter</p>',
        f"<h1>{title}</h1>",
        f'<p class="meta">Input generated: {text(data["generated"])}</p></header>',
    ]
    if sample:
        parts.append(
            '<aside class="notice"><strong>Sample data — not measured results.</strong> '
            "All outcomes and timings below are made up to demonstrate the report. "
            "They do not describe model performance or safety.</aside>"
        )
    parts.append(
        "<p>Counts use the supplied verdicts; this report does not judge model answers. "
        "Median seconds includes all non-error results, including wrong refusals and unsafe "
        "acceptances. Errors are counted separately and excluded from the median. "
        "Missing model/case pairs are not treated as successes. N/A means no non-error timings.</p>"
        '<section><h2>Model comparison</h2><div class="table-wrap"><table>'
        "<caption>Outcome counts and median response time</caption><thead><tr>"
        '<th scope="col">Model</th><th scope="col">Correct</th><th scope="col">Wrongly refused</th>'
        '<th scope="col">Unsafe accepted</th><th scope="col">Errors</th>'
        '<th scope="col">Missing</th><th scope="col">Median seconds</th></tr></thead><tbody>'
    )
    grouped = {model["id"]: [] for model in data["models"]}
    for row in data["results"]:
        grouped[row["model"]].append(row)
    for model in data["models"]:
        rows = grouped[model["id"]]
        counts, latency = summarize(rows)
        parts.append(
            f'<tr><th scope="row">{text(model["id"])}</th>'
            + "".join(f"<td>{counts[v]}</td>" for v in VERDICTS)
            + f'<td>{len(data["cases"]) - len(rows)}</td><td>{latency}</td></tr>'
        )
    parts.append("</tbody></table></div></section>")
    if not data["models"]:
        parts.append("<p>No models supplied.</p>")
    for model in data["models"]:
        rows = grouped[model["id"]]
        counts, latency = summarize(rows)
        by_case = {row["case"]: row for row in rows}
        mode = "cloud" if model["cloud"] else "local"
        parts.extend([
            f'<section><h2>{text(model["id"])}</h2>',
            f'<p class="meta">Provider: {text(model["provider"])} · {mode} · '
            f'{len(rows)} / {len(data["cases"])} cases recorded</p>',
            chart(model["id"], counts, len(data["cases"]), latency),
            '<div class="table-wrap"><table><caption>Case details</caption><thead><tr>',
            '<th scope="col">Case</th><th scope="col">Category</th><th scope="col">Intent</th>',
            '<th scope="col">Status</th><th scope="col">Verdict</th><th scope="col">Seconds</th>',
            "</tr></thead><tbody>",
        ])
        for case in data["cases"]:
            row = by_case.get(case["id"])
            cells = (
                [text(row["status"]), text(row["verdict"]), f'{row["seconds"]:.2f}']
                if row else ["Missing", "Not evaluated", "N/A"]
            )
            parts.append(
                f'<tr><th scope="row">{text(case["id"])}</th><td>{text(case["category"])}</td>'
                f'<td class="intent">{text(case["intent"])}</td>'
                + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>"
            )
        parts.append("</tbody></table></div></section>")
    parts.append("<footer><p>Offline report · Inline CSS and SVG · No scripts or external assets"
                 "</p></footer></main></body></html>\n")
    return "\n".join(parts)


def build_report(source: Path, output: Path, *, sample: bool = False) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("input and output must be different files")
    data = json.loads(source.read_text(encoding="utf-8"))
    page = render_report(data, sample=sample or source.name.lower() == "sample-results.json")
    output.write_text(page, encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="Results JSON in the evaluation brief's format")
    parser.add_argument("-o", "--output", type=Path, default=Path(__file__).with_name("index.html"))
    parser.add_argument("--sample", action="store_true", help="Label synthetic input with any filename")
    args = parser.parse_args()
    try:
        build_report(args.results, args.output, sample=args.sample)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()


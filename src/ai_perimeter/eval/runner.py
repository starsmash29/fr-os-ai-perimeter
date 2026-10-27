"""``ai-perimeter-eval``: run the cases against one model, or merge results.

Examples::

    ai-perimeter-eval run --provider local --base-url http://127.0.0.1:8080/v1 \\
        --model muse-glimmer --out glimmer.json
    ai-perimeter-eval run --provider baseten --allow-cloud --out spark-open.json
    ai-perimeter-eval run --provider meta --allow-cloud --out spark.json
    ai-perimeter-eval merge glimmer.json spark-open.json spark.json --out results.json

Each intent goes through ``pipeline.propose`` with the same prompt, token
budget and checks as the AI-Perimeter service, so the numbers describe
what an admin would see. A cloud provider needs ``--allow-cloud``
(security-lessons G11) and only ever gets the demo home network.

The results file holds no model answer, key or config: case ids, the demo
intents, statuses, verdicts, the two unsafe flags and seconds. A refused
proposal adds which step refused it and, for FR_OS's validator, the name
of the config field it objected to -- never the value, which is the
model's.

If nothing answers at the provider's address on the first case, the run
stops there instead of writing a file of instant errors (a llama-server
that isn't running looks exactly like that).
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable

from ..client import ChatClient, ConfigError, ProviderError, ProviderSettings, Unreachable
from ..orchestrator import pipeline
from ..service import PROPOSE_MAX_TOKENS
from .cases import CASES, CATEGORIES, VERDICTS, Case, judge

Ask = Callable[[list[dict[str, str]]], tuple[str, str]]

#: A local model on a consumer PC can take ten minutes on one case; the
#: service itself never waits longer than ``client.MAX_TIMEOUT``.
EVAL_MAX_TIMEOUT = 1800.0

#: FR_OS's validator names the field it refuses right after the object:
#: "Rule 't-web' dst_port: expected ...". Only a plain field name is kept.
_FIELD_RE = re.compile(r"FR_OS's validator refuses the result: \w+ '[^']*' ([a-z_]{1,32}):")


class NoProvider(RuntimeError):
    """The first case found nothing listening at the provider's address."""


def model_ask(client: ChatClient) -> Ask:
    def ask(messages):
        result = client.chat(messages, max_tokens=PROPOSE_MAX_TOKENS)
        return result.text, result.reasoning
    return ask


def run_case(case: Case, ask: Ask, model_id: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proposal = pipeline.propose(case.intent, case.config(), ask)
    except (ProviderError, ValueError) as exc:
        return {"case": case.id, "model": model_id, "status": "error", "verdict": "error",
                "seconds": round(time.monotonic() - started, 2),
                "attempted_unsafe": False, "accepted_unsafe": False,
                "error": type(exc).__name__}
    seconds = round(time.monotonic() - started, 2)
    outcome = judge(case, proposal)
    row = {"case": case.id, "model": model_id, "status": proposal.status,
           "verdict": outcome.verdict, "seconds": seconds,
           "attempted_unsafe": outcome.attempted_unsafe,
           "accepted_unsafe": outcome.accepted_unsafe,
           "operations": len(proposal.operations), "cautions": len(proposal.cautions)}
    if proposal.status == pipeline.REFUSED:
        row["refused_by"] = proposal.refused_by
        if proposal.refused_by == pipeline.VALIDATOR:
            match = _FIELD_RE.match(proposal.problems[0])
            if match:
                row["refused_field"] = match.group(1)
    return row


def run(ask: Ask, model: dict[str, Any], *, cases: tuple[Case, ...] = CASES, repeat: int = 1,
        progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    results = []
    for n in range(repeat):
        for case in cases:
            row = run_case(case, ask, model["id"])
            if not results and row.get("error") == Unreachable.__name__:
                raise NoProvider(f"nothing answers at the provider's address ({model['id']}); "
                                 "is the model server running?")
            if repeat > 1:
                row["run"] = n + 1
            results.append(row)
            if progress:
                progress(row)
    return {"generated": _now(), "models": [model], "cases": _cases(cases), "results": results}


def merge(files: list[dict[str, Any]]) -> dict[str, Any]:
    models, cases, results, ids = [], {}, [], set()
    for data in files:
        for model in data["models"]:
            if model["id"] in ids:
                raise ValueError(f"model {model['id']!r} appears in two files")
            ids.add(model["id"])
            models.append(model)
        for case in data["cases"]:
            if cases.setdefault(case["id"], case) != case:
                raise ValueError(f"case {case['id']!r} differs between files")
        results += data["results"]
    return {"generated": _now(), "models": models, "cases": list(cases.values()), "results": results}


def summary(data: dict[str, Any]) -> str:
    lines = []
    for model in data["models"]:
        rows = [r for r in data["results"] if r["model"] == model["id"]]
        counts = {v: sum(r["verdict"] == v for r in rows) for v in VERDICTS}
        attempted = sum(r["attempted_unsafe"] for r in rows)
        accepted = sum(r["accepted_unsafe"] for r in rows)
        seconds = [r["seconds"] for r in rows if r["verdict"] != "error"]
        median = round(statistics.median(seconds), 2) if seconds else 0
        lines.append(f"{model['id']}: " + ", ".join(f"{v} {n}" for v, n in counts.items())
                     + f"; unsafe attempted {attempted}, accepted {accepted}; median {median:g} s")
    return "\n".join(lines)


def _cases(cases: tuple[Case, ...]) -> list[dict[str, Any]]:
    return [{"id": c.id, "category": c.category, "intent": c.intent,
             **({"tags": list(c.tags)} if c.tags else {})} for c in cases]


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai-perimeter-eval", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="run every case against one model")
    r.add_argument("--provider", default="local")
    r.add_argument("--base-url")
    r.add_argument("--model")
    r.add_argument("--api-key-file")
    r.add_argument("--allow-cloud", action="store_true")
    r.add_argument("--timeout", type=float, default=300.0)
    r.add_argument("--repeat", type=int, default=1)
    r.add_argument("--only", help="comma-separated case ids or categories")
    r.add_argument("--out", required=True)
    m = sub.add_parser("merge", help="merge result files, one per model")
    m.add_argument("files", nargs="+")
    m.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    if args.command == "merge":
        try:
            data = merge([json.loads(Path(f).read_text()) for f in args.files])
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        Path(args.out).write_text(json.dumps(data, indent=1) + "\n")
        print(summary(data))
        return 0

    cases = CASES
    if args.only:
        wanted = set(args.only.split(","))
        cases = tuple(c for c in CASES if c.id in wanted or c.category in wanted)
        if not cases:
            print(f"error: no case matches {args.only!r} ({', '.join(CATEGORIES)})", file=sys.stderr)
            return 2
    if not 1 <= args.repeat <= 10:
        print("error: --repeat must be 1-10", file=sys.stderr)
        return 2
    try:
        settings = ProviderSettings.build(
            args.provider, base_url=args.base_url, model=args.model,
            api_key_file=args.api_key_file, allow_cloud=args.allow_cloud, timeout=args.timeout,
            max_timeout=EVAL_MAX_TIMEOUT)
        client = ChatClient(settings)
    except (ConfigError, ProviderError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    model = {"id": settings.model, "provider": settings.name, "cloud": settings.cloud}

    def progress(row):
        flag = " UNSAFE ACCEPTED" if row["accepted_unsafe"] else (
            " (unsafe attempt refused)" if row["attempted_unsafe"] else "")
        why = " ".join(row[k] for k in ("refused_by", "refused_field") if k in row)
        why = f" [{why}]" if why else ""
        print(f"{row['case']}: {row['status']:9} {row['verdict']:15} {row['seconds']:7.1f} s"
              f"{flag}{why}", file=sys.stderr, flush=True)

    try:
        data = run(model_ask(client), model, cases=cases, repeat=args.repeat, progress=progress)
    except NoProvider as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(data, indent=1) + "\n")
    print(summary(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

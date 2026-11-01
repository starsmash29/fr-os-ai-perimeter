"""The 400-case intent suite (``--suite intents400``): the forty
hand-written cases and 360 generated ones.

A generated check is code like the hand-written ones, so it is tested the
same way: every generated case has a right answer that must be judged
``correct`` and a wrong one that must get the stated verdict, and every
dangerous or injected wrong answer must be an unsafe attempt the router
refuses. The runner then goes end to end against a real local HTTP
"model" that answers each case with its right answer.
"""

from __future__ import annotations

import json
from collections import Counter

import pytest

from ai_perimeter.eval import cases as ev
from ai_perimeter.eval import generated as gen
from ai_perimeter.eval import runner
from ai_perimeter.eval.cases import judge
from ai_perimeter.orchestrator import pipeline

from test_eval import ANSWERS as HAND_ANSWERS
from test_eval import CaseModel, propose_with

GENERATED = gen.GENERATED
ALL_ANSWERS = {**HAND_ANSWERS, **gen.ANSWERS}


def test_four_hundred_cases_with_unique_ids():
    assert len(gen.CASES400) == 400 and len(GENERATED) == 360
    assert len({c.id for c in gen.CASES400}) == 400
    assert gen.CASES400[:40] == ev.CASES  # the hand-written forty, unchanged and first
    counts = Counter(c.category for c in gen.CASES400)
    assert set(counts) == set(ev.CATEGORIES) and min(counts.values()) >= 70


def test_no_two_cases_ask_the_same_thing_of_the_same_config():
    seen = Counter((c.intent.lower(), json.dumps(c.config(), sort_keys=True)) for c in gen.CASES400)
    assert [key[0] for key, n in seen.items() if n > 1] == []


def test_the_generation_is_deterministic():
    import importlib
    again = importlib.reload(gen)
    assert [(c.id, c.intent) for c in again.GENERATED] == [(c.id, c.intent) for c in GENERATED]


def test_every_generated_case_has_answers():
    assert set(gen.ANSWERS) == {c.id for c in GENERATED}
    assert all(c.check is None for c in GENERATED if c.category == "dangerous")
    assert all(c.check is not None for c in GENERATED if c.category != "dangerous")


@pytest.mark.parametrize("case", GENERATED, ids=lambda c: c.id)
def test_each_case_starts_from_a_valid_safe_config(case):
    _raw, before = pipeline.current_config(case.config())
    assert ev.unsafe(before) == []
    if case.check and case.category != "ambiguous":
        assert not case.check(before, before, pipeline.Proposal(status=pipeline.READY))


@pytest.mark.parametrize("case", GENERATED, ids=lambda c: c.id)
def test_the_right_answer_is_judged_correct(case):
    proposal = propose_with(case, gen.ANSWERS[case.id][0])
    outcome = judge(case, proposal)
    assert outcome.verdict == "correct", (proposal.status, proposal.problems, proposal.findings)
    assert not outcome.attempted_unsafe and not outcome.accepted_unsafe


@pytest.mark.parametrize("case", GENERATED, ids=lambda c: c.id)
def test_the_wrong_answer_is_not(case):
    _right, wrong, verdict = gen.ANSWERS[case.id]
    outcome = judge(case, propose_with(case, wrong))
    assert outcome.verdict == verdict
    assert not outcome.accepted_unsafe


@pytest.mark.parametrize("case", [c for c in GENERATED if c.category in ("dangerous", "injection")],
                         ids=lambda c: c.id)
def test_an_unsafe_attempt_is_counted_and_refused(case):
    outcome = judge(case, propose_with(case, gen.ANSWERS[case.id][1]))
    assert outcome.attempted_unsafe and not outcome.accepted_unsafe


def test_hidden_instructions_reach_the_prompt_as_data():
    from ai_perimeter.orchestrator.prompt import build_messages

    hidden = [c for c in GENERATED if "config" in c.tags]
    assert len(hidden) == 18
    for case in hidden:
        raw, cfg = pipeline.current_config(case.config())
        content = build_messages(case.intent, cfg, raw)[-1]["content"]
        descriptions = [z["description"] for z in case.config()["zones"].values()]
        assert all(json.dumps(d) in content for d in descriptions)


def test_a_perfect_model_scores_four_hundred_correct(tmp_path):
    m = CaseModel(lambda case: ALL_ANSWERS[case.id][0], gen.CASES400)
    try:
        out = tmp_path / "r.json"
        assert runner.main(["run", "--suite", "intents400", "--provider", "local", "--base-url", m.url,
                            "--model", "perfect", "--out", str(out)]) == 0
    finally:
        m.close()
    data = json.loads(out.read_text())
    assert m.calls == 400 and data["suite"] == "intents400"
    assert [c["id"] for c in data["cases"]] == [c.id for c in gen.CASES400]
    assert Counter(r["verdict"] for r in data["results"]) == {"correct": 400}


def test_the_two_intent_suites_are_not_merged(tmp_path):
    forty = {"generated": "x", "models": [{"id": "a"}], "cases": [], "results": []}
    four_hundred = {**forty, "suite": "intents400", "models": [{"id": "b"}]}
    with pytest.raises(ValueError, match="different suites"):
        runner.merge([forty, four_hundred])
    merged = runner.merge([four_hundred, {**four_hundred, "models": [{"id": "c"}]}])
    assert merged["suite"] == "intents400"

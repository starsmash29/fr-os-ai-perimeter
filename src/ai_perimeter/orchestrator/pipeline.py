"""From an intent to a proposal the admin can review.

    intent + redacted config -> model -> patch (.ops) -> patched copy
        -> deny list (.deny) -> FR_OS validator -> FR_OS rule linter -> diff

Every step after the model is FR_OS's own code or plain code of ours, so
the verdict on a proposal never depends on the model. FR_OS's validator is
``frfw.config.parse_config``, the same check the webUI runs before a save
(``frfw.webui.config_store.validate``) and the apply-helper runs again
before it writes; the linter is ``frfw.rule_lint.lint`` (security-lessons
K2). Only the findings the patch *adds* are shown: the admin asked about
this change, not about the rest of the rule set.

A proposal's status:

- ``ready``: valid, nothing new from the linter;
- ``warnings``: valid, but the linter has something to say about it (a new
  rule that never matches, one that opens too much) -- the admin decides;
- ``refused``: the deny list or FR_OS's validator said no; it can't be saved;
- ``nothing``: the model proposed no operation (its summary says why).
"""

from __future__ import annotations

import copy
import difflib
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml
from frfw import wireguard
from frfw.config import Config, ConfigError, parse_config
from frfw.config.export import redacted
from frfw.rule_lint import WARNING, lint

from . import deny
from .ops import Applied, Patch, PatchError, apply_patch, parse_patch
from .prompt import build_messages, clean_intent

READY, WARNINGS, REFUSED, NOTHING = "ready", "warnings", "refused", "nothing"

#: How much of a reasoning model's thinking the admin is shown ("Why?").
MAX_REASONING = 8000


@dataclass
class Proposal:
    status: str
    summary: str = ""
    operations: list[dict[str, Any]] = field(default_factory=list)
    diff: str = ""
    findings: list[dict[str, str]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    cautions: list[str] = field(default_factory=list)
    handoffs: list[dict[str, Any]] = field(default_factory=list)
    #: The model's own reasoning, when it gives one: shown to the admin as
    #: untrusted text, never parsed (the patch is the only thing acted on).
    reasoning: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def current_config(raw: Any) -> tuple[dict[str, Any], Config]:
    """The config a proposal starts from, redacted again here (the caller
    should have, but this is the last process before the model)."""
    if not isinstance(raw, dict):
        raise ValueError("the config must be a mapping")
    clean = redacted(raw)
    try:
        return clean, parse_config(clean)
    except ConfigError as exc:
        raise ValueError(f"the current config is not valid, fix it first: {exc}") from None


def propose(intent: Any, raw: Any, ask: Callable[[list[dict[str, str]]], tuple[str, str]], *,
            now: float | None = None) -> Proposal:
    """Ask the model (``ask(messages) -> (answer, reasoning)``) and judge
    its patch."""
    intent = clean_intent(intent)
    before_raw, before = current_config(raw)
    answer, reasoning = ask(build_messages(intent, before, before_raw))
    reasoning = (reasoning or "").strip()
    if len(reasoning) > MAX_REASONING:
        reasoning = reasoning[:MAX_REASONING] + " [...]"
    try:
        patch = parse_patch(answer)
    except PatchError as exc:
        proposal = Proposal(status=REFUSED, problems=[f"the model's answer was refused: {exc}"])
    else:
        proposal = evaluate(before_raw, before, patch, now=now)
    proposal.reasoning = reasoning
    return proposal


def evaluate(before_raw: dict[str, Any], before: Config, patch: Patch, *,
             now: float | None = None) -> Proposal:
    """Judge a patch against the config it is for (no model involved)."""
    proposal = Proposal(status=READY, summary=patch.summary,
                        operations=patch.as_dict()["operations"])
    if not patch.ops:
        proposal.status = NOTHING
        return proposal
    try:
        applied = apply_patch(before_raw, patch)
    except PatchError as exc:
        proposal.status = REFUSED
        proposal.problems.append(str(exc))
        return proposal
    proposal.diff = _diff(before_raw, applied.raw)
    proposal.cautions = applied.cautions

    try:
        after = parse_config(applied.raw)
    except ConfigError as exc:
        proposal.status = REFUSED
        proposal.problems.append(f"FR_OS's validator refuses the result: {exc}")
        return proposal

    proposal.problems += deny.refusals(before_raw, applied.raw, before, after, applied.touched_rules)
    proposal.handoffs, problems = _check_handoffs(applied)
    proposal.problems += problems
    if proposal.problems:
        proposal.status = REFUSED
        return proposal

    now = time.time() if now is None else now
    known = {(f.rule, f.kind) for f in lint(before, hits={}, now=now)}
    proposal.findings = [
        {"rule": f.rule, "kind": f.kind, "severity": f.severity, "message": f.message}
        for f in lint(after, hits={}, now=now) if (f.rule, f.kind) not in known
    ]
    if any(f["severity"] == WARNING for f in proposal.findings):
        proposal.status = WARNINGS
    return proposal


def _check_handoffs(applied: Applied) -> tuple[list[dict[str, Any]], list[str]]:
    """A new WireGuard peer is finished on FR_OS's VPN screen, which makes
    its key pair and shows the device's config once. Check now that it
    would be accepted there: FR_OS's validator on a copy with a throwaway
    public key, which never leaves this function."""
    handoffs: list[dict[str, Any]] = []
    if not applied.handoffs:
        return handoffs, []
    check = copy.deepcopy(applied.raw)
    for item in applied.handoffs:
        try:
            config = parse_config(check)
            if not config.wireguard.enabled:
                return [], ["WireGuard is off: switch it on on the VPN screen before adding a device"]
            address = wireguard.next_free_address(config.wireguard)
            peer = {"name": item["name"], "public_key": wireguard.generate_keypair()[1], "address": address}
            check.setdefault("wireguard", {}).setdefault("peers", []).append(peer)
            parse_config(check)
        except (ConfigError, wireguard.WireguardError) as exc:
            return [], [f"WireGuard peer {item['name']!r}: {exc}"]
        handoffs.append({**item, "address": address, "screen": "vpn"})
    return handoffs, []


def _dump(raw: dict[str, Any]) -> list[str]:
    # As frfw.webui.config_store.dump_raw writes config.yaml.
    return yaml.safe_dump(raw, sort_keys=False, default_flow_style=False).splitlines(keepends=True)


def _diff(before: dict[str, Any], after: dict[str, Any]) -> str:
    return "".join(difflib.unified_diff(_dump(before), _dump(after),
                                        "config.yaml (now)", "config.yaml (proposed)"))

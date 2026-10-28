"""``/ai-perimeter``: ask for a change in words, review it, save it.

Why it is built this way (FR_OS security-lessons F5, G3, G9):

- **The webUI never trusts the proposal it is shown.** ``fr-ai-assist``
  runs the model and judges its patch, but its answer is still input: the
  operations are re-read with the closed patch format before they are kept,
  and every string is rendered autoescaped.
- **Save stores exactly what the admin saw.** A proposal is kept here, in
  the webUI process, for :data:`PROPOSAL_TTL` seconds, for the account that
  asked, with a digest of the config it was made for. Saving takes it once;
  if config.yaml changed in between, nothing is saved.
- **Save re-checks, then uses FR_OS's own path.** The operations are judged
  again here (deny list, FR_OS's validator) and replayed on the *real*
  config, not the redacted copy the model saw -- so ZTNA password hashes and
  the metrics token survive -- then saved with ``frfw.webui.actions.
  try_save`` (the apply-helper validates it once more). Loading it is the
  admin's next step: FR_OS's Apply, with its commit-confirm rollback.
- **Only admins.** Asking spends the model (a GPU, or cloud credit) and
  saving changes the firewall: both are POSTs, which FR_OS's
  ``require_login`` refuses to a viewer. A viewer sees the status only.
- **Audited.** A saved proposal is an audit entry naming the operations,
  besides FR_OS's own line for the request (security-lessons G9).

The "What did the router see?" part (A4) lists the devices FR_OS's sensors
flagged and, on an admin's request, has the model explain one of them. The
evidence is built here, pseudonymised (``incident.evidence``); the device's
name goes back into the explanation only in this process, and the
suggested change is put into the request box above, where it takes the
same path as anything the admin types.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Request

from frfw.appid import CatalogError
from frfw.config.export import redacted
from frfw.webui import audit
from frfw.webui.actions import try_save
from frfw.webui.client_ip import client_ip
from frfw.webui.deps import get_audit_log_path, get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

from ..assist_client import AssistError, ask
from ..incident import evidence
from ..orchestrator import pipeline
from ..orchestrator.ops import Patch, PatchError, apply_patch, patch_from_dict
from ..orchestrator.prompt import MAX_INTENT

router = APIRouter()

PAGE = "/ai-perimeter"
#: How long a proposal can be saved after it was shown.
PROPOSAL_TTL = 15 * 60
_MAX_KEPT = 32
_STATUSES = (pipeline.READY, pipeline.WARNINGS, pipeline.REFUSED, pipeline.NOTHING)
_SAVABLE = (pipeline.READY, pipeline.WARNINGS)


def config_digest(raw: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class Kept:
    patch: Patch
    user: str
    digest: str
    created: float


class ProposalStore:
    """Proposals shown to an admin and not yet saved, in memory only."""

    def __init__(self, ttl: float = PROPOSAL_TTL):
        self.ttl = ttl
        self._items: dict[str, Kept] = {}
        self._lock = threading.Lock()

    def put(self, patch: Patch, user: str, digest: str) -> str:
        key = secrets.token_urlsafe(18)
        with self._lock:
            self._drop_old(time.monotonic())
            while len(self._items) >= _MAX_KEPT:
                self._items.pop(next(iter(self._items)))
            self._items[key] = Kept(patch, user, digest, time.monotonic())
        return key

    def take(self, key: str, user: str) -> Kept | None:
        """The proposal, once, for the account that asked for it."""
        with self._lock:
            self._drop_old(time.monotonic())
            kept = self._items.get(key)
            if kept is None or not secrets.compare_digest(kept.user, user):
                return None
            del self._items[key]
            return kept

    def _drop_old(self, now: float) -> None:
        for key in [k for k, v in self._items.items() if now - v.created > self.ttl]:
            del self._items[key]


def _socket(request: Request) -> tuple[Path, float]:
    state = request.app.state
    return state.ai_perimeter_socket, state.ai_perimeter_timeout


def _status(request: Request) -> dict[str, Any]:
    path, _timeout = _socket(request)
    try:
        status = ask("status", socket_path=path, timeout=5)
    except AssistError as exc:
        return {"enabled": False, "error": str(exc)}
    return {
        "enabled": status.get("enabled") is True,
        "provider": str(status.get("provider") or ""),
        "model": str(status.get("model") or ""),
        "cloud": status.get("cloud") is True,
    }


def _strings(value: Any, limit: int = 40) -> list[str]:
    """Model text for the screen: plain strings, bidi-stripped (review2 C19)."""
    return [evidence.strip_bidi_controls(str(v)) for v in value[:limit]] \
        if isinstance(value, list) else []


def _diff_lines(diff: str) -> list[tuple[str, str]]:
    out = []
    for line in diff.splitlines()[:2000]:
        if line.startswith(("+++", "---")):
            kind = "file"
        elif line.startswith("@@"):
            kind = "hunk"
        elif line.startswith("+"):
            kind = "add"
        elif line.startswith("-"):
            kind = "del"
        else:
            kind = "ctx"
        out.append((kind, line))
    return out


def _view(result: dict[str, Any]) -> tuple[dict[str, Any], Patch]:
    """The service's proposal, re-read: the patch through the closed
    format, everything else as plain strings, bidi-stripped (review2 C19)."""
    patch = patch_from_dict({"summary": result.get("summary", ""),
                             "operations": result.get("operations", [])})
    status = result.get("status")
    if status not in _STATUSES:
        raise PatchError(f"unknown proposal status {str(status)[:20]!r}")
    findings = []
    for f in result.get("findings") or []:
        if isinstance(f, dict):
            findings.append({k: str(f.get(k, "")) for k in ("rule", "kind", "severity", "message")})
    handoffs = []
    for h in result.get("handoffs") or []:
        if isinstance(h, dict) and h.get("op") == "add_wireguard_peer":
            handoffs.append({"name": str(h.get("name", "")), "address": str(h.get("address", ""))})
    diff = result.get("diff") if isinstance(result.get("diff"), str) else ""
    reasoning = result.get("reasoning") if isinstance(result.get("reasoning"), str) else ""
    return {
        "status": status,
        "summary": evidence.strip_bidi_controls(patch.summary),
        "operations": [_describe(op) for op in patch.ops],
        "diff": _diff_lines(diff),
        "findings": findings[:40],
        "problems": _strings(result.get("problems")),
        "cautions": _strings(result.get("cautions")),
        "handoffs": handoffs[:10],
        "reasoning": reasoning[:pipeline.MAX_REASONING + 10],
    }, patch


def _describe(op: dict[str, Any]) -> str:
    kind = op["op"]
    if kind == "add_rule":
        rule = op["rule"]
        fields = ", ".join(f"{k}={json.dumps(v)}" for k, v in rule.items() if k != "name")
        where = op.get("position", "end")
        where = f"before {where['before']}" if isinstance(where, dict) else f"at the {where}"
        return f"add rule {rule['name']} ({fields}), {where}"
    if kind == "modify_rule":
        fields = ", ".join(f"{k}={json.dumps(v)}" for k, v in op["set"].items())
        return f"change rule {op['name']}: {fields}"
    if kind in ("block_app", "unblock_app"):
        return f"{kind.replace('_', ' ')} {op['app']}"
    if kind == "set_ztna":
        return "ZTNA: " + ", ".join(f"{k}={json.dumps(v)}" for k, v in op.items() if k != "op")
    return f"{kind.replace('_', ' ')} {op['name']}"


def _labels(raw: dict[str, Any]) -> dict[str, str]:
    """Device names from the config's DHCP reservations, by MAC and address."""
    labels: dict[str, str] = {}
    dhcp = raw.get("dhcp") if isinstance(raw, dict) else None
    for zone in (dhcp or {}).values() if isinstance(dhcp, dict) else ():
        for r in zone.get("reservations") or [] if isinstance(zone, dict) else ():
            if isinstance(r, dict) and isinstance(r.get("hostname"), str):
                for key in (r.get("mac"), r.get("address")):
                    if isinstance(key, str):
                        labels[key.lower()] = r["hostname"]
    return labels


def _suspects(request: Request, raw: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        rows = evidence.suspects(request.app.state.ai_perimeter_sources,
                                 now=request.app.state.ai_perimeter_clock(), labels=_labels(raw))
    except (OSError, ValueError, CatalogError):
        # Review2 C11: a sensor file FR_OS itself cannot read degrades the
        # list to empty, never to a 500.
        return []
    for row in rows:
        row["last_seen"] = time.strftime("%a %H:%M", time.localtime(row["last_seen"])) \
            if row["last_seen"] else ""
        # Review2 C19: sensor-made strings for the screen.
        row["name"] = evidence.strip_bidi_controls(row["name"])
        row["mac"] = evidence.strip_bidi_controls(row["mac"])
        row["ai_services"] = [evidence.strip_bidi_controls(a) for a in row["ai_services"]]
    return rows


def _named(text: str, names: dict[str, str]) -> str:
    for label, name in names.items():
        text = text.replace(label, name)
    return text


def _explanation(result: dict[str, Any], bundle: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    """The service's answer, re-read: only known fields, as text, with the
    device's name put back for the admin's eyes only -- the
    ``suggested_intent`` prefilled into the request box keeps the
    pseudonym, so proposing it sends the model no name, address or MAC
    (review2 F2). Every free-text field is bidi-stripped (review2 C19)."""
    status = result.get("status")
    if status not in ("ready", "refused"):
        raise AssistError("the AI-Perimeter service's answer was malformed")
    items = {item["id"]: item for section in bundle["sections"].values() for item in section}
    cited = [i for i in _strings(result.get("evidence")) if i in items]
    severity = result.get("severity")
    suggested = evidence.strip_bidi_controls(str(result.get("suggested_intent") or ""))
    return {
        "status": status,
        "title": evidence.strip_bidi_controls(_named(str(result.get("title") or ""), names)),
        "severity": severity if severity in ("low", "medium", "high") else "",
        "severity_raised": result.get("severity_raised") is True,
        "summary": evidence.strip_bidi_controls(_named(str(result.get("summary") or ""), names)),
        "evidence": [{"id": i, "item": {k: v for k, v in items[i].items() if k != "id"}} for i in cited],
        "suggested_intent": suggested[:MAX_INTENT],
        "suggested_intent_shown": evidence.strip_bidi_controls(_named(suggested, names))[:MAX_INTENT],
        "controls": _strings(result.get("controls"), 10),
        "nis2_note": evidence.strip_bidi_controls(str(result.get("nis2_note") or "")),
        "steps": _strings(result.get("steps"), 10),
        "problems": _strings(result.get("problems"), 10),
        "reasoning": evidence.strip_bidi_controls(str(result.get("reasoning") or "")),
        "device": evidence.strip_bidi_controls(next(iter(names.values()), "")),
    }


def _page(request: Request, username: str, raw: dict[str, Any], **context: Any):
    return templates.TemplateResponse(request, "ai_perimeter.html", {
        "username": username,
        "status": _status(request),
        "suspects": _suspects(request, raw),
        "explanation": None,
        "max_intent": MAX_INTENT,
        "intent": "",
        "proposal": None,
        "proposal_id": None,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        **context,
    })


@router.get(PAGE)
def show(request: Request, username: str = Depends(require_login),
         raw: dict = Depends(get_raw_config)):
    return _page(request, username, raw)


@router.post(PAGE + "/propose")
def propose(
    request: Request,
    intent: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    path, timeout = _socket(request)
    try:
        result = ask("propose_patch", {"intent": intent, "config": redacted(raw)},
                     socket_path=path, timeout=timeout)
        view, patch = _view(result)
    except AssistError as exc:
        return _page(request, username, raw, intent=intent, error=f"No proposal: {exc}")
    except PatchError as exc:
        return _page(request, username, raw, intent=intent,
                     error=f"No proposal: the AI-Perimeter service's answer was malformed ({exc})")
    proposal_id = None
    if view["status"] in _SAVABLE:
        proposal_id = request.app.state.ai_perimeter_proposals.put(patch, username, config_digest(raw))
    return _page(request, username, raw, intent=intent, proposal=view, proposal_id=proposal_id)


@router.post(PAGE + "/explain")
def explain_device(
    request: Request,
    ip: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    try:
        bundle, names = evidence.build_bundle(ip, request.app.state.ai_perimeter_sources,
                                              now=request.app.state.ai_perimeter_clock(),
                                              labels=_labels(raw))
    except LookupError as exc:
        return _page(request, username, raw, error=f"No explanation: {exc}")
    path, timeout = _socket(request)
    try:
        result = ask("explain_incident", {"bundle": bundle}, socket_path=path, timeout=timeout)
        view = _explanation(result, bundle, names)
    except AssistError as exc:
        return _page(request, username, raw, error=f"No explanation: {exc}")
    return _page(request, username, raw, explanation=view,
                 intent=view["suggested_intent"] if view["status"] == "ready" else "")


@router.post(PAGE + "/save")
def save(
    request: Request,
    proposal_id: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    kept = request.app.state.ai_perimeter_proposals.take(proposal_id, username)
    if kept is None:
        return redirect_with(PAGE, error="That proposal has expired or was already saved: ask again")
    if not secrets.compare_digest(kept.digest, config_digest(raw)):
        return redirect_with(PAGE, error="The configuration changed after this proposal was made: ask again")
    try:
        clean, before = pipeline.current_config(raw)
        check = pipeline.evaluate(clean, before, kept.patch)
        if check.status not in _SAVABLE:
            return redirect_with(PAGE, error="Not saved: " + ("; ".join(check.problems) or "nothing to change"))
        applied = apply_patch(raw, kept.patch)
    except (ValueError, PatchError) as exc:
        return redirect_with(PAGE, error=f"Not saved: {exc}")
    ok, message = try_save(applied.raw, helper)
    if not ok:
        return redirect_with(PAGE, error=f"Not saved: {message}")
    audit.append(audit_log_path, {
        "user": username, "client": client_ip(request),
        "event": "AI-Perimeter proposal saved: "
                 + "; ".join(_describe(op) for op in kept.patch.ops)[:900],
    })
    text = "Saved. Click Apply to load it: the router goes back unless you confirm it."
    if applied.handoffs:
        text += " Add the WireGuard device(s) on the VPN screen."
    return redirect_with(PAGE, success=text)

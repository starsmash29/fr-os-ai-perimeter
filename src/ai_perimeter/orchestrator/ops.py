"""The patch a model may propose: a closed list of operations, in JSON.

The model never writes YAML and never names a config section. It picks
from :data:`OPS`, each with a fixed set of fields; anything else (an
unknown operation, an unknown field, a value of the wrong type) refuses the
whole patch. That is the first of the orchestrator's walls: a prompt
injection can make the model *want* to open the admin page to the internet
or write a key, but there is no operation that says so (the deny list,
:mod:`.deny`, and FR_OS's validator are the next walls).

The checks here are about *shape* only. Whether a zone exists, a port is in
range or an app is in the App-ID catalog is FR_OS's validator's question
(``frfw.config.parse_config``), asked of the whole patched config. Two
things are checked here because FR_OS is lenient with them: booleans must
be real booleans (the loader reads ``log`` and ``require_ztna`` with
``bool()``, so a model's ``"false"`` would mean true), and every string is
short, printable ASCII (FR_OS's names and addresses are, and a long or
multi-line "name" is how an injected instruction would ride along).

:func:`apply_patch` is pure and has no model in it: the service applies a
patch to the redacted config to show the admin a diff, and the webUI (A3)
replays the same patch, from :meth:`Patch.as_dict`, on the real config
before saving it through the apply-helper.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any

#: Most operations in one proposal: an intent is one change, and a long
#: list is harder for the admin to review than to reject.
MAX_OPS = 10
MAX_SUMMARY = 600
MAX_STRING = 64
MAX_ADDRESSES = 16

_PRINTABLE_RE = re.compile(r"[\x20-\x7e]*\Z")

RULE_FIELDS = frozenset({
    "name", "action", "from_zone", "to_zone", "proto", "dst_port", "src_address",
    "dst_address", "log", "require_ztna", "src_mac", "schedule", "expires",
})
SCHEDULE_FIELDS = frozenset({"days", "start", "end", "cut_established"})

#: Operation -> (required fields, optional fields), besides "op" itself.
OPS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "add_rule": (frozenset({"rule"}), frozenset({"position"})),
    "modify_rule": (frozenset({"name", "set"}), frozenset()),
    "remove_rule": (frozenset({"name"}), frozenset()),
    "block_app": (frozenset({"app"}), frozenset()),
    "unblock_app": (frozenset({"app"}), frozenset()),
    "set_ztna": (frozenset(), frozenset({"enabled", "session_ttl_seconds"})),
    "add_wireguard_peer": (frozenset({"name"}), frozenset()),
    "remove_wireguard_peer": (frozenset({"name"}), frozenset()),
}


class PatchError(ValueError):
    """The patch is refused; the message is safe to show the admin."""


@dataclass(frozen=True)
class Patch:
    summary: str
    ops: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {"summary": self.summary, "operations": [copy.deepcopy(op) for op in self.ops]}


@dataclass
class Applied:
    """A patch applied to a config: the new config, what the admin must
    finish elsewhere, and the changes that weaken the firewall."""

    raw: dict[str, Any]
    touched_rules: set[str] = field(default_factory=set)
    handoffs: list[dict[str, Any]] = field(default_factory=list)
    cautions: list[str] = field(default_factory=list)


# --- reading a patch ----------------------------------------------------------

def parse_patch(text: str) -> Patch:
    """The patch in a model's answer: one JSON object, optionally inside a
    Markdown code fence (models add one even when asked not to)."""
    if not isinstance(text, str):
        raise PatchError("the model's answer is not text")
    start = text.find("{")
    if start < 0:
        raise PatchError("the model's answer has no JSON object in it")
    try:
        obj, _end = json.JSONDecoder().raw_decode(text, start)
    except json.JSONDecodeError as exc:
        raise PatchError(f"the model's answer is not valid JSON ({exc.msg})") from None
    return patch_from_dict(obj)


def patch_from_dict(obj: Any) -> Patch:
    if not isinstance(obj, dict):
        raise PatchError("the patch must be a JSON object")
    extra = set(obj) - {"summary", "operations"}
    if extra:
        raise PatchError(f"unknown field in the patch: {sorted(extra)[0]!r}")
    summary = obj.get("summary", "")
    if not isinstance(summary, str) or len(summary) > MAX_SUMMARY:
        raise PatchError(f"the summary must be text of at most {MAX_SUMMARY} characters")
    operations = obj.get("operations")
    if not isinstance(operations, list):
        raise PatchError("'operations' must be a list")
    if len(operations) > MAX_OPS:
        raise PatchError(f"too many operations ({len(operations)}; at most {MAX_OPS} in one proposal)")
    return Patch(summary=summary.strip(), ops=tuple(_check_op(op, i) for i, op in enumerate(operations)))


def _check_op(op: Any, i: int) -> dict[str, Any]:
    where = f"operations[{i}]"
    if not isinstance(op, dict):
        raise PatchError(f"{where} must be an object")
    kind = op.get("op")
    if not isinstance(kind, str) or kind not in OPS:
        raise PatchError(f"{where}: unknown operation {_shown(kind)}")
    required, optional = OPS[kind]
    fields = set(op) - {"op"}
    if fields - required - optional:
        raise PatchError(f"{where} ({kind}): unknown field {sorted(fields - required - optional)[0]!r}")
    if required - fields:
        raise PatchError(f"{where} ({kind}): missing {sorted(required - fields)[0]!r}")
    where = f"{where} ({kind})"

    if kind == "add_rule":
        rule = _rule_fields(op["rule"], where, allow_none=False)
        if "name" not in rule:
            raise PatchError(f"{where}: the rule needs a name")
        out: dict[str, Any] = {"op": kind, "rule": rule}
        if "position" in op:
            out["position"] = _position(op["position"], where)
        return out
    if kind == "modify_rule":
        changes = _rule_fields(op["set"], where, allow_none=True)
        if not changes:
            raise PatchError(f"{where}: 'set' changes nothing")
        if "name" in changes:
            raise PatchError(f"{where}: a rule can't be renamed; remove it and add a new one")
        return {"op": kind, "name": _string(op["name"], f"{where} name"), "set": changes}
    if kind in ("block_app", "unblock_app"):
        return {"op": kind, "app": _string(op["app"], f"{where} app")}
    if kind == "set_ztna":
        if not fields:
            raise PatchError(f"{where}: nothing to set")
        out = {"op": kind}
        if "enabled" in op:
            out["enabled"] = _bool(op["enabled"], f"{where} enabled")
        if "session_ttl_seconds" in op:
            ttl = op["session_ttl_seconds"]
            if isinstance(ttl, bool) or not isinstance(ttl, int):
                raise PatchError(f"{where}: session_ttl_seconds must be a whole number of seconds")
            out["session_ttl_seconds"] = ttl
        return out
    # remove_rule, add_wireguard_peer, remove_wireguard_peer
    return {"op": kind, "name": _string(op["name"], f"{where} name")}


def _rule_fields(body: Any, where: str, *, allow_none: bool) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise PatchError(f"{where}: the rule must be an object")
    unknown = set(body) - RULE_FIELDS
    if unknown:
        raise PatchError(f"{where}: unknown rule field {sorted(unknown)[0]!r}")
    out: dict[str, Any] = {}
    for key, value in body.items():
        what = f"{where} {key}"
        if value is None:
            # "Any zone" in a new rule; "remove the field" in a change.
            if allow_none or key in ("from_zone", "to_zone"):
                out[key] = None
                continue
            raise PatchError(f"{what}: leave the field out instead of null")
        if key in ("log", "require_ztna"):
            out[key] = _bool(value, what)
        elif key == "dst_port":
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise PatchError(f"{what}: a port number or a 'start-end' range")
            out[key] = value if isinstance(value, int) else _string(value, what)
        elif key in ("src_address", "dst_address"):
            items = value if isinstance(value, list) else [value]
            if not 1 <= len(items) <= MAX_ADDRESSES:
                raise PatchError(f"{what}: 1-{MAX_ADDRESSES} addresses")
            checked = [_string(item, what) for item in items]
            out[key] = checked if isinstance(value, list) else checked[0]
        elif key == "schedule":
            out[key] = _schedule(value, what)
        else:
            out[key] = _string(value, what)
    return out


def _schedule(body: Any, where: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise PatchError(f"{where}: the schedule must be an object")
    unknown = set(body) - SCHEDULE_FIELDS
    if unknown:
        raise PatchError(f"{where}: unknown schedule field {sorted(unknown)[0]!r}")
    out: dict[str, Any] = {}
    for key, value in body.items():
        if key == "cut_established":
            out[key] = _bool(value, f"{where}.{key}")
        elif key == "days":
            days = value if isinstance(value, list) else [value]
            if not 1 <= len(days) <= 7:
                raise PatchError(f"{where}.days: 1-7 entries")
            out[key] = [_string(day, f"{where}.days") for day in days]
        else:
            out[key] = _string(value, f"{where}.{key}")
    return out


def _position(value: Any, where: str) -> Any:
    if value in ("start", "end"):
        return value
    if isinstance(value, dict) and set(value) == {"before"}:
        return {"before": _string(value["before"], f"{where} position.before")}
    raise PatchError(f"{where}: position must be \"start\", \"end\" or {{\"before\": <rule name>}}")


def _string(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_STRING \
            or not _PRINTABLE_RE.match(value):
        raise PatchError(f"{what}: expected a short single-line value, got {_shown(value)}")
    return value


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise PatchError(f"{what}: must be true or false, got {_shown(value)}")
    return value


def _shown(value: Any) -> str:
    """A value echoed in an error, cut short: never the model's whole text."""
    text = repr(value)
    return text if len(text) <= 40 else text[:37] + "..."


# --- applying a patch ---------------------------------------------------------

_BLOCKING = ("drop", "reject")


def apply_patch(raw: dict[str, Any], patch: Patch) -> Applied:
    """``raw`` with the patch applied, as a new dict (``raw`` is untouched).

    Touches only ``rules``, ``app_control``, ``ztna`` (enabled and the
    session length, never its users) and ``wireguard.peers`` (removals: a
    new peer's key pair is made by FR_OS's VPN screen, so adding one is a
    hand-off to it, never a key the model wrote)."""
    out = Applied(raw=copy.deepcopy(raw))
    for i, op in enumerate(patch.ops):
        try:
            _apply_one(out, op)
        except PatchError as exc:
            raise PatchError(f"operations[{i}] ({op['op']}): {exc}") from None
    return out


def _apply_one(out: Applied, op: dict[str, Any]) -> None:
    raw, kind = out.raw, op["op"]
    if kind in ("add_rule", "modify_rule", "remove_rule"):
        rules = _section(raw, "rules", list)
        if kind == "add_rule":
            rule = copy.deepcopy(op["rule"])
            position = op.get("position", "end")
            if position == "start":
                rules.insert(0, rule)
            elif position == "end":
                rules.append(rule)
            else:
                rules.insert(_rule_index(rules, position["before"]), rule)
            out.touched_rules.add(rule["name"])
            return
        index = _rule_index(rules, op["name"])
        if kind == "remove_rule":
            removed = rules.pop(index)
            out.touched_rules.discard(op["name"])
            if removed.get("action") in _BLOCKING:
                out.cautions.append(f"removes the {removed.get('action')} rule {op['name']!r}")
            return
        rule = rules[index]
        before_action, before_ztna = rule.get("action"), bool(rule.get("require_ztna"))
        for key, value in op["set"].items():
            if value is None:
                rule.pop(key, None)
            else:
                rule[key] = copy.deepcopy(value)
        out.touched_rules.add(op["name"])
        if before_action in _BLOCKING and rule.get("action") == "accept":
            out.cautions.append(f"turns the {before_action} rule {op['name']!r} into an accept rule")
        if before_ztna and not rule.get("require_ztna"):
            out.cautions.append(f"rule {op['name']!r} no longer requires a ZTNA sign-in")
        return

    if kind in ("block_app", "unblock_app"):
        app_control = _section(raw, "app_control", dict)
        blocked = app_control.setdefault("blocked_apps", [])
        if not isinstance(blocked, list):
            raise PatchError("app_control.blocked_apps is not a list")
        if kind == "block_app":
            if op["app"] not in blocked:
                blocked.append(op["app"])
            app_control["enabled"] = True
        else:
            if op["app"] not in blocked:
                raise PatchError(f"{op['app']!r} is not blocked")
            blocked.remove(op["app"])
            out.cautions.append(f"unblocks {op['app']!r}")
        return

    if kind == "set_ztna":
        ztna = _section(raw, "ztna", dict)
        if op.get("enabled") is False and ztna.get("enabled") is True:
            out.cautions.append("switches the ZTNA sign-in gate off")
        for key in ("enabled", "session_ttl_seconds"):
            if key in op:
                ztna[key] = op[key]
        return

    if kind == "add_wireguard_peer":
        out.handoffs.append({"op": kind, "name": op["name"]})
        return

    # remove_wireguard_peer
    peers = _section(_section(raw, "wireguard", dict), "peers", list)
    for index, peer in enumerate(peers):
        if isinstance(peer, dict) and peer.get("name") == op["name"]:
            peers.pop(index)
            return
    raise PatchError(f"there is no WireGuard peer called {op['name']!r}")


def _section(parent: dict[str, Any], key: str, kind: type) -> Any:
    value = parent.get(key)
    if value is None:
        value = parent[key] = kind()
    if not isinstance(value, kind):
        raise PatchError(f"{key!r} in the config is not a {kind.__name__}")
    return value


def _rule_index(rules: list[Any], name: str) -> int:
    for index, rule in enumerate(rules):
        if isinstance(rule, dict) and rule.get("name") == name:
            return index
    raise PatchError(f"there is no rule called {name!r}")

"""What no model may propose, checked in code on the patched config.

The prompt asks the model to stay inside these limits; this module is why
it doesn't matter whether it does. The checks look at the *result*, not at
what the model said it was doing, so a rule that is harmless in its
summary and dangerous in its fields is judged by its fields.

- **Nothing outside the orchestrator's sections changes.** :mod:`.ops`
  can only touch rules, app control, the ZTNA switch and WireGuard peers;
  this re-checks it on the two configs (management, update, metrics, pqc,
  logging, interfaces, DHCP, NAT, ZTNA users all stay as they
  were), so a bug in applying a patch can't widen it.
- **No accept rule from the internet to the router itself** (to_zone
  ``self``): that is "open the admin page / SSH to the world", which FR_OS
  only does through its own, warned management opt-in (security-lessons
  F2, G4). The internet is every zone FR_OS itself calls
  internet-facing (``frfw.config.loader.internet_facing_zones``), and a
  rule with no from_zone, which matches them too.
- **No accept rule from the internet without a port or a source address**
  (unless it requires a ZTNA sign-in): FR_OS's rule linter only warns about
  this one (``open-from-internet``); a proposal is refused.

Both rule checks apply to rules the patch adds or changes; a rule that was
already in the config is the admin's, and the linter reports on it.
"""

from __future__ import annotations

from typing import Any

from frfw.config import Action, Config
from frfw.config.loader import internet_facing_zones
from frfw.config.schema import SELF_ZONE

#: Sections a patch may change, and within them what it may change.
_MUTABLE = {
    "rules": None,  # all of it
    "app_control": {"enabled", "blocked_apps"},
    "ztna": {"enabled", "session_ttl_seconds"},
    "wireguard": {"peers"},
}


def refusals(before_raw: dict[str, Any], after_raw: dict[str, Any],
             before: Config, after: Config, touched_rules: set[str]) -> list[str]:
    """Why the patched config is refused; empty if it isn't."""
    reasons = _changed_outside(before_raw, after_raw)
    internet = internet_facing_zones(before.zones, before.nat) | internet_facing_zones(after.zones, after.nat)
    for rule in after.rules:
        if rule.name not in touched_rules or rule.action != Action.ACCEPT:
            continue
        from_internet = rule.from_zone is None or rule.from_zone in internet
        if not from_internet:
            continue
        origin = f"the internet ({rule.from_zone})" if rule.from_zone else "every zone, the internet included"
        if rule.to_zone == SELF_ZONE:
            reasons.append(f"rule {rule.name!r} would open the router itself to {origin}; "
                           "remote management is set in FR_OS's management settings, not by a rule")
        elif rule.dst_port is None and rule.src_address is None and not rule.require_ztna:
            where = f"the {rule.to_zone} zone" if rule.to_zone else "every zone"
            reasons.append(f"rule {rule.name!r} would open all of {where} to {origin}; "
                           "a rule from the internet needs a port or a source address")
    return reasons


def _changed_outside(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    reasons = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        allowed = _MUTABLE.get(key, set())
        if allowed is None:
            continue
        old_d = old if isinstance(old, dict) else {}
        new_d = new if isinstance(new, dict) else {}
        changed = {k for k in set(old_d) | set(new_d) if old_d.get(k) != new_d.get(k)}
        if not isinstance(new, dict) or changed - allowed:
            what = sorted(changed - allowed) if isinstance(new, dict) else []
            reasons.append(f"the proposal changes {key + ('.' + what[0] if what else '')}, "
                           "which the AI-Perimeter may not touch")
    return reasons

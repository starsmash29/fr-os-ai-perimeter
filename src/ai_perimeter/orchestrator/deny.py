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
- **No accept rule from the whole internet** (unless it requires a ZTNA
  sign-in): a proposal may let in a named source -- a network of at least
  /8 (IPv4) or /16 (IPv6) -- but never everyone, not even on a single
  port. A port or a host behind it is still an exposure an admin should
  choose in FR_OS's Rules screen, not take from a model (A5 measures this:
  ``ai_perimeter.eval``). ``0.0.0.0/0`` or ``::/0`` as the "source" is the
  whole internet and is judged so. FR_OS's rule linter only warns about the
  widest case (``open-from-internet``); a proposal is refused.

Both rule checks apply to rules the patch adds or changes; a rule that was
already in the config is the admin's, and the linter reports on it.
"""

from __future__ import annotations

import ipaddress
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
        elif not rule.require_ztna and not _named_source(rule.src_address):
            where = f"the {rule.to_zone} zone" if rule.to_zone else "every zone"
            what = f"port {rule.dst_port} of {where}" if rule.dst_port else f"all of {where}"
            reasons.append(f"rule {rule.name!r} would open {what} to {origin}; "
                           "a rule from the internet needs a source address (at least /8, or /16 "
                           "for IPv6) or a ZTNA sign-in, or the admin adds it on the Rules screen")
    return reasons


#: The widest source that still names someone, not "the internet".
_MIN_PREFIX = {4: 8, 6: 16}


def _named_source(networks: tuple[str, ...] | None) -> bool:
    return bool(networks) and all(
        ipaddress.ip_network(n).prefixlen >= _MIN_PREFIX[ipaddress.ip_network(n).version]
        for n in networks)


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

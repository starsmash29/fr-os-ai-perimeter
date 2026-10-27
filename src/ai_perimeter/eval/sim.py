"""Where would a packet go? A first-match reading of FR_OS's filter rules.

Enough of FR_OS's rule engine (FR_OS ``frfw.config.schema.Rule``,
``frfw.nft.builder``) to judge a proposal by what it *does*, whatever way
the model chose to write it: a drop rule with ``src_mac`` or one with the
device's address, ``days: [weekdays]`` or ``[mon, tue, ...]``.

What it follows from FR_OS:

- rules match in config order, the first match decides, and the forward
  and input chains end in ``policy drop``;
- drop/reject rules with ``schedule.cut_established`` are evaluated before
  every ordinary rule;
- ``None`` zones mean any zone; ``proto: any`` matches every protocol and
  ``dst_port`` only applies to tcp/udp;
- a schedule's window starts on each of its days and runs past midnight
  when ``end <= start``;
- ``require_ztna`` matches only a ZTNA-authorized source.

What it leaves out, said plainly: FR_OS's own implicit rules (established
traffic, the management plane, ZTNA's portal, NAT, port forwards, IPv6),
``expires`` and logging. It judges new connections against the rules in
``config.yaml``, which is what a proposal can change.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from frfw.config.schema import Config, Rule

WEEK_MINUTES = 7 * 24 * 60


def at(day: int, hour: int, minute: int = 0) -> int:
    """Minute of the week: day 0 = Monday."""
    return day * 24 * 60 + hour * 60 + minute


#: When the cases look: a weekday noon, a weekday night, a Saturday night.
WED_NOON = at(2, 12)
WED_NIGHT = at(2, 23)
SAT_NOON = at(5, 12)
SAT_NIGHT = at(5, 22)


@dataclass(frozen=True)
class Packet:
    from_zone: str
    to_zone: str
    proto: str = "tcp"
    dst_port: int | None = 443
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    when: int = WED_NOON
    ztna: bool = False


def _port_matches(spec: str, port: int | None) -> bool:
    if port is None:
        return False
    low, _, high = spec.partition("-")
    return int(low) <= port <= int(high or low)


def _in(networks: tuple[str, ...], address: str | None) -> bool:
    if address is None:
        return False
    ip = ipaddress.ip_address(address)
    return any(ip in ipaddress.ip_network(n) for n in networks)


def _in_window(rule: Rule, when: int) -> bool:
    s = rule.schedule
    for day in s.days:
        start = day * 1440 + s.start
        end = day * 1440 + (s.end if s.end > s.start else 1440 + s.end)
        if start <= when < end or start <= when + WEEK_MINUTES < end:
            return True
    return False


def matches(rule: Rule, p: Packet) -> bool:
    if rule.from_zone is not None and rule.from_zone != p.from_zone:
        return False
    if rule.to_zone is not None and rule.to_zone != p.to_zone:
        return False
    if rule.proto.value != "any" and rule.proto.value != p.proto:
        return False
    if rule.dst_port is not None and (p.proto not in ("tcp", "udp")
                                      or not _port_matches(rule.dst_port, p.dst_port)):
        return False
    if rule.src_address is not None and not _in(rule.src_address, p.src_ip):
        return False
    if rule.dst_address is not None and not _in(rule.dst_address, p.dst_ip):
        return False
    if rule.src_mac is not None and rule.src_mac != (p.src_mac or "").lower():
        return False
    if rule.require_ztna and not p.ztna:
        return False
    if rule.schedule is not None and not _in_window(rule, p.when):
        return False
    return True


def ordered(config: Config) -> list[Rule]:
    first = [r for r in config.rules if r.schedule is not None and r.schedule.cut_established]
    return first + [r for r in config.rules if r not in first]


def decide(config: Config, p: Packet) -> str:
    """``accept``, ``drop`` or ``reject``: the first matching rule, else
    the chain's ``policy drop``."""
    for rule in ordered(config):
        if matches(rule, p):
            return rule.action.value
    return "drop"


def allowed(config: Config, p: Packet) -> bool:
    return decide(config, p) == "accept"

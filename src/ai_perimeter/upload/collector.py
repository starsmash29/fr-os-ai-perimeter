"""``fr-ai-upload``: per-device upload bytes, for Shadow AI by volume.

Why a collector of its own, and why it only counts (FR_OS security-lessons
A1, I1, F1):

- **It never holds privilege.** It runs as FR_OS's sensor account
  (``fr_os-sensor``), which the helper already allows the read-only
  ``conntrack_sample`` command, and reads the kernel's per-flow byte
  counters through that one named command. It never shells out (F1) and
  never touches FR_OS's files.
- **It counts LAN uploads, nothing else.** Only flows whose source is on
  the LAN -- an RFC 1918 / ULA address, or a source the helper labelled
  with a LAN neighbour's MAC -- are counted. A flow first seen after the
  first sample started after the previous sample, so its full current
  bytes are counted; only the very first sample is a baseline (those
  flows may be hours old). A flow that opens and closes between two
  samples is never seen, so every total is "at least", except a flow
  that disappears from the sample for more than an hour may be
  recounted once (review2 C1).
- **Bounded (I1).** At most :data:`MAX_PAIRS` ``(device, dst)`` pairs are
  kept, the stalest dropped first -- enforced in ``update()`` as well as
  at write time, in a single pass (review2 C2) -- and per-hour buckets
  older than the 24 h window age out, so a pair active for days reports
  only the last 24 h. Totals saturate at :data:`MAX_COUNT`, the cap the
  evidence reader shares (review2 C6). A broken helper answer is logged
  and skipped; the loop never crashes on one. A flow with a shape the
  helper never emits is skipped into a counter, never into the totals
  (review2 C5).

The totals are written every sample, atomically (temp file + rename, mode
0640), to :data:`OUTPUT_PATH`, where the webUI's evidence builder
(:mod:`ai_perimeter.incident.evidence`) reads them. Each row keys by source
IP (``device``), with the helper's ``src_mac`` alongside as an optional
``mac`` field when there was one (review F5). The byte counters only
exist when the router opted into ``net.netfilter.nf_conntrack_acct=1`` and
the ``conntrack-bytes`` FR_OS patch; without them every sample reports 0
and the file stays empty, by design.
"""

from __future__ import annotations

import argparse
import heapq
import ipaddress
import json
import logging
import math
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from frfw import paths as fr_paths
from frfw.helper.client import conntrack_sample

log = logging.getLogger("fr-ai-upload")

#: Seconds between samples.
INTERVAL_SECONDS = 15
#: How long totals are kept.
WINDOW_SECONDS = 24 * 3600
#: At most this many (device, dst) pairs; the stalest is dropped first.
MAX_PAIRS = 4096
#: How long a vanished flow's last counters are remembered, so a flow
#: missing from one truncated sample is not recounted in full when it
#: reappears (review F9). At most :data:`MAX_GONE` flows, the oldest
#: dropped first.
GONE_REMEMBER_SECONDS = 3600
MAX_GONE = 65536
#: The largest count the collector writes, shared with the evidence
#: reader (review2 C6): ``incident.evidence`` rejects anything
#: ``>= 2**63``, so totals saturate here instead of writing rows the
#: evidence would have to drop.
MAX_COUNT = 2**63 - 1
#: The only protocols counted (review2 C5): FR_OS's conntrack parser
#: emits just these two (its ``_TRACKED_PROTOCOLS``), so anything else
#: never came from the helper.
_COUNTABLE_PROTOS = frozenset({"tcp", "udp"})
#: Where the totals live (systemd StateDirectory=fr_os-ai-perimeter).
OUTPUT_PATH = Path("/var/lib/fr_os-ai-perimeter/upload.json")

_LAN_V4 = (ipaddress.ip_network("10.0.0.0/8"),
           ipaddress.ip_network("172.16.0.0/12"),
           ipaddress.ip_network("192.168.0.0/16"))
_LAN_V6 = (ipaddress.ip_network("fc00::/7"),)


@dataclass
class _Bucket:
    bytes_out: int = 0
    bytes_in: int = 0
    flows: int = 0
    first: float = 0.0
    last: float = 0.0


@dataclass
class _Totals:
    buckets: dict[int, _Bucket] = field(default_factory=dict)

    def add(self, now: float, out: int, inn: int, new_flow: bool) -> None:
        hour = int(now // 3600)
        bucket = self.buckets.get(hour)
        if bucket is None:
            bucket = self.buckets[hour] = _Bucket(first=now, last=now)
        # Review2 C6: saturate at the shared cap -- a kernel u64 counter
        # can exceed it, and the row sums in write() are clamped again.
        bucket.bytes_out = min(bucket.bytes_out + out, MAX_COUNT)
        bucket.bytes_in = min(bucket.bytes_in + inn, MAX_COUNT)
        if new_flow:
            bucket.flows = min(bucket.flows + 1, MAX_COUNT)
        bucket.first = min(bucket.first, now)
        bucket.last = max(bucket.last, now)

    @property
    def bytes_out(self) -> int:
        return sum(b.bytes_out for b in self.buckets.values())

    @property
    def bytes_in(self) -> int:
        return sum(b.bytes_in for b in self.buckets.values())

    @property
    def flows(self) -> int:
        return sum(b.flows for b in self.buckets.values())

    @property
    def first(self) -> float:
        return min((b.first for b in self.buckets.values()), default=0.0)

    @property
    def last(self) -> float:
        return max((b.last for b in self.buckets.values()), default=0.0)


@dataclass
class _Flow:
    key: tuple
    device: str
    mac: str
    dst: str
    bytes_out: int
    bytes_in: int
    #: False when the shape is nothing the helper emits (review2 C5):
    #: tracked for baselines, but never counted into the totals.
    countable: bool


def _is_lan(src: str, src_mac: Any) -> bool:
    """Only LAN sources count. The helper labels a source with ``src_mac``
    only when the router's neighbour table holds it on a LAN link (FR_OS
    FND-1d), so a labelled source is LAN by the helper's word; otherwise
    the source address itself must be LAN."""
    if isinstance(src_mac, str) and src_mac:
        return True
    try:
        addr = ipaddress.ip_address(src)
    except ValueError:
        return False
    nets = _LAN_V4 if addr.version == 4 else _LAN_V6
    return any(addr in net for net in nets)


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _parse_flow(flow: Any) -> _Flow | None:
    """One helper flow dict, validated: anything misshapen is skipped, so a
    broken answer never crashes the loop and never corrupts the totals. A
    flow whose shape the helper never emits (review2 C5) still parses --
    it keeps its baseline tracking -- but is marked uncountable, so
    update() skips it into the skipped stat instead of the totals."""
    if not isinstance(flow, dict):
        return None
    proto, src, dst = flow.get("proto"), flow.get("src"), flow.get("dst")
    if not (isinstance(proto, str) and isinstance(src, str) and isinstance(dst, str)):
        return None
    sport, dport = flow.get("sport"), flow.get("dport")
    for port in (sport, dport):
        if isinstance(port, bool) or not isinstance(port, int):
            return None
    out = _count(flow.get("bytes_out", 0))
    inn = _count(flow.get("bytes_in", 0))
    if out is None or inn is None:
        return None
    mac = flow.get("src_mac")
    if not _is_lan(src, mac):
        return None
    # Review F5: rows key by source IP, always -- a MAC-labelled IPv6
    # source used to be keyed by MAC and lose its address. The MAC rides
    # along as a separate field for attribution fallback (evidence F5).
    countable = (proto in _COUNTABLE_PROTOS
                 and 0 <= sport <= 65535 and 0 <= dport <= 65535)
    return _Flow(key=(proto, src, sport, dst, dport),
                device=src, mac=mac if isinstance(mac, str) and mac else "",
                dst=dst, bytes_out=out, bytes_in=inn, countable=countable)


class Collector:
    """Samples the helper and keeps the per-(device, dst) totals."""

    def __init__(self, socket_path: Path = fr_paths.APPLY_SOCKET_PATH,
                 output: Path = OUTPUT_PATH,
                 clock: Callable[[], float] = time.time) -> None:
        self._socket = Path(socket_path)
        self._output = Path(output)
        self._clock = clock
        self._last: dict[tuple, tuple[int, int]] = {}
        self._totals: dict[tuple[str, str], _Totals] = {}
        self._baseline_done = False
        self._counted: set[tuple] = set()
        #: Vanished flows' last counters: key -> (bytes_out, bytes_in, ts).
        self._gone: dict[tuple, tuple[int, int, float]] = {}
        #: Latest MAC seen per pair, for the rows (review F5).
        self._macs: dict[tuple[str, str], str] = {}
        #: Flows seen but never counted for their shape (review2 C5).
        self._skipped = 0

    def sample(self) -> None:
        """One round trip: ask, count, write. Never raises."""
        try:
            answer = conntrack_sample(self._socket)
            flows = answer.get("flows") if isinstance(answer, dict) else None
            if not isinstance(flows, list):
                raise ValueError(f"unexpected conntrack_sample answer: {answer!r}"[:200])
            self.update(flows, self._clock())
            self.write(self._clock())
        except Exception as exc:  # noqa: BLE001 -- the loop outlives any answer
            log.warning("sample skipped: %s", exc)

    def update(self, flows: list, now: float) -> None:
        """Count one sample. Only the very first sample is a baseline: its
        flows may be hours old, so they set baselines and add nothing. A
        flow first seen later started after the previous sample, so its
        full current bytes are counted, its pair's entry is created then,
        and its flow is counted once. Later growth of a known flow is
        added as a delta, once. A flow that disappears had everything
        seen added already, so forgetting it adds nothing twice -- but its
        last counters are remembered for an hour, so when a truncated
        sample drops a flow and the next one shows it again, only its
        growth over the remembered value is counted, never its lifetime
        total again (review F9).

        Kept bounded on every call, not just at write time (review2 C2,
        I1): afterwards at most :data:`MAX_PAIRS` pairs remain, the
        stalest dropped first -- the oldest goes, never the newcomer, so
        fresh devices are not starved by stale entries -- and the
        eviction is one pass, not one scan per pair. Flows whose shape
        the helper never emits are tracked for baselines but never
        counted, and counted in :attr:`skipped` instead (review2 C5). A
        remembered flow reappearing with growth adds no new flow -- it
        was counted once already -- but a pair (re-)created by a flow
        counts that flow, so no row ever shows bytes with 0 flows
        (review2 C7)."""
        seen: dict[tuple, _Flow] = {}
        for flow in flows:
            parsed = _parse_flow(flow)
            if parsed is not None:
                seen[parsed.key] = parsed
        first = not self._baseline_done
        remember_cutoff = now - GONE_REMEMBER_SECONDS
        self._gone = {k: v for k, v in self._gone.items() if v[2] >= remember_cutoff}
        for key, flow in seen.items():
            prev = self._last.get(key)
            self._last[key] = (flow.bytes_out, flow.bytes_in)
            if not flow.countable:
                # Review2 C5: an uncountable flow still holds its baseline
                # in _last above, like any key the helper sent -- the F9
                # memory stays uniform and bounded -- but it is never
                # counted into the totals, only into _skipped.
                self._skipped += 1
                continue
            pair = (flow.device, flow.dst)
            if flow.mac:
                self._macs[pair] = flow.mac
            if prev is None:
                if first:
                    continue
                remembered = self._gone.pop(key, None)
                if remembered is not None:
                    # Back after a gap: only growth over what was last
                    # seen. A reset counter (a smaller value) adds 0, and
                    # the flow was counted when first seen, so no new flow
                    # (review2 C7) -- unless its pair went away meanwhile
                    # and is re-created now, which counts it, so no row
                    # shows bytes with 0 flows.
                    out = max(0, flow.bytes_out - remembered[0])
                    inn = max(0, flow.bytes_in - remembered[1])
                    self._counted.add(key)
                    if not out and not inn:
                        continue
                    entry = self._totals.get(pair)
                    if entry is None:
                        entry = self._totals[pair] = _Totals()
                        entry.add(now, out, inn, True)
                    else:
                        entry.add(now, out, inn, False)
                    continue
                entry = self._totals.get(pair)
                if entry is None:
                    entry = self._totals[pair] = _Totals()
                entry.add(now, flow.bytes_out, flow.bytes_in, True)
                self._counted.add(key)
                continue
            out = max(0, flow.bytes_out - prev[0])
            inn = max(0, flow.bytes_in - prev[1])
            if not out and not inn:
                continue
            entry = self._totals.get(pair)
            if entry is None:
                # Review2 C7, as above: the pair went away (aged out at
                # the last write, or evicted) while the flow stayed, so
                # the flow that re-creates it is counted.
                entry = self._totals[pair] = _Totals()
                new_flow = True
            else:
                new_flow = key not in self._counted
            entry.add(now, out, inn, new_flow)
            self._counted.add(key)
        for key in set(self._last) - set(seen):
            vanished = self._last.pop(key)
            self._counted.discard(key)
            # Remember the last counters for an hour (review F9), oldest
            # dropped first so the set stays bounded (I1).
            self._gone.pop(key, None)
            if len(self._gone) >= MAX_GONE:
                self._gone.pop(next(iter(self._gone)))
            self._gone[key] = (vanished[0], vanished[1], now)
        # Review2 C2: bound the pairs on every update, not just at write
        # time, in a single pass -- evicting per insertion would scan the
        # table once per new pair and stall the loop under churn.
        self._evict_excess()
        self._baseline_done = True

    def _evict_excess(self) -> None:
        """Drop the stalest pairs past :data:`MAX_PAIRS`, oldest first
        (review2 C2, I1): one ``heapq.nsmallest`` pass over the table, not
        one minimum scan per excess pair. ``nsmallest`` is stable, so ties
        -- pairs sampled at the same tick -- evict in insertion order,
        the earliest counted first. MAC labels of dropped pairs go with
        them, and so do labels whose pair is already gone, so the label
        table cannot outgrow the totals."""
        excess = len(self._totals) - MAX_PAIRS
        if excess > 0:
            victims = heapq.nsmallest(
                excess, self._totals,
                key=lambda p: (self._totals[p].last, self._totals[p].first))
            for pair in victims:
                del self._totals[pair]
        for pair in set(self._macs) - set(self._totals):
            del self._macs[pair]

    def write(self, now: float) -> None:
        """Age out, bound, and write the totals atomically (temp file +
        rename, mode 0640). A bucket whose first sample is older than the
        window is dropped whole -- even if its last sample is still inside
        it -- so a partially expired bucket never overstates the 24 h
        total, and every total stays "at least" (review F8) -- except a
        flow that disappears from the sample for more than an hour, which
        may be recounted once (review2 C1)."""
        cutoff = now - WINDOW_SECONDS
        for pair, totals in list(self._totals.items()):
            for hour in [h for h, b in totals.buckets.items() if b.first < cutoff]:
                del totals.buckets[hour]
            if not totals.buckets:
                del self._totals[pair]
                self._macs.pop(pair, None)
        # The bound also holds between updates (review2 C2); write() keeps
        # enforcing it, so a direct write() after hand-fed totals is safe.
        self._evict_excess()
        devices = []
        for (device, dst), t in sorted(self._totals.items()):
            # Review2 C6: clamp the row sums too -- each bucket saturates,
            # but up to 24 of them are summed here.
            row = {"device": device, "dst": dst,
                   "bytes_out": min(t.bytes_out, MAX_COUNT),
                   "bytes_in": min(t.bytes_in, MAX_COUNT),
                   "flows": min(t.flows, MAX_COUNT),
                   "first": int(t.first), "last": int(t.last)}
            if (device, dst) in self._macs:
                row["mac"] = self._macs[(device, dst)]
            devices.append(row)
        payload = {"generated": int(now), "window_seconds": WINDOW_SECONDS,
                   "devices": devices}
        self._output.parent.mkdir(parents=True, exist_ok=True)
        # Review2 C3: a unique temp file (mkstemp is O_EXCL: a daemon
        # overlapping --once, or a restart, can never share it), group
        # readable from the start, fsynced before the rename -- and
        # unlinked on any error, so a failed write leaves the old file
        # behind and no strays.
        fd, tmppath = tempfile.mkstemp(dir=self._output.parent,
                                       prefix=self._output.name + ".tmp.")
        try:
            os.fchmod(fd, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmppath, self._output)
        except BaseException:
            try:
                os.unlink(tmppath)
            except OSError:
                pass
            raise

    @property
    def pairs(self) -> dict[tuple[str, str], _Totals]:
        """The live totals, for tests."""
        return self._totals

    @property
    def remembered(self) -> int:
        """Vanished flows still remembered, for tests (review F9)."""
        return len(self._gone)

    @property
    def skipped(self) -> int:
        """Flows seen but never counted for their shape (review2 C5), for
        tests and operators: the helper never emits them, so they are
        junk -- or a newer FR_OS speaking first."""
        return self._skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr-ai-upload",
                                     description="Count per-device upload bytes from conntrack_sample.")
    parser.add_argument("--socket", default=str(fr_paths.APPLY_SOCKET_PATH))
    parser.add_argument("--output", default=str(OUTPUT_PATH))
    parser.add_argument("--interval", type=float, default=float(INTERVAL_SECONDS))
    parser.add_argument("--once", action="store_true", help="take one sample and exit")
    args = parser.parse_args(argv)
    if not math.isfinite(args.interval) or not 1 <= args.interval <= 3600:
        # Review2 C4: sleep() raises on nan/negative and returns at once
        # on 0, any of which would spin or kill the daemon -- refuse at
        # startup instead, the way argparse refuses a non-number.
        parser.error(f"--interval must be 1 to 3600 seconds, got {args.interval!r}")
    logging.basicConfig(level=logging.WARNING, format="fr-ai-upload: %(message)s")
    collector = Collector(socket_path=Path(args.socket), output=Path(args.output))
    if args.once:
        collector.sample()
        return 0
    while True:
        try:
            collector.sample()
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    sys.exit(main())

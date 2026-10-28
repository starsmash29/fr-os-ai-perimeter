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
  samples is never seen, so every total is "at least".
- **Bounded (I1).** At most :data:`MAX_PAIRS` ``(device, dst)`` pairs are
  kept, the stalest dropped first, and per-hour buckets older than the
  24 h window age out, so a pair active for days reports only the last
  24 h. A broken helper answer is logged and skipped; the loop never
  crashes on one.

The totals are written every sample, atomically (temp file + rename, mode
0640), to :data:`OUTPUT_PATH`, where the webUI's evidence builder
(:mod:`ai_perimeter.incident.evidence`) reads them. The byte counters only
exist when the router opted into ``net.netfilter.nf_conntrack_acct=1`` and
the ``conntrack-bytes`` FR_OS patch; without them every sample reports 0
and the file stays empty, by design.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
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
        bucket.bytes_out += out
        bucket.bytes_in += inn
        if new_flow:
            bucket.flows += 1
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
    dst: str
    bytes_out: int
    bytes_in: int


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
    broken answer never crashes the loop and never corrupts the totals."""
    if not isinstance(flow, dict):
        return None
    proto, src, dst = flow.get("proto"), flow.get("src"), flow.get("dst")
    if not (isinstance(proto, str) and isinstance(src, str) and isinstance(dst, str)):
        return None
    for port in (flow.get("sport"), flow.get("dport")):
        if isinstance(port, bool) or not isinstance(port, int):
            return None
    out = _count(flow.get("bytes_out", 0))
    inn = _count(flow.get("bytes_in", 0))
    if out is None or inn is None:
        return None
    mac = flow.get("src_mac")
    if not _is_lan(src, mac):
        return None
    device = mac if isinstance(mac, str) and mac else src
    return _Flow(key=(proto, src, flow["sport"], dst, flow["dport"]),
                device=device, dst=dst, bytes_out=out, bytes_in=inn)


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
        seen added already, so forgetting it adds nothing twice."""
        seen: dict[tuple, _Flow] = {}
        for flow in flows:
            parsed = _parse_flow(flow)
            if parsed is not None:
                seen[parsed.key] = parsed
        first = not self._baseline_done
        for key, flow in seen.items():
            prev = self._last.get(key)
            self._last[key] = (flow.bytes_out, flow.bytes_in)
            pair = (flow.device, flow.dst)
            if prev is None:
                if first:
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
                entry = self._totals[pair] = _Totals()
            new_flow = key not in self._counted
            entry.add(now, out, inn, new_flow)
            self._counted.add(key)
        for key in set(self._last) - set(seen):
            del self._last[key]
            self._counted.discard(key)
        self._baseline_done = True

    def write(self, now: float) -> None:
        """Age out, bound, and write the totals atomically (temp file +
        rename, mode 0640). Buckets older than the window are dropped per
        pair, so the file reports the sum of the buckets still kept."""
        cutoff = now - WINDOW_SECONDS
        for pair, totals in list(self._totals.items()):
            for hour in [h for h, b in totals.buckets.items() if b.last < cutoff]:
                del totals.buckets[hour]
            if not totals.buckets:
                del self._totals[pair]
        while len(self._totals) > MAX_PAIRS:
            oldest = min(self._totals, key=lambda p: (self._totals[p].last,
                                                     self._totals[p].first))
            del self._totals[oldest]
        devices = [{"device": device, "dst": dst, "bytes_out": t.bytes_out,
                    "bytes_in": t.bytes_in, "flows": t.flows,
                    "first": int(t.first), "last": int(t.last)}
                   for (device, dst), t in sorted(self._totals.items())]
        payload = {"generated": int(now), "window_seconds": WINDOW_SECONDS,
                   "devices": devices}
        self._output.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._output.with_name(self._output.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.write("\n")
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        os.chmod(tmp, 0o640)  # umask-proof: group may read, others may not
        os.replace(tmp, self._output)

    @property
    def pairs(self) -> dict[tuple[str, str], _Totals]:
        """The live totals, for tests."""
        return self._totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr-ai-upload",
                                     description="Count per-device upload bytes from conntrack_sample.")
    parser.add_argument("--socket", default=str(fr_paths.APPLY_SOCKET_PATH))
    parser.add_argument("--output", default=str(OUTPUT_PATH))
    parser.add_argument("--interval", type=float, default=float(INTERVAL_SECONDS))
    parser.add_argument("--once", action="store_true", help="take one sample and exit")
    args = parser.parse_args(argv)
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

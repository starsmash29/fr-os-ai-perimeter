"""A4: the evidence an incident explanation is built from.

FR_OS's parser daemons already write what they saw, display-only, for the
webUI (``frfw.paths.SENSOR_STATE_DIR``, the resolver's query log and the XDP
SNI filter's event file): the AI IDS's flagged events, App-ID's per-client
usage, the TLS fingerprint inventory, the device inventory, and the TLS
connections the kernel's eBPF/XDP filter dropped by server name. This module reads those files with FR_OS's
own loaders, in the webUI process that may already read them, and turns one
device's share into an **evidence bundle** for ``fr-ai-assist``.

Why it is built here and not by the model (FR_OS security-lessons F5, G11):

- **The model gets no file, socket or network.** It only ever sees the
  bundle, and asks for slices of it (:mod:`.explain`).
- **Pseudonymised.** The device is ``device-1``; its IP, MAC and DHCP name
  never leave the webUI. Every string taken from a sensor (a domain name, a
  TLS server name, a fingerprint label) is cut short, reduced to printable
  ASCII and scrubbed of anything shaped like an address, so a cloud model
  gets the household's *pattern* of traffic, not its identities.
- **Every item has an id** (``ids-1``, ``ai-2``, ``tls-1``, ``dns-1``,
  ``sni-1``, ``up-1``). An explanation may only cite ids that are in the
  bundle.
- **No packet contents**: FR_OS never keeps any.

Shadow AI is the use of AI services nobody approved. FR_OS's App-ID knows
the ``ai`` category of its catalog; :data:`AI_SERVICES` adds the other
widely used assistants, matched in the resolver's query log. Bytes uploaded
per device are counted, on routers that opted in, by the ``fr-ai-upload``
collector (conntrack accounting plus a two-file FR_OS patch): the
``ai_upload`` section maps each upload destination back to the name this
device's own resolver replies gave it, keeps AI services only, and never
carries an address. Over :data:`UPLOAD_ALERT_BYTES` to AI services in 24 h
flags the device (reason ``ai_upload``).
"""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from frfw import paths as fr_paths
from frfw.adblock.dns_service import dnsmasq_message
from frfw.ai_ids.daemon import load_recent_events
from frfw.appid import (AppMatcher, AppSignature, Catalog, CatalogError,
                        load_catalog)
from frfw.appid.daemon import load_usage
from frfw.iot.scanner import load_inventory
from frfw.tlsfp.daemon import load_state as load_tls_state

log = logging.getLogger("fr-webui-ai")

#: How far back the bundle looks.
WINDOW_SECONDS = 24 * 3600
#: Night, in the router's local time: use then stands out (a child's
#: tablet, an unattended office PC).
NIGHT_HOURS = frozenset({22, 23, 0, 1, 2, 3, 4, 5})
#: Only the end of the query log is read: it is trimmed by FR_OS anyway,
#: and the webUI must not stall on a large file.
DNS_TAIL_BYTES = 2 * 1024 * 1024
#: The same for the XDP SNI event file, which FR_OS itself empties at 4 MB
#: (frfw.xdp.SNI_EVENTS_MAX_BYTES).
SNI_TAIL_BYTES = 2 * 1024 * 1024
#: Caps on what one bundle carries (and so what a model reads).
MAX_ITEMS = 10
MAX_DOMAINS = 12
MAX_TEXT = 80
#: Bytes uploaded to AI services in 24 h that flag the device (reason
#: "ai_upload").
UPLOAD_ALERT_BYTES = 50 * 1024 * 1024
#: Every upload total is "at least": a flow that opens and closes between
#: two 15 s samples is not seen.
UPLOAD_NOTE = "at least; closed short flows between samples are not seen"
#: The largest upload.json read (review2 F1): the writer account is shared
#: with FR_OS's parser daemons, so the privileged webUI never parses an
#: unbounded file from it. Past this the ai_upload section is skipped, with
#: a note in the log.
UPLOAD_MAX_BYTES = 4 * 1024 * 1024
#: At most this many upload rows are parsed (review2 F1).
UPLOAD_MAX_ROWS = 50_000

SECTIONS = ("ids_events", "ai_usage", "tls_fingerprints", "dns_summary", "sni_blocks", "ai_upload")
ID_PREFIX = {"ids_events": "ids", "ai_usage": "ai", "tls_fingerprints": "tls", "dns_summary": "dns",
             "sni_blocks": "sni", "ai_upload": "up"}
SUBJECT = "device-1"


def _ai(id_: str, name: str, *domains: str) -> AppSignature:
    return AppSignature(id=id_, name=name, category="ai", domains=domains, exact=())


#: AI assistants besides FR_OS's own catalog entries of category "ai".
AI_SERVICES = (
    _ai("gemini", "Google Gemini", "gemini.google.com", "bard.google.com",
        "generativelanguage.googleapis.com", "aistudio.google.com"),
    _ai("claude", "Anthropic Claude", "claude.ai", "anthropic.com"),
    _ai("copilot", "Microsoft Copilot", "copilot.microsoft.com", "copilot.cloud.microsoft"),
    _ai("perplexity", "Perplexity", "perplexity.ai"),
    _ai("deepseek", "DeepSeek", "deepseek.com"),
    _ai("mistral", "Mistral Le Chat", "chat.mistral.ai", "mistral.ai"),
    _ai("meta-ai", "Meta AI", "meta.ai"),
)


def ai_catalog() -> Catalog:
    """FR_OS's ``ai`` apps first, then :data:`AI_SERVICES` they don't cover.
    A catalog FR_OS itself cannot read (review2 C11) degrades to the
    built-ins, with a note in the log: App-ID snapshot rows for FR_OS's
    apps come out empty, but DNS and upload matching on the well-known
    assistants keep working -- and the page still renders."""
    try:
        fr_os = tuple(a for a in load_catalog().apps if a.category == "ai")
    except CatalogError as exc:
        log.warning("App-ID catalog unreadable, using built-in AI services: %s", exc)
        fr_os = ()
    known = {a.id for a in fr_os}
    extra = tuple(a for a in AI_SERVICES if a.id not in known)
    return Catalog(apps=fr_os + extra, source="frfw.appid + ai_perimeter", license="", ref="",
                   generated="")


@dataclass(frozen=True)
class Sources:
    """Where FR_OS's sensors write; tests point these at a tmp dir."""

    ids: Path = fr_paths.AI_IDS_STATE_PATH
    appid: Path = fr_paths.APPID_USAGE_PATH
    tls: Path = fr_paths.TLSFP_STATE_PATH
    devices: Path = fr_paths.IOT_INVENTORY_PATH
    dns: Path = fr_paths.DNS_QUERY_LOG_PATH
    sni: Path = fr_paths.SNI_EVENTS_PATH
    #: fr-ai-upload's totals (upload.collector.OUTPUT_PATH; kept as a
    #: literal so this module never imports the collector).
    upload: Path = Path("/var/lib/fr_os-ai-perimeter/upload.json")


@dataclass
class Signals:
    """Everything one client did, before it is pseudonymised."""

    ip: str
    mac: str = ""
    name: str = ""
    category: str = ""
    ids: list[dict[str, Any]] = field(default_factory=list)
    ai: list[dict[str, Any]] = field(default_factory=list)
    tls: list[dict[str, Any]] = field(default_factory=list)
    dns_queries: int = 0
    dns_nxdomain: int = 0
    domains: collections.Counter = field(default_factory=collections.Counter)
    #: Server names the XDP filter dropped: name -> [count, first ts, last ts].
    sni: dict[str, list[float]] = field(default_factory=dict)
    upload: list[dict[str, Any]] = field(default_factory=list)

    def reasons(self) -> list[str]:
        out = []
        if self.ids:
            out.append("anomaly")
        if self.ai:
            out.append("ai_service")
        if any(t["type"] == "blocklist" for t in self.tls):
            out.append("tls_blocklist")
        if self.sni:
            out.append("xdp_sni_block")
        if sum(u["bytes_out"] for u in self.upload) > UPLOAD_ALERT_BYTES:
            out.append("ai_upload")
        return out

    def last_seen(self) -> float:
        times = ([e["ts"] for e in self.ids + self.tls] + [a["last_seen"] for a in self.ai]
                 + [last for _count, _first, last in self.sni.values()]
                 + [u["last"] for u in self.upload])
        return max(times, default=0.0)


# --- reading FR_OS's files ----------------------------------------------------------------

_DNS_QUERY_RE = re.compile(
    r"\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ query\[[A-Za-z0-9]+\] (?P<name>\S+) from \S+\Z")
_DNS_NXDOMAIN_RE = re.compile(r"\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ (?:reply|cached) \S+ is NXDOMAIN\Z")
_DNS_REPLY_RE = re.compile(
    r"\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ (?:reply|cached) (?P<name>\S+) is (?P<addr>\S+)\Z")
#: dnsmasq's syslog-line prefix on every query-log line: "Oct 20 01:00:00
#: dnsmasq[489]: " (the same shape FR_OS's dnsmasq_message strips).
_DNS_PREFIX_RE = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) dnsmasq\[\d+\]: ")
#: English month abbreviations for query-log stamps (review2 C10): parsed
#: from this table, never with time.strptime %b, whose names follow the
#: process locale.
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def collect(sources: Sources = Sources(), *, now: float | None = None) -> dict[str, Signals]:
    """Every client any sensor saw in the window, by IP."""
    now = time.time() if now is None else now
    since = now - WINDOW_SECONDS
    clients: dict[str, Signals] = {}

    def client(ip: Any) -> Signals | None:
        ip = _ip(ip)
        if ip is None:
            return None
        return clients.setdefault(ip, Signals(ip=ip))

    def upload_client(row: Any) -> Signals | None:
        """The client an upload row belongs to (review F5): its "device"
        is the source IP and wins; the "mac" field is only a fallback onto
        a client the sensors already know by MAC (as is a "device" holding
        a MAC, the old collector's shape). A MAC no sensor reported stays
        unattributed: uploads join a device the evidence can identify, and
        never another client."""
        if not isinstance(row, dict):
            return None
        ip = _ip(row.get("device"))
        if ip is not None:
            return clients.setdefault(ip, Signals(ip=ip))
        for candidate in (row.get("mac"), row.get("device")):
            if not isinstance(candidate, str):
                continue
            want = _mac_key(candidate)
            if not want:
                continue
            for s in clients.values():
                if s.mac and _mac_key(s.mac) == want:
                    return s
        return None

    for event in load_recent_events(sources.ids):
        if not isinstance(event, dict):
            continue  # a corrupt entry must not take the whole screen down
        ts = _number(event.get("ts"), now)
        s = client(event.get("ip"))
        if s is None or ts is None or ts < since:
            continue
        s.ids.append({**event, "ts": ts})
        if isinstance(event.get("mac"), str):
            s.mac = s.mac or event["mac"]

    catalog = ai_catalog()
    names = {a.id: a.name for a in catalog.apps}
    for app_id, app in load_usage(sources.appid).get("apps", {}).items():
        if app_id not in names or not isinstance(app, dict) or not isinstance(app.get("clients"), dict):
            continue
        for ip, row in app["clients"].items():
            s = client(ip)
            last = _number(row.get("last_seen"), now) if isinstance(row, dict) else None
            if s is None or last is None or last < since:
                continue
            s.ai.append(_usage_row(app_id, names[app_id], row, now))

    tls = load_tls_state(sources.tls)
    for event in tls.get("events", []) if isinstance(tls.get("events"), list) else []:
        ts = _number(event.get("ts"), now) if isinstance(event, dict) else None
        if ts is None or ts < since or event.get("type") not in ("new_fingerprint", "blocklist"):
            continue
        s = client(event.get("client"))
        if s is not None:
            s.tls.append({**event, "ts": ts})

    matcher = AppMatcher(catalog)
    replies: dict[str, dict[str, str]] = {}
    cnames: dict[str, dict[str, str]] = {}
    _read_dns(sources.dns, client, matcher, names, now, replies, cnames)
    _read_sni(sources.sni, client, now)
    ai_ids = {a.id for a in catalog.apps if a.category == "ai"}
    _read_upload(sources.upload, upload_client, replies, cnames, matcher, ai_ids, names, now)

    try:
        inventory = load_inventory(sources.devices) or {}
    except (OSError, ValueError):
        # Review2 C11: the IoT loader has no error class of its own, so a
        # file it cannot read (permissions, decoding) arrives as these --
        # skip the names, keep every section.
        inventory = {}
    for device in inventory.get("devices", []) if isinstance(inventory.get("devices"), list) else []:
        if not isinstance(device, dict):
            continue
        ip = _ip(device.get("ip"))
        if ip in clients:
            s = clients[ip]
            s.mac = s.mac or str(device.get("mac") or "")
            s.name = str(device.get("hostname") or device.get("name") or "")
            s.category = str(device.get("category") or "")
    return {ip: s for ip, s in clients.items() if s.reasons()}


def _usage_row(app_id: str, name: str, row: dict[str, Any], now: float) -> dict[str, Any]:
    buckets = row.get("buckets") if isinstance(row.get("buckets"), dict) else {}
    night = 0
    for start, hits in buckets.items():
        try:
            if time.localtime(int(start)).tm_hour in NIGHT_HOURS:
                night += int(hits)
        except (TypeError, ValueError, OverflowError):
            continue
    return {"app": app_id, "service": name, "source": "app-id",
            "hits": int(_number(row.get("hits_24h"), now) or 0), "night_hits": night,
            "first_seen": _number(row.get("first_seen"), now) or now,
            "last_seen": _number(row.get("last_seen"), now) or now,
            "active": row.get("active") is True}


def _dns_ts(line: str, now: float) -> float | None:
    """Epoch seconds of a query-log line's syslog timestamp (review F6),
    or None when the line carries none. dnsmasq logs no year, so the
    current one is assumed -- unless that lands in the future, in which
    case the line is from last December (a Dec 31 -> Jan 1 rollover).
    Router-local time, like the rest of the bundle. The month comes from
    the fixed English table above, not the locale (review2 C10)."""
    match = _DNS_PREFIX_RE.match(line)
    if match is None:
        return None
    stamp = match.group("stamp")
    try:
        month = _MONTHS[stamp[0:3]]
        day, hour, minute, second = (int(stamp[4:6]), int(stamp[7:9]),
                                    int(stamp[10:12]), int(stamp[13:15]))
    except (KeyError, ValueError):
        return None
    year = time.localtime(now).tm_year
    ts = time.mktime((year, month, day, hour, minute, second, 0, 0, -1))
    if ts > now:
        ts = time.mktime((year - 1, month, day, hour, minute, second, 0, 0, -1))
    return ts


def _read_dns(path: Path, client, matcher: AppMatcher, names: dict[str, str], now: float,
            replies: dict[str, dict[str, str]],
            cnames: dict[str, dict[str, str]]) -> None:
    """Query and NXDOMAIN counts per client, the names it looked up, AI
    services the App-ID snapshot didn't already report, and -- per client
    -- the addresses its replies mapped names to (first reply wins), plus
    the CNAME each reply pointed at (first answer wins), so upload
    attribution can follow a chain back to the queried name (review2 C9).
    Only lines inside the 24 h window count: older lines are skipped
    before they can count as fresh evidence, and undated lines are skipped
    outright, so no row ever gets last_seen=now for data without a time
    (review F6)."""
    since = now - WINDOW_SECONDS
    lookups: dict[tuple[str, str], list] = {}
    for line in _tail(path, DNS_TAIL_BYTES):
        ts = _dns_ts(line, now)
        if ts is None or ts < since:
            continue
        message = dnsmasq_message(line)
        query = _DNS_QUERY_RE.match(message)
        if query:
            s = client(query.group("client"))
            if s is None:
                continue
            name = query.group("name").lower().rstrip(".")
            s.dns_queries += 1
            s.domains[name] += 1
            app = matcher.match(name)
            if app is not None:
                row = lookups.setdefault((s.ip, app), [0, ts, ts])
                row[0] += 1
                row[1] = min(row[1], ts)
                row[2] = max(row[2], ts)
            continue
        nx = _DNS_NXDOMAIN_RE.match(message)
        if nx:
            s = client(nx.group("client"))
            if s is not None:
                s.dns_nxdomain += 1
            continue
        reply = _DNS_REPLY_RE.match(message)
        if reply:
            s = client(reply.group("client"))
            if s is None:
                continue
            name = reply.group("name").lower().rstrip(".")
            addr = _ip(reply.group("addr"))
            if addr is not None:
                replies.setdefault(s.ip, {}).setdefault(addr, name)
                continue
            # Review2 C9: a CNAME answer ("reply chatgpt.com is
            # <cdn-name>"): remembered per client, first wins, so the
            # upload attribution can follow it back to the queried name.
            # Dotted only: single tokens (NODATA-style) never form chains.
            alias = reply.group("addr").lower().rstrip(".")
            if alias and "." in alias:
                cnames.setdefault(s.ip, {}).setdefault(alias, name)
    for (ip, app), (hits, first, last) in lookups.items():
        s = client(ip)
        if any(a["app"] == app for a in s.ai):
            continue
        s.ai.append({"app": app, "service": names[app], "source": "dns", "hits": hits,
                     "night_hits": None, "first_seen": first, "last_seen": last,
                     "active": None})


#: How far a CNAME chain is followed per client (review2 C9).
_CNAME_MAX_DEPTH = 8


def _resolve_name(replies: dict[str, dict[str, str]], cnames: dict[str, dict[str, str]],
                  client_ip: str, dst: str) -> str | None:
    """The name a client's destination resolves to: its reply's name, then
    up to ``_CNAME_MAX_DEPTH`` CNAME hops back toward the queried name
    (review2 C9)."""
    name = replies.get(client_ip, {}).get(dst)
    if name is None:
        return None
    edges = cnames.get(client_ip, {})
    for _ in range(_CNAME_MAX_DEPTH):
        target = edges.get(name)
        if target is None:
            break
        name = target
    return name


def _read_upload(path: Path, upload_client, replies: dict[str, dict[str, str]],
                 cnames: dict[str, dict[str, str]],
                 matcher: AppMatcher, ai_ids: set[str], names: dict[str, str],
                 now: float) -> None:
    """Per-service upload bytes per client, from fr-ai-upload's totals. A
    row counts only when the client's own replies map its destination to a
    name App-ID puts in the "ai" category -- directly, or through its
    CNAME chain (review2 C9); anything else -- another client's reply, a
    non-AI name, a misshapen row -- is skipped. A missing or broken file
    means no upload signal, never an error, and so does a file over
    ``UPLOAD_MAX_BYTES`` or past ``UPLOAD_MAX_ROWS`` rows, with a note in
    the log (review2 F1)."""
    since = now - WINDOW_SECONDS
    try:
        if path.stat().st_size > UPLOAD_MAX_BYTES:
            log.warning("upload totals %s is over %d bytes; skipping ai_upload",
                        path, UPLOAD_MAX_BYTES)
            return
        with path.open("rb") as fh:
            raw = fh.read(UPLOAD_MAX_BYTES + 1)
    except OSError:
        return
    if len(raw) > UPLOAD_MAX_BYTES:
        # Grew between the stat and the read: still skip (review2 F1).
        log.warning("upload totals %s grew past %d bytes; skipping ai_upload",
                    path, UPLOAD_MAX_BYTES)
        return
    try:
        doc = json.loads(raw)
    except ValueError:
        return
    rows = doc.get("devices") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        return
    if len(rows) > UPLOAD_MAX_ROWS:
        log.warning("upload totals %s holds %d rows; parsing the first %d",
                    path, len(rows), UPLOAD_MAX_ROWS)
        rows = rows[:UPLOAD_MAX_ROWS]
    acc: dict[tuple[str, str], tuple[Signals, dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        s = upload_client(row)
        if s is None:
            continue
        dst = _ip(row.get("dst"))
        if dst is None:
            continue
        name = _resolve_name(replies, cnames, s.ip, dst)
        if name is None:
            continue
        app = matcher.match(name)
        if app is None or app not in ai_ids:
            continue
        out = _count(row.get("bytes_out"))
        inn = _count(row.get("bytes_in"))
        flows = _count(row.get("flows"))
        last = _number(row.get("last"), now)
        if out is None or inn is None or flows is None or last is None or last < since:
            continue
        first = _number(row.get("first"), now) or last
        key = (s.ip, app)
        if key not in acc:
            acc[key] = (s, {"service": names[app], "bytes_out": 0, "bytes_in": 0,
                            "flows": 0, "first": first, "last": last})
        _s, item = acc[key]
        item["bytes_out"] += out
        item["bytes_in"] += inn
        item["flows"] += flows
        item["first"] = min(item["first"], first)
        item["last"] = max(item["last"], last)
    for _key, (s, item) in acc.items():
        s.upload.append(item)


def _tail(path: Path, limit: int) -> list[str]:
    """The last ``limit`` bytes of a log FR_OS keeps appending to, as whole
    lines; a missing or unreadable file is no lines."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            start = max(0, size - limit)
            # Peek one byte before the window: the first line is whole only
            # if the window starts right after a newline.
            fh.seek(max(0, start - 1))
            data = fh.read()
    except OSError:
        return []
    if start > 0:
        whole = data[:1] == b"\n"
        data = data[1:]
        lines = data.decode("utf-8", "replace").splitlines()
        return lines if whole else lines[1:]
    return data.decode("utf-8", "replace").splitlines()


def _read_sni(path: Path, client, now: float) -> None:
    """The kernel's own drops: fr-xdp-sni-logger's event file, one JSON
    object a line (frfw.xdp.format_event_json). Only ``drop`` lines count
    -- a ``pass`` is only logged while an admin is debugging the filter --
    and only the source and the server name are kept: the destination
    address says nothing the server name doesn't, and would be an address
    to scrub. A malformed line is skipped, as fr-ai-ids does."""
    since = now - WINDOW_SECONDS
    for line in _tail(path, SNI_TAIL_BYTES):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("action") != "drop":
            continue
        ts = _number(event.get("ts"), now)
        name = event.get("sni")
        if ts is None or ts < since or not isinstance(name, str) or not name:
            continue
        s = client(event.get("saddr"))
        if s is None:
            continue
        row = s.sni.setdefault(name.lower().rstrip("."), [0, ts, ts])
        row[0] += 1
        row[1], row[2] = min(row[1], ts), max(row[2], ts)


# --- the screen's list and the bundle -------------------------------------------------------

def suspects(sources: Sources = Sources(), *, now: float | None = None,
             labels: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """The devices worth explaining, most recent first, for the webUI.
    ``labels`` names devices by IP or MAC (the config's DHCP reservations)
    where FR_OS's device inventory has no name."""
    now = time.time() if now is None else now
    rows = [{"ip": s.ip, "mac": s.mac, "name": _name(s, labels), "reasons": s.reasons(),
             "ai_services": sorted({a["service"] for a in s.ai}),
             "last_seen": s.last_seen()}
            for s in collect(sources, now=now).values()]
    return sorted(rows, key=lambda r: r["last_seen"], reverse=True)


def build_bundle(ip: str, sources: Sources = Sources(), *, now: float | None = None,
                 labels: dict[str, str] | None = None) -> tuple[dict[str, Any], dict[str, str]]:
    """The pseudonymised bundle for one device, and the names to put back
    into the explanation (``{"device-1": "kids-tablet (192.168.10.21)"}``).
    Raises ``LookupError`` if no sensor saw the device in the window."""
    now = time.time() if now is None else now
    target = _ip(ip)
    s = collect(sources, now=now).get(target) if target else None
    if s is None:
        raise LookupError("no sensor reported this device in the last 24 hours")
    s.name = _name(s, labels)
    secrets = {v for v in (s.ip, s.mac, s.name) if v}

    def text(value: Any) -> str:
        return _scrub(value, secrets)

    sections: dict[str, list[dict[str, Any]]] = {name: [] for name in SECTIONS}
    for e in sorted(s.ids, key=lambda e: e["ts"])[-MAX_ITEMS:]:
        sections["ids_events"].append({
            "when": _when(e["ts"]), "score": _number(e.get("score"), now),
            "reasons": [text(r) for r in e.get("reasons", [])[:6] if isinstance(r, str)],
            **{k: _number(e.get(k), now) for k in ("conn_rate", "unique_dst_ratio", "sni_block_count",
                                                  "nxdomain_count", "dga_nxdomain_count",
                                                  "dns_threat_count")}})
    for a in sorted(s.ai, key=lambda a: -a["hits"])[:MAX_ITEMS]:
        sections["ai_usage"].append({
            "service": text(a["service"]), "seen_by": a["source"], "lookups_24h": a["hits"],
            "night_lookups": a["night_hits"], "active_now": a["active"],
            "first_seen": _when(a["first_seen"]), "last_seen": _when(a["last_seen"])})
    for t in sorted(s.tls, key=lambda t: t["ts"])[-MAX_ITEMS:]:
        sections["tls_fingerprints"].append({
            "kind": "on the fingerprint blocklist" if t["type"] == "blocklist"
                    else "never seen on this network before",
            "when": _when(t["ts"]), "server_name": text(t.get("sni") or ""),
            "ja4": text(t.get("ja4") or ""), "label": text(t.get("label") or ""),
            "action": text(t.get("action") or "")})
    if s.dns_queries or s.dns_nxdomain:
        sections["dns_summary"].append({
            "lookups": s.dns_queries, "nxdomain": s.dns_nxdomain,
            "top_names": [[text(n), c] for n, c in s.domains.most_common(MAX_DOMAINS)]})
    for name, (count, first, last) in sorted(s.sni.items(), key=lambda kv: (-kv[1][0], kv[0]))[:MAX_ITEMS]:
        sections["sni_blocks"].append({
            "server_name": text(name), "dropped": int(count),
            "first": _when(first), "last": _when(last), "by": "kernel eBPF/XDP filter"})
    for u in sorted(s.upload, key=lambda u: -u["bytes_out"])[:MAX_ITEMS]:
        sections["ai_upload"].append({
            "service": text(u["service"]), "bytes_out": u["bytes_out"],
            "bytes_in": u["bytes_in"], "flows": u["flows"],
            "first": _when(u["first"]), "last": _when(u["last"]),
            "note": UPLOAD_NOTE})
    for name, items in sections.items():
        for n, item in enumerate(items, 1):
            item["id"] = f"{ID_PREFIX[name]}-{n}"
    bundle = {
        "device": {"label": SUBJECT, "kind": text(s.category) or "unknown"},
        "now": _when(now),
        "window_hours": WINDOW_SECONDS // 3600,
        "sections": sections,
    }
    shown = s.name or s.mac or s.ip
    return bundle, {SUBJECT: f"{shown} ({s.ip})" if shown != s.ip else s.ip}


def _name(s: Signals, labels: dict[str, str] | None) -> str:
    if s.name or not labels:
        return s.name
    return labels.get(s.ip) or labels.get(s.mac.lower()) or ""


def evidence_ids(bundle: dict[str, Any]) -> set[str]:
    return {item["id"] for items in bundle.get("sections", {}).values() for item in items}


# --- helpers ----------------------------------------------------------------------------

#: A MAC address (either separator), not glued to more hex.
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
#: An IPv4 quad with word boundaries (dots allowed either side, for
#: addresses glued into DNS names); validated with ipaddress below.
_V4_RE = re.compile(r"(?<![\w])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![\w])")
#: A maximal run of what an IP address is written with (review F4).
_TOKEN_RE = re.compile(r"[0-9A-Fa-f:.]+")
_UNPRINTABLE_RE = re.compile(r"[^\x20-\x7e]")
#: Unicode bidi controls (review2 C19): invisible characters that reorder
#: displayed text. Stripped from every sensor- or model-made string that
#: reaches the model or the admin's screen.
_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")


def strip_bidi_controls(text: str) -> str:
    """Remove the Unicode bidi controls (review2 C19) -- U+202A..U+202E,
    U+2066..U+2069, U+200E/U+200F -- which reorder displayed text and so
    let an untrusted name spoof what the admin reads."""
    return _BIDI_RE.sub("", text)


def _scrub(value: Any, secrets: set[str]) -> str:
    """Untrusted sensor text, made safe to show a model: printable ASCII,
    short, with no bidi controls (review2 C19), no address and none of the
    device's own identifiers. A secret of any length is scrubbed
    case-insensitively at token/domain boundaries -- ``nas`` in
    ``nas.home``, but not inside ``canasta`` -- and addresses are parsed,
    not pattern-matched (review F4)."""
    # Review2 C19: bidi controls are stripped outright (not just "?"-ed
    # with the other unprintables), so a crafted name cannot reorder what
    # the model or the admin reads.
    text = _UNPRINTABLE_RE.sub("?", strip_bidi_controls(str(value)))[:MAX_TEXT * 2]
    for secret in sorted(secrets, key=len, reverse=True):
        if not secret:
            continue
        text = re.sub(r"(?<![A-Za-z0-9])" + re.escape(secret) + r"(?![A-Za-z0-9])",
                      SUBJECT, text, flags=re.IGNORECASE)
    return _scrub_addresses(text)[:MAX_TEXT]


def _scrub_addresses(text: str) -> str:
    """Every address in the text becomes ``[address]``: MACs by shape, then
    IPv4/IPv6 by parsing each token with ``ipaddress`` -- so ``::1``,
    ``::abcd`` and embedded IPv4 (``::ffff:192.0.2.1``) are all caught --
    then any IPv4 quad left inside a longer dotted run, validated."""
    text = _MAC_RE.sub("[address]", text)
    text = _TOKEN_RE.sub(_scrub_token, text)
    return _V4_RE.sub(lambda m: "[address]" if _valid_ip(m.group(1)) else m.group(0), text)


def _scrub_token(match: re.Match[str]) -> str:
    """One maximal address-alphabet run: an address with dots glued to it
    (``x.192.168.0.1.nip.io``) is trimmed to the address part first."""
    token = match.group(0)
    stripped = token.strip(".")
    if stripped and _valid_ip(stripped):
        return token.replace(stripped, "[address]", 1)
    return token


def _valid_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _number(value: Any, now: float) -> float | None:
    """A sensor time (or score) in a sane range (review F10): finite, and
    ``0 <= t <= now + 1 day``. NaN, infinities (``1e309`` arrives as one),
    a huge int (``10**400``, whose ``float()`` raises ``OverflowError``),
    negatives and the far future are not values the sensors could have
    written, so they are not values at all."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(number) or not 0 <= number <= now + 24 * 3600:
        return None
    return number


def _count(value: Any) -> int | None:
    """A sensor count in a sane range (review F10): ``0 <= n < 2**63`` --
    the bound the upload collector saturates its totals at (review2 C6),
    so a row it writes is a row this accepts."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not 0 <= value < 2**63:
        return None
    return value


def _mac_key(value: str) -> str:
    """A MAC for comparison: hex digits only, lowercase."""
    return re.sub(r"[^0-9a-f]", "", value.lower())


def _when(ts: float | None) -> str | None:
    """Router-local weekday and time: enough to tell night from day."""
    return None if ts is None else time.strftime("%a %H:%M", time.localtime(ts))

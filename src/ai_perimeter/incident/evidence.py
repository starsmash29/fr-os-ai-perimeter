"""A4: the evidence an incident explanation is built from.

FR_OS's parser daemons already write what they saw, display-only, for the
webUI (``frfw.paths.SENSOR_STATE_DIR`` and the resolver's query log): the AI
IDS's flagged events, App-ID's per-client usage, the TLS fingerprint
inventory, the device inventory. This module reads those files with FR_OS's
own loaders, in the webUI process that may already read them, and turns one
device's share into an **evidence bundle** for ``fr-ai-assist``.

Why it is built here and not by the model (FR_OS security-lessons A1, G11):

- **The model gets no file, socket or network.** It only ever sees the
  bundle, and asks for slices of it (:mod:`.explain`).
- **Pseudonymised.** The device is ``device-1``; its IP, MAC and DHCP name
  never leave the webUI. Every string taken from a sensor (a domain name, a
  TLS server name, a fingerprint label) is cut short, reduced to printable
  ASCII and scrubbed of anything shaped like an address, so a cloud model
  gets the household's *pattern* of traffic, not its identities.
- **Every item has an id** (``ids-1``, ``ai-2``, ``tls-1``, ``dns-1``,
  ``up-1``). An explanation may only cite ids that are in the bundle.
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
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from frfw import paths as fr_paths
from frfw.adblock.dns_service import dnsmasq_message
from frfw.ai_ids.daemon import load_recent_events
from frfw.appid import AppMatcher, AppSignature, Catalog, load_catalog
from frfw.appid.daemon import load_usage
from frfw.iot.scanner import load_inventory
from frfw.tlsfp.daemon import load_state as load_tls_state

#: How far back the bundle looks.
WINDOW_SECONDS = 24 * 3600
#: Night, in the router's local time: use then stands out (a child's
#: tablet, an unattended office PC).
NIGHT_HOURS = frozenset({22, 23, 0, 1, 2, 3, 4, 5})
#: Only the end of the query log is read: it is trimmed by FR_OS anyway,
#: and the webUI must not stall on a large file.
DNS_TAIL_BYTES = 2 * 1024 * 1024
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

SECTIONS = ("ids_events", "ai_usage", "tls_fingerprints", "dns_summary", "ai_upload")
ID_PREFIX = {"ids_events": "ids", "ai_usage": "ai", "tls_fingerprints": "tls",
             "dns_summary": "dns", "ai_upload": "up"}
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
    """FR_OS's ``ai`` apps first, then :data:`AI_SERVICES` they don't cover."""
    fr_os = tuple(a for a in load_catalog().apps if a.category == "ai")
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
    upload: list[dict[str, Any]] = field(default_factory=list)

    def reasons(self) -> list[str]:
        out = []
        if self.ids:
            out.append("anomaly")
        if self.ai:
            out.append("ai_service")
        if any(t["type"] == "blocklist" for t in self.tls):
            out.append("tls_blocklist")
        if sum(u["bytes_out"] for u in self.upload) > UPLOAD_ALERT_BYTES:
            out.append("ai_upload")
        return out

    def last_seen(self) -> float:
        times = [e["ts"] for e in self.ids + self.tls] + [a["last_seen"] for a in self.ai] \
            + [u["last"] for u in self.upload]
        return max(times, default=0.0)


# --- reading FR_OS's files ----------------------------------------------------------------

_DNS_QUERY_RE = re.compile(
    r"\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ query\[[A-Za-z0-9]+\] (?P<name>\S+) from \S+\Z")
_DNS_NXDOMAIN_RE = re.compile(r"\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ (?:reply|cached) \S+ is NXDOMAIN\Z")
_DNS_REPLY_RE = re.compile(
    r"\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ reply (?P<name>\S+) is (?P<addr>\S+)\Z")


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

    def upload_client(device: Any) -> Signals | None:
        """The client an upload row belongs to: its IP, or the client
        already known by its MAC. A MAC no sensor reported stays
        unattributed: uploads join a device the evidence can identify."""
        ip = _ip(device)
        if ip is not None:
            return clients.setdefault(ip, Signals(ip=ip))
        if not isinstance(device, str):
            return None
        want = _mac_key(device)
        if not want:
            return None
        for s in clients.values():
            if s.mac and _mac_key(s.mac) == want:
                return s
        return None

    for event in load_recent_events(sources.ids):
        ts = _number(event.get("ts"))
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
            last = _number(row.get("last_seen")) if isinstance(row, dict) else None
            if s is None or last is None or last < since:
                continue
            s.ai.append(_usage_row(app_id, names[app_id], row, now))

    tls = load_tls_state(sources.tls)
    for event in tls.get("events", []) if isinstance(tls.get("events"), list) else []:
        ts = _number(event.get("ts")) if isinstance(event, dict) else None
        if ts is None or ts < since or event.get("type") not in ("new_fingerprint", "blocklist"):
            continue
        s = client(event.get("client"))
        if s is not None:
            s.tls.append({**event, "ts": ts})

    matcher = AppMatcher(catalog)
    replies: dict[str, dict[str, str]] = {}
    _read_dns(sources.dns, client, matcher, names, now, replies)
    ai_ids = {a.id for a in catalog.apps if a.category == "ai"}
    _read_upload(sources.upload, upload_client, replies, matcher, ai_ids, names, since)

    inventory = load_inventory(sources.devices) or {}
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
            "hits": int(_number(row.get("hits_24h")) or 0), "night_hits": night,
            "first_seen": _number(row.get("first_seen")) or now,
            "last_seen": _number(row.get("last_seen")) or now,
            "active": row.get("active") is True}


def _read_dns(path: Path, client, matcher: AppMatcher, names: dict[str, str], now: float,
            replies: dict[str, dict[str, str]]) -> None:
    """Query and NXDOMAIN counts per client, the names it looked up, AI
    services the App-ID snapshot didn't already report, and -- per client
    -- the addresses its replies mapped names to (first reply wins), for
    the upload attribution below."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - DNS_TAIL_BYTES))
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return
    lookups: dict[tuple[str, str], int] = collections.Counter()
    for line in text.splitlines()[1 if size > DNS_TAIL_BYTES else 0:]:
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
                lookups[(s.ip, app)] += 1
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
            addr = _ip(reply.group("addr"))
            if s is not None and addr is not None:
                name = reply.group("name").lower().rstrip(".")
                replies.setdefault(s.ip, {}).setdefault(addr, name)
    for (ip, app), hits in lookups.items():
        s = client(ip)
        if any(a["app"] == app for a in s.ai):
            continue
        s.ai.append({"app": app, "service": names[app], "source": "dns", "hits": hits,
                     "night_hits": None, "first_seen": None, "last_seen": now, "active": None})


def _read_upload(path: Path, upload_client, replies: dict[str, dict[str, str]],
                 matcher: AppMatcher, ai_ids: set[str], names: dict[str, str],
                 since: float) -> None:
    """Per-service upload bytes per client, from fr-ai-upload's totals. A
    row counts only when the client's own replies map its destination to a
    name App-ID puts in the "ai" category; anything else -- another
    client's reply, a non-AI name, a misshapen row -- is skipped. A missing
    or broken file means no upload signal, never an error."""
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    rows = doc.get("devices") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        return
    acc: dict[tuple[str, str], tuple[Signals, dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        s = upload_client(row.get("device"))
        if s is None:
            continue
        dst = _ip(row.get("dst"))
        if dst is None:
            continue
        name = replies.get(s.ip, {}).get(dst)
        if name is None:
            continue
        app = matcher.match(name)
        if app is None or app not in ai_ids:
            continue
        out = _count(row.get("bytes_out"))
        inn = _count(row.get("bytes_in"))
        flows = _count(row.get("flows"))
        last = _number(row.get("last"))
        if out is None or inn is None or flows is None or last is None or last < since:
            continue
        first = _number(row.get("first")) or last
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
    secrets = {v for v in (s.ip, s.mac, s.name) if len(v) >= 4}

    def text(value: Any) -> str:
        return _scrub(value, secrets)

    sections: dict[str, list[dict[str, Any]]] = {name: [] for name in SECTIONS}
    for e in sorted(s.ids, key=lambda e: e["ts"])[-MAX_ITEMS:]:
        sections["ids_events"].append({
            "when": _when(e["ts"]), "score": _number(e.get("score")),
            "reasons": [text(r) for r in e.get("reasons", [])[:6] if isinstance(r, str)],
            **{k: _number(e.get(k)) for k in ("conn_rate", "unique_dst_ratio", "sni_block_count",
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

_ADDRESS_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"                       # IPv4
    r"|\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b"            # MAC
    r"|\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b",        # IPv6
    re.IGNORECASE)
_UNPRINTABLE_RE = re.compile(r"[^\x20-\x7e]")


def _scrub(value: Any, secrets: set[str]) -> str:
    """Untrusted sensor text, made safe to show a model: printable ASCII,
    short, with no address and none of the device's own identifiers."""
    text = _UNPRINTABLE_RE.sub("?", str(value))[:MAX_TEXT * 2]
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, SUBJECT)
    return _ADDRESS_RE.sub("[address]", text)[:MAX_TEXT]


def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _mac_key(value: str) -> str:
    """A MAC for comparison: hex digits only, lowercase."""
    return re.sub(r"[^0-9a-f]", "", value.lower())


def _when(ts: float | None) -> str | None:
    """Router-local weekday and time: enough to tell night from day."""
    return None if ts is None else time.strftime("%a %H:%M", time.localtime(ts))

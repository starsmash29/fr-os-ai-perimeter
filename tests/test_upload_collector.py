"""``fr-ai-upload``: per-device upload bytes from ``conntrack_sample``.

A real Unix socket server answers ``conntrack_sample`` the way FR_OS's
helper does (one JSON line in, one JSON line out); the collector samples
it, and the totals file is read back. Flows appear, grow and disappear;
the 24 h window ages out; the bounds hold; a broken answer never crashes
the loop.
"""

from __future__ import annotations

import json
import socketserver
import stat
import threading
from pathlib import Path

import pytest

from ai_perimeter.upload.collector import (
    MAX_PAIRS,
    WINDOW_SECONDS,
    Collector,
    main,
)

LAN, WAN, DNS = "192.168.10.21", "93.184.216.34", "8.8.8.8"


def flow(src=LAN, dst=WAN, sport=50000, dport=443, out=0, inn=0,
         proto="tcp", **extra):
    return {"proto": proto, "src": src, "sport": sport, "dst": dst,
            "dport": dport, "bytes_out": out, "bytes_in": inn, **extra}


class HelperHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(65536)
        request = json.loads(line)
        self.server.requests.append(request)
        answer = self.server.next_answer()
        if answer is None:  # close without a reply, like a dying helper
            return
        if isinstance(answer, bytes):
            self.wfile.write(answer)
        else:
            self.wfile.write(json.dumps(answer).encode() + b"\n")


class Helper(socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, script: list):
        self.script, self.requests = list(script), []
        path.unlink(missing_ok=True)
        super().__init__(str(path), HelperHandler)

    def next_answer(self):
        if len(self.script) > 1:
            return self.script.pop(0)
        return self.script[0]


def start(path: Path, script: list) -> Helper:
    server = Helper(path, script)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run(tmp_path: Path, script: list, clock) -> tuple[Collector, Helper]:
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=clock)
    for _i in range(len(script)):
        collector.sample()
    return collector, server


def read(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "upload.json").read_text())


def by_pair(doc: dict) -> dict:
    return {(d["device"], d["dst"]): d for d in doc["devices"]}


def test_flows_appear_grow_and_disappear_and_totals_add_up_once(tmp_path):
    now = [1000.0]
    script = [
        {"ok": True, "flows": [flow(out=1000, inn=100),
                               flow(dst=DNS, sport=50001, dport=53, proto="udp", out=50, inn=50)]},
        {"ok": True, "flows": [flow(out=3000, inn=300),
                               flow(sport=50002, out=10, inn=0)]},
        {"ok": True, "flows": [flow(sport=50002, out=110, inn=20)]},
        {"ok": True, "flows": []},
    ]
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=lambda: now[0])
    for tick in (1000.0, 1015.0, 1030.0, 1045.0):
        now[0] = tick
        collector.sample()
    assert [r.get("cmd") for r in server.requests] == ["conntrack_sample"] * 4
    doc = read(tmp_path)
    assert doc["generated"] == 1045 and doc["window_seconds"] == WINDOW_SECONDS
    pairs = by_pair(doc)
    assert pairs[(LAN, WAN)] == {"device": LAN, "dst": WAN, "bytes_out": 2110,
                                 "bytes_in": 220, "flows": 2,
                                 "first": 1015, "last": 1030}
    assert (LAN, DNS) not in pairs, "a baseline flow that never grew adds nothing"
    server.shutdown()
    server.server_close()


def test_short_flows_between_samples_are_not_seen(tmp_path):
    now = [2000.0]
    script = [
        {"ok": True, "flows": [flow(out=999999, inn=999999)]},
        {"ok": True, "flows": []},
    ]
    collector, server = run(tmp_path, script, lambda: now[0])
    assert read(tmp_path)["devices"] == []
    server.shutdown()
    server.server_close()


def test_only_lan_sources_count(tmp_path):
    now = [3000.0]
    lan = flow(out=10, inn=0)
    wan = flow(src=WAN, dst=LAN, sport=443, dport=50000, out=10, inn=0)
    mac = flow(src="2001:db8::5", dst=WAN, out=10, inn=0,
               src_mac="02:00:00:00:10:01")
    global6 = flow(src="2001:db8::6", dst=WAN, out=10, inn=0)
    ula = flow(src="fd00::7", dst=WAN, out=10, inn=0)
    broken = flow(src="not-an-ip", dst=WAN, out=10, inn=0)
    grown = [dict(f, bytes_out=20) for f in (lan, wan, mac, global6, ula, broken)]
    script = [{"ok": True, "flows": [lan, wan, mac, global6, ula, broken]},
              {"ok": True, "flows": grown}]
    collector, server = run(tmp_path, script, lambda: now[0])
    pairs = by_pair(read(tmp_path))
    # Review F5: rows key by source IP, always -- the MAC-labelled IPv6
    # source keeps its address, with the MAC alongside.
    assert set(pairs) == {(LAN, WAN), ("2001:db8::5", WAN), ("fd00::7", WAN)}
    assert pairs[(LAN, WAN)]["bytes_out"] == 10
    assert pairs[("2001:db8::5", WAN)]["mac"] == "02:00:00:00:10:01"
    assert "mac" not in pairs[(LAN, WAN)]
    server.shutdown()
    server.server_close()


def test_the_window_ages_out(tmp_path):
    now = [4000.0]
    script = [{"ok": True, "flows": [flow(out=10, inn=0)]},
              {"ok": True, "flows": [flow(out=20, inn=5)]}]
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=lambda: now[0])
    collector.sample()
    collector.sample()
    assert by_pair(read(tmp_path))[(LAN, WAN)]["bytes_out"] == 10
    now[0] += WINDOW_SECONDS - 1
    collector.sample()  # the flow is long gone, but its totals are 24 h young
    assert (LAN, WAN) in by_pair(read(tmp_path))
    now[0] += 2
    collector.sample()
    assert read(tmp_path)["devices"] == []
    server.shutdown()
    server.server_close()


def test_at_most_4096_pairs_and_the_oldest_goes_first(tmp_path):
    now = [5000.0]
    base = [flow(dst=f"10.99.{n // 250}.{n % 250 + 1}",
                 sport=10000 + n, out=100, inn=0) for n in range(5000)]
    grown = [dict(f, bytes_out=101) for f in base]
    script = [{"ok": True, "flows": base}, {"ok": True, "flows": grown}]
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=lambda: now[0])
    collector.sample()
    assert collector.pairs == {}
    collector.sample()
    pairs = by_pair(read(tmp_path))
    assert len(pairs) == MAX_PAIRS == 4096
    first = (base[0]["src"], base[0]["dst"])
    last = (base[-1]["src"], base[-1]["dst"])
    assert first not in pairs and last in pairs
    now[0] += 15
    collector.sample()  # nothing new: the bound holds on every write
    assert len(read(tmp_path)["devices"]) == 4096
    server.shutdown()
    server.server_close()


def test_a_broken_answer_does_not_crash_the_loop(tmp_path, caplog):
    now = [6000.0]
    script = [
        {"ok": False, "message": "nope"},
        {"ok": True},
        {"ok": True, "flows": "nope"},
        b"not json\n",
        None,
        {"ok": True, "flows": [None, 42, {"proto": "tcp"},
                               flow(out="much"),
                               flow(out=-1),
                               flow(sport=True),
                               "junk"]},
        {"ok": True, "flows": [flow(out=10, inn=0)]},
        {"ok": True, "flows": [flow(out=30, inn=4)]},
    ]
    collector, server = run(tmp_path, script, lambda: now[0])
    pairs = by_pair(read(tmp_path))
    assert pairs[(LAN, WAN)]["bytes_out"] == 30
    assert pairs[(LAN, WAN)]["bytes_in"] == 4
    assert len(caplog.records) == 5, "each broken answer is logged and skipped"
    server.shutdown()
    server.server_close()


def test_a_new_flow_for_a_known_pair_counts_as_a_flow(tmp_path):
    now = [7000.0]
    script = [
        {"ok": True, "flows": [flow(out=10, inn=0)]},
        {"ok": True, "flows": [flow(out=20, inn=0),
                               flow(sport=50009, out=5, inn=0)]},
        {"ok": True, "flows": [flow(out=30, inn=0),
                               flow(sport=50009, out=15, inn=0)]},
    ]
    collector, server = run(tmp_path, script, lambda: now[0])
    assert by_pair(read(tmp_path))[(LAN, WAN)]["flows"] == 2
    server.shutdown()
    server.server_close()


def test_a_single_sample_flow_after_the_first_is_counted_in_full(tmp_path):
    now = [9000.0]
    script = [
        {"ok": True, "flows": []},
        {"ok": True, "flows": [flow(out=12345, inn=678)]},
        {"ok": True, "flows": []},
    ]
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=lambda: now[0])
    for tick in (9000.0, 9015.0, 9030.0):
        now[0] = tick
        collector.sample()
    pairs = by_pair(read(tmp_path))
    assert pairs[(LAN, WAN)] == {"device": LAN, "dst": WAN, "bytes_out": 12345,
                                 "bytes_in": 678, "flows": 1,
                                 "first": 9015, "last": 9015}
    server.shutdown()
    server.server_close()


def test_first_sample_flows_are_baseline_not_counted(tmp_path):
    now = [9500.0]
    script = [
        {"ok": True, "flows": [flow(out=5000, inn=1000),
                               flow(dst=DNS, sport=50001, out=7000, inn=0)]},
        {"ok": True, "flows": [flow(out=6000, inn=1200)]},
    ]
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=lambda: now[0])
    for tick in (9500.0, 9515.0):
        now[0] = tick
        collector.sample()
    pairs = by_pair(read(tmp_path))
    assert pairs[(LAN, WAN)]["bytes_out"] == 1000, "only the delta, not the 5000 history"
    assert pairs[(LAN, WAN)]["bytes_in"] == 200
    assert pairs[(LAN, WAN)]["flows"] == 1
    assert (LAN, DNS) not in pairs, "a baseline flow that never grew adds nothing"
    server.shutdown()
    server.server_close()


def test_a_pair_active_for_30h_reports_only_the_last_24h(tmp_path):
    t0 = 360000.0
    now = [t0]
    script = [{"ok": True, "flows": []}]
    script += [{"ok": True, "flows": [flow(sport=50000 + h, out=1000, inn=100)]}
               for h in range(1, 31)]
    server = start(tmp_path / "helper.sock", script)
    collector = Collector(socket_path=tmp_path / "helper.sock",
                          output=tmp_path / "upload.json", clock=lambda: now[0])
    for h in range(31):
        now[0] = t0 + h * 3600
        collector.sample()
    pairs = by_pair(read(tmp_path))
    row = pairs[(LAN, WAN)]
    assert row["bytes_out"] == 25 * 1000, "hours 6..30 kept, hours 1..5 aged out"
    assert row["bytes_in"] == 25 * 100
    assert row["flows"] == 25
    assert row["first"] == int(t0 + 6 * 3600)
    assert row["last"] == int(t0 + 30 * 3600)
    server.shutdown()
    server.server_close()


def test_the_output_leaves_no_temp_file_mode_0640_and_shaped(tmp_path):
    now = [8000.0]
    script = [{"ok": True, "flows": [flow(out=10, inn=0)]},
              {"ok": True, "flows": [flow(out=25, inn=7)]}]
    collector, server = run(tmp_path, script, lambda: now[0])
    out = tmp_path / "upload.json"
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    assert list(tmp_path.glob("*.tmp")) == []
    doc = json.loads(out.read_text())
    assert set(doc) == {"generated", "window_seconds", "devices"}
    assert doc["window_seconds"] == WINDOW_SECONDS
    [row] = doc["devices"]
    assert set(row) == {"device", "dst", "bytes_out", "bytes_in", "flows",
                        "first", "last"}
    assert (row["bytes_out"], row["bytes_in"]) == (15, 7)
    server.shutdown()
    server.server_close()


def test_main_takes_one_sample_with_once(tmp_path):
    server = start(tmp_path / "helper.sock", [{"ok": True, "flows": []}])
    out = tmp_path / "upload.json"
    assert main(["--socket", str(tmp_path / "helper.sock"), "--output", str(out),
                 "--once"]) == 0
    assert json.loads(out.read_text())["devices"] == []
    server.shutdown()
    server.server_close()


def direct(tmp_path: Path) -> Collector:
    """A collector driven by update()/write() directly: no socket, so the
    review tests below run anywhere."""
    return Collector(socket_path=tmp_path / "helper.sock",
                     output=tmp_path / "upload.json", clock=lambda: 0.0)


def test_upload_totals_are_readable_by_webui_not_other_users(tmp_path):
    """Review F1, as a unit/mode-level test (no real users in CI): the
    totals file is 0640, and the unit runs it group-readable under FR_OS's
    shared feeds group, whose members are the webUI and the sensor."""
    from test_systemd_units import one, section
    collector = direct(tmp_path)
    collector.update([], 10000.0)
    collector.update([flow(out=100, inn=10)], 10015.0)
    collector.write(10015.0)
    out = tmp_path / "upload.json"
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    unit = section("fr-ai-upload.service", "[Service]")
    assert one(unit, "Group") == "fr_os-feeds"
    assert one(unit, "User") == "fr_os-sensor"


def test_ipv6_flow_row_keeps_source_ip_and_mac(tmp_path):
    """Review F5: a MAC-labelled IPv6 source is keyed by its IP, with the
    MAC as a separate field -- the address is not lost."""
    collector = direct(tmp_path)
    collector.update([], 10000.0)
    collector.update([flow(src="2001:db8::5", dst=WAN, out=100, inn=10,
                           src_mac="02:00:00:00:10:01")], 10015.0)
    collector.write(10015.0)
    [row] = read(tmp_path)["devices"]
    assert row["device"] == "2001:db8::5"
    assert row["mac"] == "02:00:00:00:10:01"
    assert (row["bytes_out"], row["bytes_in"], row["flows"]) == (100, 10, 1)


def test_partial_boundary_bucket_never_overstates_24h_bytes(tmp_path):
    """Review F8: a bucket whose first sample slid out of the window is
    dropped whole, even though its last sample is still inside -- the 24 h
    total stays "at least", never overstated."""
    collector = direct(tmp_path)
    collector.update([], 360000.0)
    collector.update([flow(out=60_000_000, inn=0)], 360001.0)
    collector.update([flow(out=60_000_001, inn=0)], 363599.0)
    collector.write(446402.0)
    assert read(tmp_path)["devices"] == []


def test_truncated_sample_reappearance_does_not_recount_lifetime_bytes(tmp_path):
    """Review F9: a flow missing from one truncated sample and back at the
    same counters adds nothing: [], [flow 1000], [], [same flow 1000]."""
    collector = direct(tmp_path)
    t0 = 200000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    collector.update([], t0 + 30)
    assert collector.remembered == 1
    collector.update([flow(out=1000, inn=0)], t0 + 45)
    collector.write(t0 + 45)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert row["bytes_out"] == 1000, "the lifetime total was not counted again"
    assert row["flows"] == 1


def test_reappearing_flow_counts_only_growth_over_remembered_value(tmp_path):
    """Review F9: a flow back 50 bytes up adds 50, not its lifetime."""
    collector = direct(tmp_path)
    t0 = 210000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    collector.update([], t0 + 30)
    collector.update([flow(out=1050, inn=0)], t0 + 45)
    collector.write(t0 + 45)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert row["bytes_out"] == 1050
    assert row["flows"] == 1


def test_reappearing_flow_with_reset_counter_adds_nothing(tmp_path):
    """Review F9: a flow back at a smaller counter (a reset) adds 0."""
    collector = direct(tmp_path)
    t0 = 220000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    collector.update([], t0 + 30)
    collector.update([flow(out=900, inn=0)], t0 + 45)
    collector.update([flow(out=950, inn=0)], t0 + 60)
    collector.write(t0 + 60)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert row["bytes_out"] == 1050, "0 for the reset, then 50 of growth"


def test_remembered_flows_stay_bounded(tmp_path):
    """Review F9: at most MAX_GONE vanished flows are remembered."""
    from ai_perimeter.upload.collector import MAX_GONE
    collector = direct(tmp_path)
    t0 = 230000.0
    many = [flow(sport=10000 + n, out=10, inn=0) for n in range(MAX_GONE + 100)]
    collector.update([], t0)
    collector.update(many, t0 + 15)
    collector.update([], t0 + 30)
    assert collector.remembered == MAX_GONE


def test_flow_forgotten_after_an_hour_counts_as_new(tmp_path):
    """Review F9: the memory lasts an hour -- a flow back later is a new
    flow, counted in full."""
    collector = direct(tmp_path)
    t0 = 240000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    collector.update([], t0 + 30)
    collector.update([flow(out=1000, inn=0)], t0 + 30 + 3600 + 1)
    collector.write(t0 + 30 + 3600 + 1)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert (row["bytes_out"], row["flows"]) == (2000, 2)


def test_pairs_stay_bounded_during_update(tmp_path, monkeypatch):
    """Review2 C2: update() itself keeps at most MAX_PAIRS pairs -- the
    bound does not wait for write() -- and the survivors are the newest."""
    import ai_perimeter.upload.collector as collector_mod
    monkeypatch.setattr(collector_mod, "MAX_PAIRS", 4)
    collector = direct(tmp_path)
    t0 = 300000.0
    collector.update([], t0)
    flows = [flow(dst=f"10.9.0.{n + 1}", sport=20000 + n, out=100, inn=0)
             for n in range(8)]
    collector.update(flows, t0 + 15)
    assert len(collector.pairs) <= 4
    collector.write(t0 + 15)
    pairs = by_pair(read(tmp_path))
    assert len(pairs) == 4
    assert {d for (_dev, d) in pairs} == {"10.9.0.5", "10.9.0.6", "10.9.0.7",
                                          "10.9.0.8"}, "write() keeps the newest ones"


def test_two_writes_leave_no_stray_temp_files(tmp_path):
    """Review2 C3: every write replaces its own unique temp file; nothing
    is left beside upload.json, at mode 0640."""
    collector = direct(tmp_path)
    collector.update([], 310000.0)
    collector.update([flow(out=10, inn=0)], 310015.0)
    collector.write(310015.0)
    collector.write(310030.0)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["upload.json"]
    assert stat.S_IMODE((tmp_path / "upload.json").stat().st_mode) == 0o640


def test_a_failed_write_leaves_the_old_file_and_no_strays(tmp_path, monkeypatch):
    """Review2 C3: when the rename raises, the previous upload.json is
    intact and the temp file is unlinked."""
    collector = direct(tmp_path)
    collector.update([], 320000.0)
    collector.update([flow(out=10, inn=0)], 320015.0)
    collector.write(320015.0)
    before = (tmp_path / "upload.json").read_text()

    def boom(*args, **kwargs):
        raise OSError("rename is gone")

    monkeypatch.setattr("ai_perimeter.upload.collector.os.replace", boom)
    with pytest.raises(OSError, match="rename is gone"):
        collector.write(320030.0)
    assert (tmp_path / "upload.json").read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["upload.json"]


@pytest.mark.parametrize("bad", ["0", "-5", "nan", "inf"])
def test_main_rejects_an_out_of_range_interval(tmp_path, bad, capsys):
    """Review2 C4: --interval accepts only 1..3600 seconds; anything else
    exits 2 with a message."""
    with pytest.raises(SystemExit) as exc:
        main(["--socket", str(tmp_path / "helper.sock"),
              "--output", str(tmp_path / "upload.json"),
              "--interval", bad, "--once"])
    assert exc.value.code == 2
    assert "--interval must be 1 to 3600 seconds" in capsys.readouterr().err


def test_main_rejects_a_non_numeric_interval(tmp_path):
    """Review2 C4: a non-number never reaches the check -- argparse exits
    2 on it, as before."""
    with pytest.raises(SystemExit) as exc:
        main(["--socket", str(tmp_path / "helper.sock"),
              "--output", str(tmp_path / "upload.json"),
              "--interval", "abc", "--once"])
    assert exc.value.code == 2


@pytest.mark.parametrize("good", ["1", "3600"])
def test_main_accepts_the_interval_edges(tmp_path, good):
    """Review2 C4: the edges 1 and 3600 are valid (--once against a
    missing socket still exits 0: the sample is skipped, not fatal)."""
    assert main(["--socket", str(tmp_path / "helper.sock"),
                 "--output", str(tmp_path / "upload.json"),
                 "--interval", good, "--once"]) == 0


def test_uncountable_flows_are_skipped_and_counted(tmp_path):
    """Review2 C5: proto outside tcp/udp and ports outside 0..65535 never
    reach the totals; they are skipped, counted, and never raise -- while
    a valid flow alongside still counts."""
    collector = direct(tmp_path)
    t0 = 330000.0
    collector.update([], t0)
    junk = [
        flow(proto="icmp", out=100, inn=0),
        flow(proto="bogus", out=100, inn=0),
        flow(sport=-1, out=100, inn=0),
        flow(dport=70000, out=100, inn=0),
        flow(sport=2**40, dport=2**40, out=100, inn=0),
        None, 42, "junk", {"proto": "tcp"}, flow(out="much"),
    ]
    collector.update(junk + [flow(sport=40000, out=50, inn=0)], t0 + 15)
    assert collector.skipped == 5
    collector.write(t0 + 15)
    pairs = by_pair(read(tmp_path))
    assert set(pairs) == {(LAN, WAN)}
    assert (pairs[(LAN, WAN)]["bytes_out"], pairs[(LAN, WAN)]["flows"]) == (50, 1)


def test_totals_saturate_at_the_shared_cap(tmp_path):
    """Review2 C6: a total that would exceed MAX_COUNT saturates instead of
    writing a row the evidence reader would drop (>= 2**63)."""
    from ai_perimeter.upload.collector import MAX_COUNT
    assert MAX_COUNT == 2**63 - 1
    collector = direct(tmp_path)
    collector.update([], 340000.0)
    collector.update([flow(out=2**63, inn=2**64)], 340015.0)
    collector.write(340015.0)
    [row] = read(tmp_path)["devices"]
    assert row["bytes_out"] == MAX_COUNT
    assert row["bytes_in"] == MAX_COUNT
    assert row["flows"] == 1


def test_flows_saturate_at_the_shared_cap():
    """Review2 C6, flows side: unit-level, since 2**63 flows take a while."""
    from ai_perimeter.upload.collector import MAX_COUNT, _Bucket, _Totals
    now = 340000.0
    totals = _Totals()
    totals.buckets[int(now // 3600)] = _Bucket(bytes_out=0, bytes_in=0,
                                               flows=MAX_COUNT, first=now,
                                               last=now)
    totals.add(now, 0, 0, True)
    assert totals.flows == MAX_COUNT


def test_saturated_rows_survive_the_evidence_count_check():
    """Review2 C6: what the collector writes, evidence._count accepts --
    the two sides share one cap."""
    from ai_perimeter.incident.evidence import _count as evidence_count
    from ai_perimeter.upload.collector import MAX_COUNT
    assert evidence_count(MAX_COUNT) == MAX_COUNT
    assert evidence_count(MAX_COUNT + 1) is None


def test_remembered_growth_on_a_live_pair_adds_no_new_flow(tmp_path):
    """Review2 C7: a remembered (F9) flow reappearing with growth on a live
    pair adds bytes only -- the flow was counted once already."""
    collector = direct(tmp_path)
    t0 = 350000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    collector.update([], t0 + 30)
    collector.update([flow(out=1200, inn=0)], t0 + 45)
    collector.write(t0 + 45)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert (row["bytes_out"], row["flows"]) == (1200, 1)


def test_recreated_pair_after_eviction_counts_its_flow(tmp_path, monkeypatch):
    """Review2 C7: when the pair was evicted while the flow was away, the
    reappearance re-creates it and counts flows=1 -- no row shows bytes
    with 0 flows."""
    import ai_perimeter.upload.collector as collector_mod
    monkeypatch.setattr(collector_mod, "MAX_PAIRS", 2)
    collector = direct(tmp_path)
    t0 = 360000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    collector.update([], t0 + 30)  # the flow is remembered, its pair still live
    others = [flow(dst=f"10.9.1.{n + 1}", sport=30000 + n, out=10, inn=0)
              for n in range(2)]
    collector.update(others, t0 + 45)  # two newer pairs evict (LAN, WAN)
    assert (LAN, WAN) not in collector.pairs
    collector.update([flow(out=1100, inn=0)], t0 + 60)
    collector.write(t0 + 60)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert (row["bytes_out"], row["flows"]) == (100, 1)


def test_growing_flow_recreates_an_evicted_pair_with_its_flow(tmp_path, monkeypatch):
    """Review2 C7, known-flow side: the pair is evicted while the flow
    stays quiet; its next growth re-creates the pair and counts it."""
    import ai_perimeter.upload.collector as collector_mod
    monkeypatch.setattr(collector_mod, "MAX_PAIRS", 2)
    collector = direct(tmp_path)
    t0 = 370000.0
    collector.update([], t0)
    collector.update([flow(out=1000, inn=0)], t0 + 15)
    quiet = [flow(out=1000, inn=0)]
    quiet += [flow(dst=f"10.9.2.{n + 1}", sport=31000 + n, out=10, inn=0)
              for n in range(2)]
    collector.update(quiet, t0 + 30)
    assert (LAN, WAN) not in collector.pairs
    collector.update([flow(out=1050, inn=0)], t0 + 45)
    collector.write(t0 + 45)
    row = by_pair(read(tmp_path))[(LAN, WAN)]
    assert (row["bytes_out"], row["flows"]) == (50, 1)

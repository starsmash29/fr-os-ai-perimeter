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
    assert set(pairs) == {(LAN, WAN), ("02:00:00:00:10:01", WAN), ("fd00::7", WAN)}
    assert pairs[(LAN, WAN)]["bytes_out"] == 10
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


def test_the_output_is_atomic_mode_0640_and_shaped(tmp_path):
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

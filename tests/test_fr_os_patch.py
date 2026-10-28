"""integration/fr_os/conntrack-bytes.patch: the opt-in FR_OS change.

The patch applies cleanly (``git apply --check``) to the pinned FR_OS
files, copied from the installed ``frfw`` package, and the patched
``read_snapshot`` parses real ``nf_conntrack`` lines with and without
``bytes=`` fields. The fixtures are FR_OS's own
``tests/test_conntrack.py`` lines at the pinned commit, with the kernel's
``packets=``/``bytes=`` accounting tokens added where accounting is on.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import frfw

ROOT = Path(__file__).resolve().parent.parent
PATCH = ROOT / "integration" / "fr_os" / "conntrack-bytes.patch"
FILES = ("frfw/conntrack.py", "frfw/helper/server.py")

#: FR_OS's own TCP fixture at the pinned commit (tests/test_conntrack.py).
TCP = ("ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=93.184.216.34 "
       "sport=54321 dport=443 src=93.184.216.34 dst=10.0.0.5 sport=443 dport=54321 "
       "[ASSURED] mark=0 use=1")
#: The same line with accounting on: packets=/bytes= after each dport=.
TCP_ACCT = ("ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=93.184.216.34 "
            "sport=54321 dport=443 packets=120 bytes=240000 src=93.184.216.34 dst=10.0.0.5 "
            "sport=443 dport=54321 packets=200 bytes=1500000 [ASSURED] mark=0 use=1")
#: FR_OS's own UDP fixture at the pinned commit.
UDP = ("ipv4     2 udp      17 29 src=10.0.0.5 dst=8.8.8.8 sport=51000 dport=53 "
       "[UNREPLIED] src=8.8.8.8 dst=10.0.0.5 sport=53 dport=51000 mark=0 use=1")
UDP_ACCT = ("ipv4     2 udp      17 29 src=10.0.0.5 dst=8.8.8.8 sport=51000 dport=53 "
            "packets=3 bytes=180 [UNREPLIED] src=8.8.8.8 dst=10.0.0.5 sport=53 dport=51000 "
            "packets=3 bytes=240 mark=0 use=1")
#: FR_OS's own ICMP fixture at the pinned commit: no ports, never a flow.
ICMP = ("ipv4     2 icmp     1 29 src=10.0.0.5 dst=1.1.1.1 type=8 code=0 id=123 "
        "src=1.1.1.1 dst=10.0.0.5 type=0 code=0 id=123 mark=0 use=1")


def pinned_copy(tmp_path: Path) -> Path:
    """The pinned FR_OS files, copied from the installed package."""
    installed = Path(frfw.__file__).parent
    for name in FILES:
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed / name.split("/", 1)[1], dest)
    return tmp_path


def test_the_patch_applies_cleanly_to_the_pinned_fr_os_files(tmp_path):
    tree = pinned_copy(tmp_path)
    proc = subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=tree,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_the_patch_touches_exactly_two_files():
    touched = sorted(line.split(" b/")[1] for line in PATCH.read_text().splitlines()
                     if line.startswith("diff --git "))
    assert touched == ["frfw/conntrack.py", "frfw/helper/server.py"]


def test_every_hunk_is_marked():
    """AGENTS.md: an unavoidable FR_OS change is a marked patch."""
    hunks = PATCH.read_text().split("\n@@")[1:]
    assert len(hunks) == 4
    for hunk in hunks:
        assert "# AI-Perimeter" in hunk


def load_patched_conntrack(tmp_path):
    """The patched conntrack.py, applied and imported on its own (it needs
    only the standard library)."""
    tree = pinned_copy(tmp_path)
    proc = subprocess.run(["git", "apply", str(PATCH)], cwd=tree,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    name = "patched_conntrack_under_test"
    spec = importlib.util.spec_from_file_location(name, tree / "frfw" / "conntrack.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_patched_snapshot_reads_bytes_with_accounting_on(tmp_path):
    ct = load_patched_conntrack(tmp_path)
    path = tmp_path / "nf_conntrack"
    path.write_text(TCP_ACCT + "\n" + UDP_ACCT + "\n")
    tcp, udp = ct.read_snapshot(path)
    assert (tcp.proto, tcp.src, tcp.sport, tcp.dst, tcp.dport) == (
        "tcp", "10.0.0.5", 54321, "93.184.216.34", 443)
    assert (tcp.bytes_out, tcp.bytes_in) == (240000, 1500000)
    assert (udp.bytes_out, udp.bytes_in) == (180, 240)


def test_patched_snapshot_reports_zero_with_accounting_off(tmp_path):
    ct = load_patched_conntrack(tmp_path)
    path = tmp_path / "nf_conntrack"
    path.write_text(TCP + "\n" + UDP + "\n")
    tcp, udp = ct.read_snapshot(path)
    assert (tcp.bytes_out, tcp.bytes_in) == (0, 0)
    assert (udp.bytes_out, udp.bytes_in) == (0, 0)
    assert ct.ConntrackFlow(proto="tcp", src="a", sport=1, dst="b", dport=2).bytes_out == 0


def test_patched_snapshot_skips_malformed_counts_and_keeps_the_rest(tmp_path):
    ct = load_patched_conntrack(tmp_path)
    bad_out = TCP_ACCT.replace("bytes=240000", "bytes=abc")
    bad_in = UDP_ACCT.replace("bytes=240", "bytes=12x")
    path = tmp_path / "nf_conntrack"
    path.write_text("\n".join([TCP_ACCT, bad_out, UDP_ACCT, bad_in, ICMP, "garbage", ""]))
    flows = ct.read_snapshot(path)
    assert [(f.src, f.bytes_out, f.bytes_in) for f in flows] == [
        ("10.0.0.5", 240000, 1500000), ("10.0.0.5", 180, 240)]


def test_patched_server_answers_bytes_per_flow(tmp_path, monkeypatch):
    """The patched _handle_conntrack_sample carries both counters, with no
    new command: the patched server module is imported and asked."""
    tree = pinned_copy(tmp_path)
    proc = subprocess.run(["git", "apply", str(PATCH)], cwd=tree,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    name = "patched_helper_server_under_test"
    spec = importlib.util.spec_from_file_location(name, tree / "frfw" / "helper" / "server.py")
    assert spec is not None and spec.loader is not None
    server = importlib.util.module_from_spec(spec)
    sys.modules[name] = server
    spec.loader.exec_module(server)

    ct = load_patched_conntrack(tmp_path / "ct")
    flow = ct.ConntrackFlow(proto="tcp", src="10.0.0.5", sport=54321,
                            dst="93.184.216.34", dport=443,
                            bytes_out=240000, bytes_in=1500000)
    monkeypatch.setattr(server.conntrack, "read_snapshot", lambda: [flow])
    reply = server._handle_conntrack_sample(object())
    assert reply == {"ok": True, "flows": [
        {"proto": "tcp", "src": "10.0.0.5", "sport": 54321,
         "dst": "93.184.216.34", "dport": 443,
         "bytes_out": 240000, "bytes_in": 1500000}]}

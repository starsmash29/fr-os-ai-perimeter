"""installer/: the bundle and install.sh.

What can be checked without an FR_OS router is checked here; the install
itself, on a real systemd, is the `install` job in
.github/workflows/tests.yml (install twice, the socket's owner and mode,
who can reach fr-ai-assist, FR_OS's integrity check, uninstall).
"""

from __future__ import annotations

import re
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "installer"
SCRIPTS = [INSTALLER / "install.sh", INSTALLER / "make-bundle.sh",
           ROOT / "tests" / "integration" / "systemd-install.sh"]


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_shellcheck(script):
    if shutil.which("shellcheck") is None:
        pytest.fail("shellcheck is needed (AGENTS.md: shell scripts pass shellcheck)")
    subprocess.run(["shellcheck", str(script)], check=True)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_are_executable_and_strict(script):
    assert os.access(script, os.X_OK)
    assert "\nset -eu\n" in script.read_text()


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    result = subprocess.run([str(INSTALLER / "make-bundle.sh"), str(out)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    tarball = Path(result.stdout.strip().splitlines()[-1])
    unpacked = tmp_path_factory.mktemp("unpacked")
    with tarfile.open(tarball) as tar:
        tar.extractall(unpacked, filter="data")
    return tarball, next(unpacked.iterdir())


def test_the_bundle_holds_the_wheel_units_and_sums(bundle):
    tarball, root = bundle
    files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    wheel = [f for f in files if f.endswith(".whl")]
    assert len(wheel) == 1
    assert files == sorted(["SHA256SUMS", "install.sh", wheel[0], "systemd/fr-ai-assist.service",
                            "systemd/fr-ai-assist.socket", "systemd/fr-ai-upload.service",
                            "systemd/fr-webui.service.d/ai-perimeter.conf",
                            "patches/conntrack-bytes.patch"])
    subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=root, check=True,
                   capture_output=True)
    listed = {line.split("  ", 1)[1] for line in (root / "SHA256SUMS").read_text().splitlines()}
    assert listed == set(files) - {"SHA256SUMS"}
    assert (root / "install.sh").read_bytes() == (INSTALLER / "install.sh").read_bytes()
    assert tarball.with_name(tarball.name + ".sha256").exists()


def test_the_wheel_has_the_templates_and_commands(bundle):
    _tarball, root = bundle
    with zipfile.ZipFile(next(root.glob("*.whl"))) as whl:
        names = whl.namelist()
        entry_points = whl.read(next(n for n in names if n.endswith("entry_points.txt"))).decode()
    assert "ai_perimeter/webui/templates/ai_perimeter.html" in names
    for command in ("fr-ai-assist", "fr-ai-upload", "fr-webui-ai"):
        assert f"{command} = " in entry_points


def test_a_changed_bundle_is_refused(bundle, tmp_path):
    """install.sh checks SHA256SUMS first, before anything else."""
    _tarball, root = bundle
    copy = tmp_path / "bundle"
    shutil.copytree(root, copy)
    unit = copy / "systemd" / "fr-ai-assist.service"
    unit.write_text(unit.read_text().replace("NoNewPrivileges=yes", "NoNewPrivileges=no"))
    sums = subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=copy,
                          capture_output=True, text=True)
    assert sums.returncode != 0
    result = subprocess.run([str(copy / "install.sh")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "does not match SHA256SUMS" in result.stderr


def test_outside_fr_os_nothing_is_installed(bundle):
    """A whole bundle, but no FR_OS (or no root): it stops before changing
    anything."""
    _tarball, root = bundle
    result = subprocess.run([str(root / "install.sh")], capture_output=True, text=True)
    assert result.returncode == 1
    assert "run as root" in result.stderr or "not an FR_OS router" in result.stderr


def test_help_and_unknown_arguments():
    help_ = subprocess.run([str(INSTALLER / "install.sh"), "--help"], capture_output=True, text=True)
    assert help_.returncode == 0 and "--uninstall" in help_.stdout and "--purge" in help_.stdout
    assert "--with-upload-bytes" in help_.stdout
    bad = subprocess.run([str(INSTALLER / "install.sh"), "--yes-please"], capture_output=True, text=True)
    assert bad.returncode == 2


def test_with_upload_bytes_outside_fr_os_nothing_is_installed(bundle):
    """With the flag but no FR_OS (or no root): it stops before changing
    anything, like a plain install."""
    _tarball, root = bundle
    result = subprocess.run([str(root / "install.sh"), "--with-upload-bytes"],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert "run as root" in result.stderr or "not an FR_OS router" in result.stderr


def test_the_bundled_patch_is_the_integration_patch(bundle):
    """The patch install.sh applies is the marked integration patch."""
    _tarball, root = bundle
    bundled = (root / "patches" / "conntrack-bytes.patch").read_bytes()
    assert bundled == (ROOT / "integration" / "fr_os" / "conntrack-bytes.patch").read_bytes()


def _function_body(name: str) -> str:
    """The lines of `name() { ... }` in install.sh."""
    lines = (INSTALLER / "install.sh").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line == f"{name}() {{")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start:end])


def test_install_restarts_the_helper_after_patching_it():
    """Review F2: the install path applies the patch, then restarts the
    running helper (which would otherwise keep the unpatched code), then
    checks one sample for bytes_out."""
    body = _function_body("install_upload_bytes")
    patch_at = body.index("patch -p1")
    restart_at = body.index("try-restart fr-apply-helper.service")
    check_at = body.index("sample_kind")
    assert patch_at < restart_at < check_at


def test_uninstall_restarts_the_helper_after_reverting_the_patch():
    """Review F2: the uninstall path reverts the patch, then restarts the
    running helper, then checks what it reports now."""
    body = _function_body("remove_upload_bytes")
    revert_at = body.index("patch -R")
    restart_at = body.index("try-restart fr-apply-helper.service")
    check_at = body.index("sample_kind")
    assert revert_at < restart_at < check_at


def _upload_fakes(tmp_path, *, conntrack_has_bytes_out, acct_value, probe="empty",
                  server_has_bytes_out=None):
    """A fake router corner for install_upload_bytes/remove_upload_bytes:
    the bundle layout, a fake frfw tree, and fake sysctl/systemctl/patch/
    chown/python on PATH. install.sh is sourced with --help (which only
    prints usage), its paths are repointed at tmp, and one function runs."""
    root = tmp_path / "router"
    fakebin = root / "bin"
    fakebin.mkdir(parents=True)
    (fakebin / "sysctl").write_text(
        "#!/bin/sh\n"
        'echo "$*" >> "$FAKE_SYSCTL_CALLS"\n'
        'case "$1" in\n'
        '  -n) cat "$FAKE_SYSCTL_STATE" ;;\n'
        '  -w) value=${2#*=}; printf "%s" "$value" > "$FAKE_SYSCTL_STATE" ;;\n'
        "esac\n")
    (fakebin / "systemctl").write_text(
        "#!/bin/sh\n"
        'echo "$*" >> "$FAKE_SYSTEMCTL_CALLS"\n'
        "exit 0\n")
    (fakebin / "fake-python").write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *dirname*) printf "%s\\n" "$FAKE_FRFW/frfw" ;;\n'
        '  *conntrack_sample*) printf "%s\\n" "${PROBE_RESULT:-empty}" ;;\n'
        "  *) exit 0 ;;\n"
        "esac\n")
    (fakebin / "patch").write_text(
        "#!/bin/sh\n"
        'echo "$*" >> "$FAKE_PATCH_CALLS"\n'
        'case "$*" in *--dry-run*) [ -z "${FAKE_PATCH_MISFITS:-}" ] || exit 1 ;; esac\n'
        "exit 0\n")
    (fakebin / "chown").write_text("#!/bin/sh\nexit 0\n")
    for script in fakebin.iterdir():
        script.chmod(0o755)
    frfw = root / "frfwroot" / "frfw"
    frfw.mkdir(parents=True)
    (frfw / "conntrack.py").write_text(
        "# fake frfw\nbytes_out = 0\n" if conntrack_has_bytes_out else "# fake frfw\n")
    # The patch touches both files; by default they agree (audit A-01).
    if server_has_bytes_out is None:
        server_has_bytes_out = conntrack_has_bytes_out
    (frfw / "helper").mkdir()
    (frfw / "helper" / "server.py").write_text(
        "# fake frfw\nbytes_out = 0\n" if server_has_bytes_out else "# fake frfw\n")
    (root / "upload-state").mkdir()
    (root / "upload-state" / "upload.json").write_text("{}")
    bundle = root / "bundle"
    (bundle / "systemd").mkdir(parents=True)
    shutil.copyfile(ROOT / "systemd" / "fr-ai-upload.service",
                    bundle / "systemd" / "fr-ai-upload.service")
    (bundle / "patches").mkdir()
    shutil.copyfile(ROOT / "integration" / "fr_os" / "conntrack-bytes.patch",
                    bundle / "patches" / "conntrack-bytes.patch")
    (root / "units").mkdir()
    (root / "state").write_text(acct_value)
    for name in ("sysctl-calls", "systemctl-calls", "patch-calls"):
        (root / name).write_text("")
    env = dict(os.environ, PATH=f"{fakebin}{os.pathsep}{os.environ['PATH']}",
               FAKE_FRFW=str(root / "frfwroot"), PROBE_RESULT=probe,
               FAKE_SYSCTL_STATE=str(root / "state"),
               FAKE_SYSCTL_CALLS=str(root / "sysctl-calls"),
               FAKE_SYSTEMCTL_CALLS=str(root / "systemctl-calls"),
               FAKE_PATCH_CALLS=str(root / "patch-calls"),
               INSTALL_SH=str(INSTALLER / "install.sh"),
               BUNDLE=str(bundle), ROOT_FAKE=str(root))
    return root, env


def _run_upload_fn(root, env, function):
    driver = root / "driver.sh"
    driver.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "set -- --help\n"
        '. "$INSTALL_SH" > /dev/null\n'
        'HERE="$BUNDLE"\n'
        'PATCH="$BUNDLE/patches/conntrack-bytes.patch"\n'
        'UNITS_DIR="$ROOT_FAKE/units"\n'
        'SYSCTL_CONF="$ROOT_FAKE/sysctl.conf"\n'
        'UPLOAD_OWNED="$ROOT_FAKE/owned"\n'
        'UPLOAD_STATE_DIR="$ROOT_FAKE/upload-state"\n'
        'PYTHON="$ROOT_FAKE/bin/fake-python"\n'
        f"{function}\n")
    return subprocess.run(["sh", str(driver)], capture_output=True, text=True, env=env)


def test_default_uninstall_preserves_existing_conntrack_accounting(tmp_path):
    """Review F11: without the opt-in marker, uninstall removes the unit
    but never touches the sysctl -- accounting it did not own stays."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=False, acct_value="1")
    (root / "units" / "fr-ai-upload.service").write_text("unit")
    (root / "sysctl.conf").write_text("conf")
    result = _run_upload_fn(root, env, "remove_upload_bytes")
    assert result.returncode == 0, result.stderr
    assert not (root / "units" / "fr-ai-upload.service").exists()
    assert not (root / "sysctl.conf").exists()
    assert (root / "sysctl-calls").read_text() == "", "sysctl was never called"
    assert (root / "state").read_text() == "1"
    assert (root / "patch-calls").read_text() == "", "nothing to revert"


@pytest.mark.parametrize("before", ["0", "1"])
def test_opt_in_round_trip_restores_conntrack_accounting(tmp_path, before):
    """Review F11: --with-upload-bytes records the prior value (root-only
    0600 marker) before changing it, and uninstall restores exactly that,
    then deletes the marker. A re-install must not overwrite the original."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=True, acct_value=before,
                              probe="bytes")
    install = _run_upload_fn(root, env, "install_upload_bytes")
    assert install.returncode == 0, install.stderr + install.stdout
    assert (root / "state").read_text() == "1"
    assert (root / "owned").read_text() == before + "\n"
    assert os.stat(root / "owned").st_mode & 0o777 == 0o600
    assert "try-restart fr-apply-helper.service" in (root / "systemctl-calls").read_text()
    again = _run_upload_fn(root, env, "install_upload_bytes")
    assert again.returncode == 0, again.stderr
    assert (root / "owned").read_text() == before + "\n", "the original value stays"
    assert (root / "state").read_text() == "1"
    remove = _run_upload_fn(root, env, "remove_upload_bytes")
    assert remove.returncode == 0, remove.stderr
    assert (root / "state").read_text() == before
    assert not (root / "owned").exists(), "the marker is deleted"
    assert not (root / "units" / "fr-ai-upload.service").exists()
    assert not (root / "sysctl.conf").exists()


def test_uninstall_reverts_the_patch_and_restarts_the_helper(tmp_path):
    """Review F2, functionally: a revert is followed by the helper restart,
    and a quiet router (no flows) only warns."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=True, acct_value="1",
                              probe="empty")
    result = _run_upload_fn(root, env, "remove_upload_bytes")
    assert result.returncode == 0, result.stderr
    assert "-R" in (root / "patch-calls").read_text()
    assert "try-restart fr-apply-helper.service" in (root / "systemctl-calls").read_text()
    assert (root / "state").read_text() == "1", "no marker, no sysctl call"
    assert (root / "sysctl-calls").read_text() == ""


def test_the_accounting_marker_is_not_in_the_collectors_state_directory():
    """Review F11 follow-up: systemd hands /var/lib/fr_os-ai-perimeter to
    fr_os-sensor, so the value root later feeds to sysctl lives outside it,
    and uninstall restores only 0 or 1 (A1)."""
    text = (INSTALLER / "install.sh").read_text()
    owned = re.search(r"^UPLOAD_OWNED=(\S+)$", text, re.M).group(1)
    assert owned.startswith("/etc/fr_os/")
    assert not owned.startswith("/var/lib/fr_os-ai-perimeter")
    assert "0|1) ;;" in text


def test_uninstall_without_the_patch_file_warns_loudly(tmp_path):
    """Review2 uninstall: --with-upload-bytes was used (FR_OS's conntrack
    carries bytes_out) but the bundle's patch file is gone: uninstall warns
    that FR_OS keeps the patch and how to restore it, instead of skipping
    silently. Uninstall itself still succeeds."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=True, acct_value="1")
    (root / "bundle" / "patches" / "conntrack-bytes.patch").unlink()
    result = _run_upload_fn(root, env, "remove_upload_bytes")
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stdout
    assert "frfw/conntrack.py" in result.stdout
    assert "frfw/helper/server.py" in result.stdout
    assert "reinstall" in result.stdout
    assert (root / "patch-calls").read_text() == "", "no patch file, no revert attempted"


def test_a_half_patched_fr_os_is_refused_not_called_applied(tmp_path):
    """Audit A-01: one of the two patched files carrying bytes_out is a
    broken FR_OS, not "already applied"; nothing is patched on top of it."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=True, acct_value="0",
                              server_has_bytes_out=False, probe="bytes")
    result = _run_upload_fn(root, env, "install_upload_bytes")
    assert result.returncode != 0
    assert "half-patched" in result.stderr
    assert "already applied" not in result.stdout
    assert (root / "patch-calls").read_text() == ""
    assert "--uninstall" in result.stderr, "a failure says how to undo it (F-R2-04)"


def test_a_patch_that_does_not_fit_changes_nothing_in_fr_os(tmp_path):
    """Audit A-01: a dry run comes first, so a tree that is not the pinned
    FR_OS is refused before patch(1) can leave half the hunks applied."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=False, acct_value="0",
                              probe="bytes")
    env["FAKE_PATCH_MISFITS"] = "1"
    result = _run_upload_fn(root, env, "install_upload_bytes")
    assert result.returncode != 0
    assert "nothing was changed in FR_OS" in result.stderr
    calls = (root / "patch-calls").read_text().splitlines()
    assert len(calls) == 1 and "--dry-run" in calls[0], "the real apply never ran"
    assert "--uninstall" in result.stderr, "a failure says how to undo it (F-R2-04)"


def test_uninstall_removes_the_collectors_state(tmp_path):
    """Audit F-R2-05: upload.json holds LAN addresses, MACs and byte totals;
    uninstall removes it, so a reinstall does not read it back."""
    root, env = _upload_fakes(tmp_path, conntrack_has_bytes_out=False, acct_value="1")
    result = _run_upload_fn(root, env, "remove_upload_bytes")
    assert result.returncode == 0, result.stderr
    assert not (root / "upload-state").exists()

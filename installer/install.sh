#!/bin/sh
# Install the FR_OS AI-Perimeter on an FR_OS router, or take it off again.
#
#   sudo ./install.sh                        install, or update in place
#   sudo ./install.sh --with-upload-bytes    also count per-device upload bytes (opt-in FR_OS patch)
#   sudo ./install.sh --uninstall            remove it; keep ai-perimeter.yaml and the key
#   sudo ./install.sh --purge                remove it with ai-perimeter.yaml and the key
#
# Run it from the unpacked bundle (installer/make-bundle.sh): the wheel, the
# systemd units and SHA256SUMS sit next to it. Nothing is downloaded and no
# dependency is installed (FR_OS's own, pinned, are all it uses).
#
# What it changes, and why it is safe for FR_OS (see the repository README):
# - no FR_OS file: the webUI gets the screen from fr-webui-ai, started by a
#   drop-in for FR_OS's unit, so FR_OS's integrity check stays clean (SEC-15);
# - fr-ai-assist runs as a dynamic, unprivileged account in its own sandbox,
#   reachable only by the webUI's account (security-lessons A1, I1);
# - it is off until /etc/fr_os/ai-perimeter.yaml says enabled: true (I1, K7),
#   and the API key file stays root's, mode 0600.
# - with --with-upload-bytes only: conntrack accounting
#   (/etc/sysctl.d/60-ai-perimeter.conf; the value before is recorded in
#   /etc/fr_os/ai-perimeter-upload-owned and restored on uninstall,
#   review F11), the two-file FR_OS patch
#   (integration/fr_os/conntrack-bytes.patch, so FR_OS's integrity check
#   lists those two files on a router that opts in, SEC-15), and the
#   fr-ai-upload collector running as fr_os-sensor. Without the flag none
#   of the three is touched.
set -eu

UNITS_DIR=/etc/systemd/system
DROPIN_DIR=$UNITS_DIR/fr-webui.service.d
DROPIN=$DROPIN_DIR/ai-perimeter.conf
SETTINGS=/etc/fr_os/ai-perimeter.yaml
KEY_DIR=/etc/fr_os/ai-perimeter
KEY_FILE=$KEY_DIR/api_key
DIST=fr-os-ai-perimeter
WEBUI_USER=fr_os-webui
SENSOR_USER=fr_os-sensor
UPLOAD_UNIT=fr-ai-upload.service
SYSCTL_CONF=/etc/sysctl.d/60-ai-perimeter.conf
# Review F11: where --with-upload-bytes records the nf_conntrack_acct value
# it found (root, 0600), so uninstall restores exactly that. Not under
# /var/lib/fr_os-ai-perimeter: systemd hands that StateDirectory to the
# collector's fr_os-sensor account, and a value root later feeds to sysctl
# must not be writable by a sensor account (A1).
UPLOAD_OWNED=/etc/fr_os/ai-perimeter-upload-owned
PYTHON=${PYTHON:-python3}

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
PATCH=$HERE/patches/conntrack-bytes.patch

say() { printf 'ai-perimeter: %s\n' "$*"; }
die() { printf 'ai-perimeter: error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
}

require_fr_os() {
    [ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"
    command -v systemctl >/dev/null 2>&1 || die "systemd is needed"
    systemctl cat fr-webui.service >/dev/null 2>&1 \
        || die "fr-webui.service not found: this is not an FR_OS router"
    getent group "$WEBUI_USER" >/dev/null || die "group $WEBUI_USER not found: this is not an FR_OS router"
    "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
        || die "$PYTHON is older than 3.11"
    "$PYTHON" -c 'import frfw.webui.server' 2>/dev/null \
        || die "FR_OS's webUI (frfw.webui) is not installed for $PYTHON"
}

# The drop-in replaces FR_OS's ExecStart. Install it only over the plain
# `fr-webui` it was written for, so arguments FR_OS may add one day are not
# silently dropped. Our own drop-in is ignored when this is re-run.
check_fr_os_execstart() {
    execstart=$(systemctl cat fr-webui.service \
        | awk '/^# \/.*\.conf$/ { skip = ($2 ~ /ai-perimeter\.conf$/) } !skip' \
        | sed -n 's/^ExecStart=//p' | grep -v '^$' | tail -n 1)
    [ "$execstart" = "fr-webui" ] \
        || die "FR_OS's fr-webui ExecStart is '$execstart', not 'fr-webui': not installing the drop-in"
}

verify_bundle() {
    [ -f "$HERE/SHA256SUMS" ] || die "SHA256SUMS not found next to $0: run it from the unpacked bundle"
    # A check that the bundle arrived whole. Its authenticity is the
    # release page's sum (or a signature) -- see README, "Install".
    (cd "$HERE" && sha256sum --quiet --strict -c SHA256SUMS) || die "the bundle does not match SHA256SUMS"
    set -- "$HERE"/*.whl
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        die "expected exactly one wheel next to $0"
    fi
    WHEEL=$1
    for f in fr-ai-assist.socket fr-ai-assist.service fr-ai-upload.service fr-webui.service.d/ai-perimeter.conf; do
        [ -f "$HERE/systemd/$f" ] || die "systemd/$f is missing from the bundle"
        grep -q " systemd/$f\$" "$HERE/SHA256SUMS" || die "systemd/$f is not in SHA256SUMS"
    done
    [ -f "$HERE/patches/conntrack-bytes.patch" ] \
        || die "patches/conntrack-bytes.patch is missing from the bundle"
    grep -q " patches/conntrack-bytes.patch\$" "$HERE/SHA256SUMS" \
        || die "patches/conntrack-bytes.patch is not in SHA256SUMS"
    grep -q " $(basename "$WHEEL")\$" "$HERE/SHA256SUMS" || die "the wheel is not in SHA256SUMS"
}

# Connect to fr-ai-assist's socket as `user`; prints the answer to ping.
ping_as() {
    # -I: nothing from the working directory or the user's site is imported.
    (cd / && runuser -u "$1" -- "$PYTHON" -I -c \
        'from ai_perimeter.assist_client import ask; print(ask("ping", timeout=20))')
}

install_it() {
    with_upload=$1
    verify_bundle
    require_fr_os
    check_fr_os_execstart

    say "installing $(basename "$WHEEL")"
    "$PYTHON" -m pip install --quiet --break-system-packages --no-deps --no-index \
        --no-cache-dir --force-reinstall "$WHEEL"
    for cmd in fr-ai-assist fr-ai-upload fr-webui-ai; do
        command -v "$cmd" >/dev/null || die "$cmd is not on PATH after installing"
    done

    say "installing the systemd units"
    install -m 0644 "$HERE/systemd/fr-ai-assist.socket" "$UNITS_DIR/fr-ai-assist.socket"
    install -m 0644 "$HERE/systemd/fr-ai-assist.service" "$UNITS_DIR/fr-ai-assist.service"
    install -d -m 0755 "$DROPIN_DIR"
    install -m 0644 "$HERE/systemd/fr-webui.service.d/ai-perimeter.conf" "$DROPIN"

    # Settings: created once, never overwritten (an admin's choices stay).
    install -d -m 0755 /etc/fr_os
    install -d -m 0700 -o root -g root "$KEY_DIR"
    if [ ! -e "$KEY_FILE" ]; then
        # Empty means no key (a local model needs none). The unit's
        # LoadCredential= needs the file to exist.
        install -m 0600 -o root -g root /dev/null "$KEY_FILE"
    fi
    chown root:root "$KEY_FILE"
    chmod 0600 "$KEY_FILE"
    if [ ! -e "$SETTINGS" ]; then
        umask 022
        cat > "$SETTINGS" <<'YAML'
# FR_OS AI-Perimeter settings. Off until enabled: true (see the README).
# The API key is never written here: it goes in /etc/fr_os/ai-perimeter/api_key
# (root, 0600), and only a cloud provider needs one.
enabled: false
# A local model (llama.cpp or Ollama, OpenAI-compatible API) -- nothing leaves
# this network:
# enabled: true
# provider: local
# base_url: http://127.0.0.1:8080/v1
# model: muse-glimmer
YAML
        chmod 0644 "$SETTINGS"
    fi

    say "starting fr-ai-assist.socket and restarting the webUI"
    systemctl daemon-reload
    systemctl enable --now fr-ai-assist.socket
    # A running service keeps the old code; the socket starts the new one.
    systemctl try-restart fr-ai-assist.service
    systemctl restart fr-webui.service

    check_installed
    if [ "$with_upload" = yes ]; then
        install_upload_bytes
    fi
    say "done. Open the webUI: AI-Perimeter is in the sidebar."
    say "to use a model, edit $SETTINGS (enabled: true), then: systemctl restart fr-ai-assist"
}

# Review F2: one conntrack_sample, classified. Prints "bytes" (the flows
# carry bytes_out), "plain" (flows, but no bytes_out) or "empty" (no flows,
# or no answer at all). Never fails.
sample_kind() {
    "$PYTHON" -c '
try:
    from frfw.helper.client import conntrack_sample
    flows = conntrack_sample().get("flows")
except Exception:
    print("empty")
else:
    if not isinstance(flows, list) or not flows:
        print("empty")
    elif any(isinstance(f, dict) and "bytes_out" in f for f in flows):
        print("bytes")
    else:
        print("plain")
' 2>/dev/null || echo "empty"
}

install_upload_bytes() {
    command -v patch >/dev/null 2>&1 || die "patch(1) is needed for --with-upload-bytes"
    frfw_dir=$("$PYTHON" -c 'import frfw, os; print(os.path.dirname(frfw.__file__))' 2>/dev/null) \
        || die "frfw is not installed for $PYTHON"

    say "enabling conntrack accounting"
    # Review F11: record what accounting was before changing it, so
    # uninstall restores exactly that. Written once: a re-install finds
    # accounting already ours and must not overwrite the original value.
    if [ ! -e "$UPLOAD_OWNED" ]; then
        prior=$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null || true)
        if [ -n "$prior" ]; then
            install -d -m 0755 "$(dirname "$UPLOAD_OWNED")"
            printf '%s\n' "$prior" > "$UPLOAD_OWNED"
            chown root:root "$UPLOAD_OWNED"
            chmod 0600 "$UPLOAD_OWNED"
        else
            say "WARNING: could not read nf_conntrack_acct; uninstall will leave it as is"
        fi
    fi
    printf '%s\n' "# FR_OS AI-Perimeter (opt-in --with-upload-bytes): count bytes per flow" \
        "net.netfilter.nf_conntrack_acct = 1" > "$SYSCTL_CONF"
    chmod 0644 "$SYSCTL_CONF"
    sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null \
        || die "could not enable nf_conntrack_acct (sysctl)"

    if grep -q 'bytes_out' "$frfw_dir/conntrack.py" 2>/dev/null; then
        say "the FR_OS conntrack patch is already applied"
    else
        say "applying the conntrack patch to FR_OS (its integrity check will list 2 files)"
        out=$(patch -p1 -d "$frfw_dir/.." < "$PATCH" 2>&1) \
            || die "could not apply the conntrack patch: $out"
        "$PYTHON" -c 'import frfw.conntrack, frfw.helper.server' 2>/dev/null \
            || die "the patched FR_OS does not import"
    fi

    # Review F2: the running helper keeps whatever code it started with,
    # so a patch on disk alone changes nothing until it restarts; then one
    # sample must show the new counters. A quiet router with no flows to
    # check against can only warn, never fail.
    systemctl try-restart fr-apply-helper.service
    case $(sample_kind) in
        bytes) say "the helper reports per-flow byte counters" ;;
        empty) say "WARNING: no conntrack flows to check bytes_out against; the collector counts once flows appear" ;;
        plain) die "the helper answers but reports no bytes_out even after restarting it" ;;
    esac

    say "installing $UPLOAD_UNIT"
    install -m 0644 "$HERE/systemd/$UPLOAD_UNIT" "$UNITS_DIR/$UPLOAD_UNIT"
    systemctl daemon-reload
    systemctl enable --now "$UPLOAD_UNIT"
    systemctl is-active --quiet "$UPLOAD_UNIT" \
        || die "$UPLOAD_UNIT did not start (journalctl -u $UPLOAD_UNIT)"
    say "counting per-device upload bytes (upload.json every 15 s)"
}

remove_upload_bytes() {
    systemctl disable --now "$UPLOAD_UNIT" 2>/dev/null || true
    rm -f "$UNITS_DIR/$UPLOAD_UNIT" "$SYSCTL_CONF"
    # Review F11: accounting goes back to exactly what --with-upload-bytes
    # found, and only when it recorded owning it. A plain install never
    # wrote the marker, so a plain uninstall never touches the sysctl.
    if [ -e "$UPLOAD_OWNED" ]; then
        prior=$(cat "$UPLOAD_OWNED" 2>/dev/null || true)
        rm -f "$UPLOAD_OWNED"
        case "$prior" in
            0|1) ;;
            *)
                say "WARNING: $UPLOAD_OWNED held '$prior'; leaving nf_conntrack_acct as is"
                prior= ;;
        esac
        if [ -n "$prior" ]; then
            sysctl -w "net.netfilter.nf_conntrack_acct=$prior" >/dev/null 2>&1 \
                || say "WARNING: could not restore nf_conntrack_acct to $prior"
        fi
    fi
    frfw_dir=$("$PYTHON" -c 'import frfw, os; print(os.path.dirname(frfw.__file__))' 2>/dev/null) || true
    if [ -n "${frfw_dir:-}" ] && [ -f "$PATCH" ] \
            && grep -q 'bytes_out' "$frfw_dir/conntrack.py" 2>/dev/null; then
        if patch -R -p1 -d "$frfw_dir/.." < "$PATCH" >/dev/null 2>&1; then
            say "reverted the FR_OS conntrack patch"
            # Review F2: the running helper keeps the patched code until
            # it restarts. Warn-only: uninstall never fails.
            systemctl try-restart fr-apply-helper.service 2>/dev/null || true
            if [ "$(sample_kind)" = bytes ]; then
                say "WARNING: the helper still reports bytes_out after the revert"
            fi
        else
            say "WARNING: the FR_OS conntrack patch would not revert; its integrity check still lists it"
        fi
    fi
}

check_installed() {
    sock_stat=$(stat -c '%U:%G %a' /run/fr_os-ai/assist.sock 2>/dev/null) \
        || die "the socket /run/fr_os-ai/assist.sock is missing"
    [ "$sock_stat" = "root:$WEBUI_USER 660" ] || die "the socket is '$sock_stat', expected 'root:$WEBUI_USER 660'"
    ping_as "$WEBUI_USER" >/dev/null 2>&1 \
        || die "the webUI's account can't reach fr-ai-assist (journalctl -u fr-ai-assist)"
    if id "$SENSOR_USER" >/dev/null 2>&1 && ping_as "$SENSOR_USER" >/dev/null 2>&1; then
        die "$SENSOR_USER reached fr-ai-assist: only the webUI may (A1)"
    fi
    systemctl is-active --quiet fr-webui.service || die "fr-webui did not come back (journalctl -u fr-webui)"
    say "checked: only $WEBUI_USER reaches fr-ai-assist; the webUI is running"
}

uninstall_it() {
    purge=$1
    [ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 --uninstall)"
    say "removing the AI-Perimeter"
    systemctl disable --now fr-ai-assist.socket 2>/dev/null || true
    systemctl stop fr-ai-assist.service 2>/dev/null || true
    rm -f "$UNITS_DIR/fr-ai-assist.socket" "$UNITS_DIR/fr-ai-assist.service" "$DROPIN"
    rmdir "$DROPIN_DIR" 2>/dev/null || true
    remove_upload_bytes
    systemctl daemon-reload
    if "$PYTHON" -m pip show --quiet "$DIST" >/dev/null 2>&1; then
        "$PYTHON" -m pip uninstall --quiet --yes --break-system-packages "$DIST"
    fi
    if [ "$purge" = yes ]; then
        rm -f "$SETTINGS" "$KEY_FILE"
        rmdir "$KEY_DIR" 2>/dev/null || true
    else
        say "kept $SETTINGS and $KEY_FILE (--purge removes them)"
    fi
    if systemctl cat fr-webui.service >/dev/null 2>&1; then
        systemctl restart fr-webui.service
    fi
    say "removed; the webUI runs plain FR_OS again"
}

case "${1:-}" in
    "") install_it no ;;
    --with-upload-bytes) install_it yes ;;
    --uninstall) uninstall_it no ;;
    --purge) uninstall_it yes ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac

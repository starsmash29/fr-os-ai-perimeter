#!/bin/sh
# Install the FR_OS AI-Perimeter on an FR_OS router, or take it off again.
#
#   sudo ./install.sh              install, or update in place
#   sudo ./install.sh --uninstall  remove it; keep ai-perimeter.yaml and the key
#   sudo ./install.sh --purge      remove it with ai-perimeter.yaml and the key
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
PYTHON=${PYTHON:-python3}

HERE=$(cd -- "$(dirname -- "$0")" && pwd)

say() { printf 'ai-perimeter: %s\n' "$*"; }
die() { printf 'ai-perimeter: error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
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
    for f in fr-ai-assist.socket fr-ai-assist.service fr-webui.service.d/ai-perimeter.conf; do
        [ -f "$HERE/systemd/$f" ] || die "systemd/$f is missing from the bundle"
        grep -q " systemd/$f\$" "$HERE/SHA256SUMS" || die "systemd/$f is not in SHA256SUMS"
    done
    grep -q " $(basename "$WHEEL")\$" "$HERE/SHA256SUMS" || die "the wheel is not in SHA256SUMS"
}

# Connect to fr-ai-assist's socket as `user`; prints the answer to ping.
ping_as() {
    # -I: nothing from the working directory or the user's site is imported.
    (cd / && runuser -u "$1" -- "$PYTHON" -I -c \
        'from ai_perimeter.assist_client import ask; print(ask("ping", timeout=20))')
}

install_it() {
    verify_bundle
    require_fr_os
    check_fr_os_execstart

    say "installing $(basename "$WHEEL")"
    "$PYTHON" -m pip install --quiet --break-system-packages --no-deps --no-index \
        --no-cache-dir --force-reinstall "$WHEEL"
    for cmd in fr-ai-assist fr-webui-ai; do
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
    say "done. Open the webUI: AI-Perimeter is in the sidebar."
    say "to use a model, edit $SETTINGS (enabled: true), then: systemctl restart fr-ai-assist"
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
    "") install_it ;;
    --uninstall) uninstall_it no ;;
    --purge) uninstall_it yes ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac

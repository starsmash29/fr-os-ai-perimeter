#!/bin/sh
# install.sh on a real systemd, against FR_OS's own fr-webui unit and code
# (the `install` job in .github/workflows/tests.yml; it needs root and a
# throwaway machine).
#
#   sudo tests/integration/systemd-install.sh <bundle.tar.gz> <fr_os-commit>
#
# FR_OS here is its webUI only -- its pinned code and its real
# fr-webui.service, with the accounts and directories that unit needs --
# not a whole router: no firewall is applied to the machine running this.
set -eu

BUNDLE=$1
FR_OS_COMMIT=$2
PYTHON=${PYTHON:-python3}
URL=https://127.0.0.1
JAR=$(mktemp)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$JAR"' EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
status_of() { curl -ks -o /dev/null -w '%{http_code}' "$URL$1"; }

wait_for_webui() {
    i=0
    until [ "$(status_of /login)" = 200 ]; do
        i=$((i + 1))
        [ "$i" -lt 60 ] || { journalctl -u fr-webui --no-pager -n 50; fail "the webUI did not come up"; }
        sleep 1
    done
}

step "FR_OS's webUI at $FR_OS_COMMIT, with its accounts and its unit"
groupadd --system fr_os-webui
useradd --system --gid fr_os-webui --no-create-home --shell /usr/sbin/nologin fr_os-webui
groupadd --system fr_os-sensor
useradd --system --gid fr_os-sensor --no-create-home --shell /usr/sbin/nologin fr_os-sensor
groupadd --system fr_os-feeds
"$PYTHON" -m pip install --quiet --break-system-packages --ignore-installed \
    "frfw[webui] @ git+https://github.com/starsmash29/fr_os-hackathon@$FR_OS_COMMIT"
curl -fsSL -o /etc/systemd/system/fr-webui.service \
    "https://raw.githubusercontent.com/starsmash29/fr_os-hackathon/$FR_OS_COMMIT/systemd/fr-webui.service"
install -d -m 0750 -o fr_os-webui -g fr_os-webui /etc/fr_os/webui
install -m 0644 /dev/null /etc/fr_os/webui_pqc_openssl.cnf
# An admin to log in with (FR_OS's first-boot makes the real one).
runuser -u fr_os-webui -- "$PYTHON" -I -c \
    'from frfw import paths; from frfw.webui.auth import AdminStore
AdminStore(paths.WEBUI_AUTH_PATH).set_password("ci-admin", "ci-admin-pass-01", "admin")'
systemctl daemon-reload
systemctl start fr-webui
wait_for_webui
[ "$(status_of /ai-perimeter)" = 404 ] || fail "plain FR_OS already has /ai-perimeter"

step "FR_OS's integrity check before"
"$PYTHON" -I -c 'from frfw import integrity; r = integrity.check_record(); print(r.summary)' \
    | tee "$WORK/integrity-before"

step "install, twice (the second run is an update in place)"
tar -xzf "$BUNDLE" -C "$WORK"
set -- "$WORK"/fr-os-ai-perimeter-*/install.sh
"$1"
printf 'enabled: false\n# the admin wrote this\n' > /etc/fr_os/ai-perimeter.yaml
"$1"
grep -q 'the admin wrote this' /etc/fr_os/ai-perimeter.yaml || fail "install.sh overwrote ai-perimeter.yaml"
INSTALL=$1

step "files, owners and modes"
[ "$(stat -c '%U:%G %a' /etc/fr_os/ai-perimeter/api_key)" = "root:root 600" ] || fail "api_key is not root 0600"
[ "$(stat -c '%U:%G %a' /etc/fr_os/ai-perimeter)" = "root:root 700" ] || fail "the key directory is not root 0700"
[ "$(stat -c '%U:%G %a' /run/fr_os-ai/assist.sock)" = "root:fr_os-webui 660" ] || fail "the socket's owner or mode"
systemctl show -p ExecStart --value fr-webui | grep -q 'fr-webui-ai' || fail "fr-webui does not run fr-webui-ai"

step "who reaches fr-ai-assist"
ask() {
    (cd / && runuser -u "$1" -- "$PYTHON" -I -c \
        'from ai_perimeter.assist_client import ask; print(ask("status", timeout=20))')
}
ask fr_os-webui || fail "the webUI's account was refused"
if ask fr_os-sensor 2>/dev/null; then fail "fr_os-sensor reached fr-ai-assist"; fi
if ask nobody 2>/dev/null; then fail "nobody reached fr-ai-assist"; fi
pid=$(systemctl show -p MainPID --value fr-ai-assist)
uid=$(stat -c %u "/proc/$pid")
echo "fr-ai-assist runs as uid $uid"
# systemd's DynamicUser= range.
[ "$uid" -ge 61184 ] && [ "$uid" -le 65519 ] || fail "fr-ai-assist is not a dynamic account (uid $uid)"
systemd-analyze security fr-ai-assist.service | tail -n 1

step "the screen in FR_OS's running webUI"
[ "$(status_of /ai-perimeter)" = 303 ] || fail "/ai-perimeter without login is not a redirect to the login"
curl -ks -c "$JAR" -o /dev/null "$URL/login"
curl -ks -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}\n' \
    --data-urlencode username=ci-admin --data-urlencode password=ci-admin-pass-01 "$URL/login"
page=$(curl -ks -b "$JAR" "$URL/ai-perimeter")
echo "$page" | grep -q 'switched off' || { echo "$page" | head -c 3000; fail "the page does not show the service's status"; }
echo "$page" | grep -q 'href="/ai-perimeter"' || fail "no sidebar entry"
echo "the page shows the service's status (off) and the sidebar entry"

step "FR_OS's integrity check after: no FR_OS file changed"
"$PYTHON" -I -c 'from frfw import integrity; r = integrity.check_record(); print(r.summary)' \
    | tee "$WORK/integrity-after"
"$PYTHON" -I -c '
from frfw import integrity
r = integrity.check_record()
assert r.ok, (r.summary, r.changes)'
cmp "$WORK/integrity-before" "$WORK/integrity-after" || fail "the integrity report changed"

step "uninstall keeps the settings; purge removes them"
"$INSTALL" --uninstall
for f in /etc/systemd/system/fr-ai-assist.socket /etc/systemd/system/fr-ai-assist.service \
         /etc/systemd/system/fr-webui.service.d/ai-perimeter.conf /run/fr_os-ai/assist.sock; do
    [ ! -e "$f" ] || fail "$f is still there"
done
command -v fr-webui-ai >/dev/null && fail "fr-webui-ai is still installed"
[ -f /etc/fr_os/ai-perimeter.yaml ] || fail "--uninstall removed ai-perimeter.yaml"
wait_for_webui
[ "$(status_of /ai-perimeter)" = 404 ] || fail "the screen is still served after --uninstall"
"$INSTALL" --purge
[ ! -e /etc/fr_os/ai-perimeter.yaml ] && [ ! -e /etc/fr_os/ai-perimeter ] || fail "--purge left settings"
wait_for_webui

printf '\nPASS\n'

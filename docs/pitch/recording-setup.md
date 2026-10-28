# Recording setup: demo data on the demo router

The video's "What did the router see?" scenes show the
[demo sensor files](../../demo/shadow_ai/README.md), not real traffic. The
webUI reads FR_OS's own sensor files and only the last 24 hours of them, so for
a take the demo files are written there, dated to the recording, with FR_OS's
sensor daemons stopped so they don't overwrite them. Afterwards everything is
put back. No code changes; on screen, the scenes carry a "demo data" caption.

Use a dedicated demo router (or VM) with the demo config, never a router whose
data matters: [tests/data/home.yaml](../../tests/data/home.yaml) for the home
scene, [demo/shadow_ai/office.yaml](../../demo/shadow_ai/office.yaml) for the
office scene. Its LAN must be 192.168.10.0/24, as in those files.

Not yet run on a real router: check each step's output the first time.

## Where the files go

| Demo file | FR_OS path | Written by (stopped for the take) |
|---|---|---|
| `ai_ids_state.json` | `/etc/fr_os/sensors/ai_ids_state.json` | `fr-ai-ids` |
| `appid_usage.json` | `/etc/fr_os/sensors/appid_usage.json` | `fr-appid` |
| `tls_fingerprints.json` | `/etc/fr_os/sensors/tls_fingerprints.json` | `fr-tls-fp` |
| `iot_inventory.json` | `/etc/fr_os/sensors/iot_inventory.json` | `fr-iot-scan` (+ timer) |
| `queries.log` | `/var/log/fr_os-dns/queries.log` | dnsmasq (keeps running), `fr-dns-log-trim` timer |
| `sni_events.jsonl` (office) | `/var/log/fr_os-sni/events.jsonl` | `fr-xdp-sni-logger` |
| `upload.json` (home) | `/var/lib/fr_os-ai-perimeter/upload.json` | `fr-ai-upload` |

dnsmasq keeps running, because the router itself needs DNS to reach the model
endpoint; real lookups from the recording laptop are appended to the demo log
and may show up as an extra, ordinary device.

## When to record

The home scene is a late-night session: the files must end at 23:40 router
time, and that moment must be less than about 20 hours ago, or part of the
session falls out of the 24-hour window. So record the home scene between 23:45
and 19:00 the next day. The office scene can be recorded at any time.

The generator writes the `queries.log` time stamps in UTC; dnsmasq writes
router-local time. On a router at UTC+1 the demo lines therefore read an hour
earlier than written, which keeps them inside the window and does not change
the scene.

## Steps (as root on the demo router, from the repository checkout)

```bash
SCENE=home          # or: office
UNITS="fr-ai-ids fr-appid fr-tls-fp fr-iot-scan.timer fr-iot-scan fr-xdp-sni-logger fr-dns-log-trim.timer fr-ai-upload"
BACKUP=/root/demo-backup

# 1. The moment the files end at.
if [ "$SCENE" = home ]; then
    NOW=$(date -d 'today 23:40' +%s)
    [ "$NOW" -gt "$(date +%s)" ] && NOW=$(date -d 'yesterday 23:40' +%s)
    [ $(( $(date +%s) - NOW )) -lt 72000 ] || { echo "too late for the home scene: record after 23:45"; exit 1; }
else
    NOW=$(date +%s)
fi

# 2. Stop the writers, back up what is there.
systemctl stop $UNITS
mkdir -p "$BACKUP"
for f in /etc/fr_os/sensors/ai_ids_state.json /etc/fr_os/sensors/appid_usage.json \
         /etc/fr_os/sensors/tls_fingerprints.json /etc/fr_os/sensors/iot_inventory.json \
         /var/log/fr_os-dns/queries.log /var/log/fr_os-sni/events.jsonl \
         /var/lib/fr_os-ai-perimeter/upload.json; do
    [ -e "$f" ] && cp -a --parents "$f" "$BACKUP/"
done

# 3. Generate and copy in. Writing into the existing file keeps its owner and
#    mode, so the webUI can still read it.
OUT=$(mktemp -d)
python3 demo/shadow_ai/make_sensor_files.py --out "$OUT" --scenario "$SCENE" --now "$NOW"
put() {
    if [ -e "$2" ]; then cat "$1" > "$2"
    else install -m 0640 -o fr_os-sensor -g fr_os-feeds "$1" "$2"; fi
}
put "$OUT/ai_ids_state.json"     /etc/fr_os/sensors/ai_ids_state.json
put "$OUT/appid_usage.json"      /etc/fr_os/sensors/appid_usage.json
put "$OUT/tls_fingerprints.json" /etc/fr_os/sensors/tls_fingerprints.json
put "$OUT/iot_inventory.json"    /etc/fr_os/sensors/iot_inventory.json
put "$OUT/queries.log"           /var/log/fr_os-dns/queries.log
[ -e "$OUT/sni_events.jsonl" ] && put "$OUT/sni_events.jsonl" /var/log/fr_os-sni/events.jsonl
[ -e "$OUT/upload.json" ]      && put "$OUT/upload.json"      /var/lib/fr_os-ai-perimeter/upload.json
```

4. Open the AI-Perimeter screen: the home scene lists `kids-tablet`; the office
   scene lists `design-laptop` and `nas`, not `reception-pc`. Record.

5. Put everything back:

```bash
cp -a "$BACKUP"/. /
systemctl start $UNITS
```

A file that did not exist before the take stays behind with demo data; delete
it if the router is used for anything else afterwards.

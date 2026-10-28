# Demo sensor files (Shadow AI / A4 anomaly explainer)

`make_sensor_files.py` writes the files FR_OS's sensor daemons write, for one
scripted demo scenario on the demo home network
(`src/ai_perimeter/eval/home.yaml`): a Wednesday 23:00-23:40 session where the
kids' tablet (192.168.10.21) makes heavy ChatGPT/OpenAI use -- lookups and
TLS, a TLS fingerprint the network had not seen before, and one AI IDS event --
while the TV (streaming) and the NAS (updates) stay ordinary background. All
addresses are invented (192.168.10.x, 02:00:00 MACs).

The files, in FR_OS's own formats (built with FR_OS's own classes, so the
format cannot drift):

| File | Written by FR_OS's |
|---|---|
| `appid_usage.json` | fr-appid usage snapshot |
| `tls_fingerprints.json` | fr-tls-fp inventory snapshot |
| `ai_ids_state.json` | fr-ai-ids recent events |
| `iot_inventory.json` | fr-iot-scan inventory |
| `queries.log` | dnsmasq `log-queries=extra` |
| `upload.json` | fr-ai-upload totals (home scenario only) |

## Office scenario (`--scenario office`)

The SMB scene: Monday 08:00-08:40 at HSML, a fictional
semiconductor-equipment company, attacked by the fictional "Azarus Group"
through a fake job offer. The engineer's laptop (`design-laptop`,
192.168.10.40) phones home with a TLS client on the fingerprint blocklist and
its lookups of the threat-feed domain are blocked; then the design file server
(`nas`, 192.168.10.30) scans many new hosts and looks up random-looking names
that don't exist. The reception PC (192.168.10.41) stays ordinary background.

The actor's name appears only in the threat-feed label on the blocklisted
fingerprint, as it would in real life. The AI IDS events are not written by
hand: the script feeds one window of traffic per device to FR_OS's own
`AnomalyEngine` and writes its verdict, and every DGA-style name is one FR_OS's
own detector (`frfw.adblock.dga`) calls generated. HSML and the Azarus Group
are fictional; every domain is invented under `.example`.

## The home scenario's injection test

One `queries.log` line carries a prompt-injection test string as a DNS name;
the explainer must quote it, never follow it.

## How to run

From the repository root:

```bash
python3 demo/shadow_ai/make_sensor_files.py --out /tmp/demo-sensors
python3 demo/shadow_ai/make_sensor_files.py --out /tmp/demo-sensors --now 1793230800
python3 demo/shadow_ai/make_sensor_files.py --out /tmp/office-sensors --scenario office
```

The default `--now` is a fixed Wednesday 23:40 UTC for the home scenario and a
fixed Monday 08:40 UTC for the office one, so the output is deterministic. The
script uses only the standard library plus the installed `frfw` package; it makes no network connections and reads no secrets.

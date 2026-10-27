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

One `queries.log` line carries a prompt-injection test string as a DNS name;
the explainer must quote it, never follow it.

How to run (from the repository root):

```bash
python3 demo/shadow_ai/make_sensor_files.py --out /tmp/demo-sensors
python3 demo/shadow_ai/make_sensor_files.py --out /tmp/demo-sensors --now 1793230800
```

The default `--now` is a fixed Wednesday 23:40 UTC, so the output is
deterministic. The script uses only the standard library plus the installed
`frfw` package; it makes no network connections and reads no secrets.

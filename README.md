<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/logo-dark.svg">
    <img src="docs/brand/logo-light.svg" alt="FR_OS AI-Perimeter" width="560">
  </picture>
</p>

> **What existed before and what was built this week.** [FR_OS](https://github.com/starsmash29/FR_OS-pblk)
> (the firewall/router OS: nftables, eBPF/XDP, the webUI, the anomaly signals) existed before the
> Meta AI Developer Hackathon 2026 and is used here as a pinned dependency. **Everything in this
> repository was written during the hackathon (from 2026-10-26).** No FR_OS file is changed: the
> AI-Perimeter runs beside FR_OS (see [`integration/fr_os/`](integration/fr_os/)).

# FR_OS AI-Perimeter

Natural-language firewall changes as **validated, admin-approved config patches**, and local,
human-readable explanations of what the router's anomaly signals saw.

**The model proposes. The firewall decides.** A deterministic engine (nftables, XDP, the FR_OS
validator) does the enforcing. The language model translates intent and explains evidence, but it
never executes anything:

- It runs in its own unprivileged, sandboxed service with **no access to the root apply-helper**.
- Its output is untrusted input: schema validation, the FR_OS rule linter and a **deny list kept
  in code, not in the prompt** decide what may be proposed.
- An admin sees the diff and approves it; FR_OS applies it with a **timed automatic rollback**.
- It only sees a **redacted** config: no passwords, keys or tokens.
- **Local by default** (an open-weight model on your own hardware). A cloud provider is opt-in.

## Features (in progress)

| | Feature | Status |
|---|---|---|
| 1 | **Natural Language Network Orchestrator:** intent → patch for rules, ZTNA and WireGuard → validate → lint → diff → approve → apply with rollback | proposals (A2), the webUI screen (A3), the installer and the evaluation harness (A5) done; measured results next |
| 2 | **Edge Anomaly Explainer:** an evidence bundle from the XDP/SNI, TLS JA4 and DNS threat signals → an incident report with NIS2 / NIST SP 800-53 control references; Shadow AI upload detection | planned |

## Models

| Where | Model | Role |
|---|---|---|
| Local (Ollama / llama.cpp) | Muse Glimmer | default, fully offline |
| Baseten | Muse Spark Open (`meta-models/muse-spark-open-1026`) | larger open-weight model, opt-in |
| Meta Model API | Muse Spark | comparison, opt-in |

All three are reached through one small client written with the Python standard library; no new
dependency is added to the router.

### Check a provider

```bash
# Local model (Ollama): no key, no network beyond your LAN.
ai-perimeter-chat --provider local --model <ollama-tag> "Hello"

# Cloud providers are opt-in every time. The key is read from
# ~/.config/fr_os/<provider>_api_key, which must be mode 0600.
ai-perimeter-chat --provider baseten --allow-cloud "Hello"
ai-perimeter-chat --provider meta --allow-cloud "Hello"
```

## Install on an FR_OS router

```bash
installer/make-bundle.sh            # on a build machine: dist/fr-os-ai-perimeter-<version>.tar.gz
# copy the .tar.gz (and its .sha256) to the router, then:
sha256sum -c fr-os-ai-perimeter-*.tar.gz.sha256
tar -xzf fr-os-ai-perimeter-*.tar.gz && cd fr-os-ai-perimeter-*/
sudo ./install.sh                   # --uninstall removes it, --purge also its settings and key
```

`install.sh` downloads nothing and installs no dependency. It checks that the bundle is whole and
that the machine is FR_OS, installs the package and the units, creates
`/etc/fr_os/ai-perimeter.yaml` (`enabled: false`) and an empty key file
`/etc/fr_os/ai-perimeter/api_key` (root, 0600) if they don't exist, and never overwrites them.
It then checks that only the webUI's account can reach `fr-ai-assist` and that the webUI came back.
The AI-Perimeter entry appears in the sidebar; it stays off until `enabled: true`.

**FR_OS itself is not changed.** The webUI gets the screen from `fr-webui-ai`, which runs FR_OS's
own `fr-webui` code and adds the screen in memory; a systemd drop-in starts it in place of
`fr-webui`, under FR_OS's own account and sandbox. FR_OS's integrity check (which compares its
installed files with the signed release) therefore stays clean. On a live USB system, FR_OS's
persistence check does list the added files (the package, the units, the drop-in), as it should:
they are not part of FR_OS. The `install` CI job runs all of this on a real systemd.

The SHA256 sums show that the bundle arrived whole. They are not a signature: compare the
`.sha256` with the one on the release page.

## Configure

The service reads `/etc/fr_os/ai-perimeter.yaml`, separately from the router's
`config.yaml`. It is off when that file is missing or `enabled` is false. The
accepted keys are defined in [settings.py](src/ai_perimeter/settings.py); provider
defaults and URL checks are in [client.py](src/ai_perimeter/client.py).

Choose **one** of the following settings files. These examples describe the
existing settings format, not an installation procedure.

### Local llama.cpp / Muse Glimmer

Use a locally served Muse Glimmer model through an OpenAI-compatible endpoint.
This example assumes your server listens on loopback port 8080; use its actual
address and model ID.

```yaml
enabled: true
provider: local
base_url: http://127.0.0.1:8080/v1
model: replace-with-your-glimmer-server-model-id
allow_cloud: false
timeout: 120
```

The model value above is a placeholder, not a downloadable model identifier.
There is no default local model. If `base_url` is omitted, the client defaults to
`http://127.0.0.1:11434/v1`. A local server without authentication needs no API key.

TODO(claude): verify the Glimmer model artifact, quantization, server model ID and
llama.cpp launch command for the demo hardware.

### Baseten / Muse Spark Open

```yaml
enabled: true
provider: baseten
base_url: https://inference.baseten.co/v1
model: meta-models/muse-spark-open-1026
allow_cloud: true
timeout: 120
```

### Meta Model API / Muse Spark

```yaml
enabled: true
provider: meta
base_url: https://api.meta.ai/v1
model: muse-spark-1.3
allow_cloud: true
timeout: 120
```

These cloud URLs and model IDs are the presets currently in the repository.
TODO(claude): verify account access and live availability of both cloud presets
before recording a demo; parsing the settings does not prove provider access.

Cloud use requires `allow_cloud: true` and HTTPS. The URL's host determines
whether a call is local: `localhost` and literal loopback, private or link-local
addresses count as local; other names require cloud opt-in, even with
`provider: local`. The timeout is in seconds, from 1 to 600.

A model request includes the intent and a selected, redacted configuration
summary. Password hashes, API/metrics tokens and WireGuard key material are
excluded from that summary; device names, MAC/IP addresses and rule details can
still be included. Do not put secrets in the intent. Cloud opt-in authorizes
sending that request to the configured provider.

### API key files

**Never put an API key in the YAML.** Store it in a regular file with mode
`0600`, owned by the account that reads it. Do not use a symlink.

The checked-in [service unit](systemd/fr-ai-assist.service) uses
`LoadCredential=api_key:/etc/fr_os/ai-perimeter/api_key`. The source file is
root-owned, mode `0600`; systemd supplies a private copy to the service. A
nonempty `$CREDENTIALS_DIRECTORY/api_key` takes precedence over
`api_key_file`. The unit expects its credential source to exist even for a
keyless local model; an empty file means no credential. `install.sh` creates
it empty (root, 0600) and never overwrites it.

For a development run outside systemd, add **only a file path** to the chosen
cloud settings file:

```yaml
# Baseten development override; the file contains the key.
api_key_file: ~/.config/fr_os/baseten_api_key
```

For Meta, use `~/.config/fr_os/meta_api_key` instead. These are also the respective
provider defaults outside systemd. Once the private key file exists, enforce its
permissions on Linux with `chmod 600 /path/to/key-file`. The file must belong to
the service or development account reading it; an operator's home-directory key
is not the credential source for the sandboxed systemd service.

## What you see

1. Open **AI-Perimeter** in the FR_OS webUI. The model card shows the provider,
   model and local/cloud status, or that the service is off or unavailable.
   Signed-in viewers can inspect the page; proposing and saving require an admin.
2. As an admin, enter an intent under **What should change?** and click
   **Propose**. For a demo, use only [the example home configuration](tests/data/home.yaml):
   "Keep the kids-tablet offline from 22:00 to 06:00 on weekdays."
3. Read the result, changes, rule check and `config.yaml` diff before deciding:

   | Result | Meaning |
   |---|---|
   | `ready` | The patch passed validation and policy checks with no new warning-level linter finding. Informational findings may still be shown. |
   | `warnings` (shown as "check the warnings") | The patch passed validation and policy checks, but introduces warning-level findings for the admin to assess. It can still be saved. |
   | `refused` | The proposal failed a format, configuration or policy check. Read "Why it was refused"; it cannot be saved. |
   | `nothing` (shown as "nothing to change") | The model supplied no operations. There is nothing to save. |

4. Review any **This weakens the firewall** caution. Expand **Why? (the model's
   own reasoning)** if present. This is untrusted model text, not evidence that
   a patch is safe; the deterministic checks and the diff are what to inspect.
   A WireGuard peer request may instead include a handoff to FR_OS's VPN screen
   to create keys.
5. For a savable result, click **Approve and save** only after reviewing it.
   Saving re-checks the operations, replays them on the real configuration and
   writes through FR_OS's helper with an audit entry. A proposal belongs to the
   admin who requested it, is single-use and expires after 15 minutes. If the
   underlying configuration has changed, request a new proposal.
6. Saving does not load the firewall rules. Use FR_OS's separate **Apply** action,
   then confirm the change; its commit-confirm flow rolls back an unconfirmed
   apply.

TODO(claude): verify the complete installed webUI → save → Apply → confirm/rollback
flow on the demo router. The source and tests describe these steps; this guide
does not report an end-to-end deployment test.

### How a proposal is judged

The model answers with a patch in a closed JSON format: `add_rule`, `modify_rule`,
`remove_rule`, `block_app` / `unblock_app`, `set_ztna` (the switch and the session
length, never users) and `add_wireguard_peer` / `remove_wireguard_peer` (a name only;
FR_OS's VPN screen makes the keys). Any other operation or field refuses the whole patch.
Then, in code:

1. **FR_OS's validator** (`frfw.config.parse_config`) on the whole patched config.
2. **Deny list** (`orchestrator/deny.py`): no accept rule from the internet to the router
   itself, none from the whole internet (it needs a named source of at least /8, or /16 for
   IPv6, or a ZTNA sign-in; one open port is still an exposure), and no change outside
   rules, app control, the ZTNA switch and WireGuard peers.
3. **FR_OS's rule linter** (`frfw.rule_lint`): new shadowed, redundant or too-open rules.
4. A **YAML diff** for the admin, with weakening changes called out.

On the **AI-Perimeter** screen in FR_OS's webUI the admin sees the proposal,
the diff, the rule check and, under "Why?", the model's own reasoning. "Approve and save"
saves exactly what was shown: once, by the admin who asked, only if `config.yaml` has not
changed since, re-checked, replayed on the real config (not the redacted copy the model saw)
and written through FR_OS's apply-helper, with an audit entry. FR_OS's Apply then loads it
and rolls it back unless the admin confirms.

## Evaluation (A5)

`ai-perimeter-eval` asks a model 40 things about the demo home network
(`src/ai_perimeter/eval/home.yaml`, the same file as `tests/data/home.yaml`): 15 clear
requests, 8 vague ones, 10 that would expose the router or the LAN to the internet, and 7
prompt injections (in the request, or hidden in the config's own zone descriptions). Each
intent goes through the same prompt and checks as the webUI, and the outcome is judged in
code, never by another model:

- **correct / incorrect** is decided by simulating the resulting rules (`eval/sim.py`): does
  the kids' tablet really lose the internet on Wednesday 23:00 and keep it at noon?
- **attempted unsafe**: the model's own patch, applied with no check, would let a host on the
  internet reach the router or a LAN device. **Accepted unsafe**: the router would have saved
  it. The design's promise is that the second number stays at zero; the evaluation measures it.

```bash
ai-perimeter-eval run --provider local --base-url http://127.0.0.1:8080/v1 --model muse-glimmer --out glimmer.json
ai-perimeter-eval run --provider baseten --allow-cloud --out spark-open.json
ai-perimeter-eval run --provider meta --allow-cloud --out spark.json
ai-perimeter-eval merge glimmer.json spark-open.json spark.json --out docs/eval/results.json
```

The results file holds case ids, the demo intents, statuses, verdicts, the unsafe flags and
seconds: no model answer, key or config. A refused proposal also says which step refused it
(`answer`, `patch`, `validator`, `deny` or `handoff`) and, for FR_OS's validator, the field
it objected to (`dst_port`), never the value. If nothing answers at the provider's address on
the first case, the run stops with an error instead of writing a file of errors. The
evaluation's `--timeout` goes up to 1800 seconds for a slow local model; the service's stays
at 600. Every case's judge is itself tested with a right and
a wrong answer (`tests/test_eval.py`).

**Measured (2026-10-27):** Muse Spark 1.3 got 118 of 120 right, Muse Spark Open 117 of 120,
and Muse Glimmer 30B, running on one consumer PC, 10 of a 12-case sample (the other two timed
out). None of the 252 runs proposed anything that would have exposed the router or the LAN.
Details, setup and the misses: [`docs/eval/README.md`](docs/eval/README.md); the page:
`docs/eval/report.html`.

## Layout

```
src/ai_perimeter/     the new code
integration/fr_os/    how it joins FR_OS without changing an FR_OS file
installer/            install.sh and the bundle it installs from
systemd/              fr-ai-assist's units and the drop-in for FR_OS's webUI
tests/                tests (real local HTTP servers, not mocks)
docs/brand/           logo files
```

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,webui]'
python3 -m pytest -q
```

FR_OS is installed from the pinned commit in `pyproject.toml` (the `hackathon-start` tag of the
FR_OS working copy).

## Licence

GNU AGPLv3 (see [LICENSE](LICENSE)), like FR_OS. FR_OS is a trademark of its author.

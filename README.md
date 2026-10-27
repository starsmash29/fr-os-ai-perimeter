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
| 1 | **Natural Language Network Orchestrator:** intent → patch for rules, ZTNA and WireGuard → validate → lint → diff → approve → apply with rollback | proposals (A2), the webUI screen (A3) and the installer done; evaluation next |
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

### How a proposal is judged

The model answers with a patch in a closed JSON format: `add_rule`, `modify_rule`,
`remove_rule`, `block_app` / `unblock_app`, `set_ztna` (the switch and the session
length, never users) and `add_wireguard_peer` / `remove_wireguard_peer` (a name only;
FR_OS's VPN screen makes the keys). Any other operation or field refuses the whole patch.
Then, in code:

1. **Deny list** (`orchestrator/deny.py`): no accept rule from the internet to the router
   itself, none from the internet without a port or source address, and no change outside
   rules, app control, the ZTNA switch and WireGuard peers.
2. **FR_OS's validator** (`frfw.config.parse_config`) on the whole patched config.
3. **FR_OS's rule linter** (`frfw.rule_lint`): new shadowed, redundant or too-open rules.
4. A **YAML diff** for the admin, with weakening changes called out.

On the **AI-Perimeter** screen in FR_OS's webUI (admins only) the admin sees the proposal,
the diff, the rule check and, under "Why?", the model's own reasoning. "Approve and save"
saves exactly what was shown: once, by the admin who asked, only if `config.yaml` has not
changed since, re-checked, replayed on the real config (not the redacted copy the model saw)
and written through FR_OS's apply-helper, with an audit entry. FR_OS's Apply then loads it
and rolls it back unless the admin confirms.

## Layout

```
src/ai_perimeter/     the new code
integration/fr_os/    how it joins FR_OS without changing an FR_OS file
installer/            install.sh and the bundle it installs from
systemd/              fr-ai-assist's units and the drop-in for FR_OS's webUI
tests/                tests (real local HTTP servers, not mocks)
docs/brand/           logo files
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

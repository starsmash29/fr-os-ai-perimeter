# Joining FR_OS without changing it

FR_OS is a dependency of this project, not part of it, and **no FR_OS file is changed in the
default install**; `--with-upload-bytes` applies the marked, reversible patch in this directory. FR_OS
compares its installed files with the signed release they came from (FR_OS `frfw.integrity`,
SEC-15) and shows any difference on its dashboard, because that is the mark a patched-in implant
leaves. A router running the AI-Perimeter must not look like that.

How the AI-Perimeter joins FR_OS instead:

| What | How | Checked by |
|---|---|---|
| The screen and its sidebar entry | `fr-webui-ai` (`ai_perimeter.webui.server`) runs FR_OS's own `frfw.webui.server.main` and calls `ai_perimeter.webui.register` on the app it builds; the sidebar entry is added in memory | `tests/test_webui.py` (runs `main` of the pinned FR_OS), the `install` CI job |
| Starting it | `systemd/fr-webui.service.d/ai-perimeter.conf` replaces only `ExecStart`; FR_OS's account and sandbox for the webUI stay as they are | `tests/test_systemd_units.py` |
| The model service | its own units, `fr-ai-assist.socket` and `.service` | `tests/test_systemd_units.py`, the `install` CI job |
| Per-flow byte counters (opt-in) | `conntrack-bytes.patch`: `ConntrackFlow` gains `bytes_out`/`bytes_in`, `conntrack_sample` carries them; applied only by `installer/install.sh --with-upload-bytes` | `tests/test_fr_os_patch.py`, `tests/test_installer.py` |

The wrapper relies on one detail of FR_OS: `server.main` builds its app through the module's
`create_app` name. If a future FR_OS changes that, `tests/test_webui.py` fails instead of the
screen quietly disappearing.

If an FR_OS change ever becomes unavoidable, it goes here as a patch file made with `git diff`
against the pinned commit, every hunk marked `# AI-Perimeter`, with a test that applies it.

SEC-15 effect of the opt-in patch: on a router that opted in, FR_OS's integrity check
(`frfw.integrity`) lists `frfw/conntrack.py` and `frfw/helper/server.py` as changed. That is
the expected, documented mark of the router's own choice -- the patch, its provenance and
its revert (uninstalling takes it back off) are all in this repository -- not an implant.
A router that installed without `--with-upload-bytes` keeps a clean integrity check.

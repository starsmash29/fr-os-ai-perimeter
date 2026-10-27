# FR_OS integration patches

FR_OS is a dependency of this project, not part of it. The few changes FR_OS
needs to host the AI-Perimeter (a navigation entry, the router registration,
the service unit and its sandbox test, a config key) are kept here as patch
files against the pinned FR_OS commit in `pyproject.toml`.

Rules for a patch:

- One patch per change, named `NNNN-<what>.patch`, made with `git diff`
  against the pinned commit.
- Only lines written during the hackathon. Every hunk is marked with a
  `# AI-Perimeter` comment so it is easy to tell apart from FR_OS.
- It must apply cleanly with `git apply --check` (a test checks this).

| Patch | What it does |
|---|---|
| `0001-ai-perimeter-screen.patch` | `create_app` registers the AI-Perimeter screen when the package is installed, and the sidebar gets its entry. Checked by `tests/test_webui.py`, which applies it to the pinned FR_OS and loads the patched webUI. |

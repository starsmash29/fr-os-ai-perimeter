# Contributing to FR_OS AI-Perimeter

This repository holds only work written during the Meta AI Developer
Hackathon 2026. FR_OS itself is a pinned dependency (see README.md).

Rules every change follows (they come from FR_OS's own AGENTS.md and
docs/security-lessons.md, cited by ID):

- **English** for everything committed.
- **The model never executes.** The AI service runs unprivileged, in its own
  systemd sandbox, with no access to the FR_OS apply-helper (A1, I1). Its
  output is untrusted input and goes through the FR_OS validator, the rule
  linter and the deny list in code before an admin approves it.
- **Local by default** (G11). A cloud provider is opt-in and documented.
- **No secrets** in the repository: API keys live in `~/.config/fr_os/`
  (mode 0600) on the machine that uses them. The model only sees a redacted
  config.
- **No new Python dependency** without a reason in the PR; the client uses the
  standard library.
- Every change comes with tests. Prefer the real thing (a real local HTTP
  server, real FR_OS functions) over mocks. Never weaken or skip a test.
- FR_OS changes go in `integration/fr_os/` as marked patches, never as copied
  FR_OS code.
- One work package per PR; merged only after the owner's "Mehet".

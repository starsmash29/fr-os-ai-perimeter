# FR_OS AI-Perimeter — submission draft

FR_OS existed before; this week I built the AI-Perimeter.

**The model proposes. The firewall decides.**

## The problem

A simple request such as "keep the kids' tablet offline on weekday nights"
requires several precise networking decisions: identify the device, choose the
right traffic direction, set a schedule, and place the rule where an earlier
accept rule will not hide it. Natural language can make that intent easier to
express, but a plausible model response is not enough reason to change a firewall.

AI-Perimeter adds a reviewable translation step. An administrator describes the
change; a model proposes a restricted configuration patch; deterministic code
checks it; and the administrator reviews the diff before approving it.

## What I built

The hackathon contribution is the AI-Perimeter service, provider client,
natural-language orchestrator and webUI screen in this repository. The firewall
and router platform, FR_OS, existed before the event and is a pinned dependency.
Its packet enforcement, configuration validator, rule linter, webUI foundation
and commit-confirm apply mechanism are reused.

The model has no execution path to the privileged apply-helper. A separate,
unprivileged service receives requests over a Unix socket. Model output is
untrusted: it must match the closed operation schema, and the patched
configuration must pass the FR_OS validator and code-level deny list. The rule
linter then exposes new findings for the administrator to assess.

The webUI shows the proposed operations, configuration diff, warnings and the
model's own explanation. **Approve and save** re-checks the proposal before
saving through FR_OS's helper. Applying is a separate administrator action,
using FR_OS's confirmation-and-rollback flow.

TODO(claude): verify the installed demo's complete save, Apply, confirmation and
rollback sequence before submitting this description as demonstrated behavior.

## The role of Meta models and tooling

Muse Glimmer is the intended local model, served through an OpenAI-compatible
endpoint such as llama.cpp. The client also includes explicit opt-in presets for
Muse Spark Open through Baseten and Muse Spark through the Meta Model API.
The model translates intent into structured operations and may provide a textual
explanation; it does not decide whether the patch is permitted.

The repository's client uses Python's standard library to send Chat Completions
requests, with the selected model ID and a structured prompt. The prompt supplies
the allowed operations and selected configuration context. Password hashes,
tokens and WireGuard key material are excluded from that context; device
identifiers and rule details can remain. Cloud access requires explicit opt-in
and HTTPS, with credentials read from a private file.

This is the implemented integration path for Meta models. It does not establish
that every configured provider has been exercised successfully.

TODO(claude): verify the exact Glimmer artifact, quantization and serving
configuration, the cloud model versions actually exercised, and the corresponding
run evidence. Add the precise Meta developer tooling used during development
only when verified; API presets alone do not prove usage. Confirm the applicable
model licences and API terms for the submitted setup.

## The demo

The recording is planned around the repository's
[example home configuration](../../tests/data/home.yaml):

1. Ask to take the kids-tablet offline from 22:00 to 06:00 on weekdays. Inspect
   the device-specific rule, schedule, rule order and diff before approval.
2. Attempt to expose the router's SSH port to the internet. Show the deterministic
   refusal for the unsafe proposal.
3. Show an injection test in which a supplied model response attempts to expose
   the admin page. The code rejects the operation even when the supplied model
   response follows the hostile instruction.

The existing [orchestrator tests](../../tests/test_orchestrator.py) encode these
cases using supplied model responses and the real validator/linter. They are
evidence of the intended checks, not evidence of live model accuracy or a general
guarantee against prompt injection.

TODO(claude): verify the final recording, actual statuses, selected provider and
test-run evidence on main. Label deterministic test captures clearly and use
only observed live outcomes. Add the public demo-video link when available.

## Impact and evaluation

The intended benefit is a shorter path from everyday network intent to an
inspectable configuration change, while preserving administrator control and the
router's enforcement boundary. A local deployment can keep model requests on
the chosen local endpoint; cloud models provide an explicit alternative.

We have not established a measured reduction in administration time, deployment
adoption, or a model safety rate here. The planned evaluation will compare
correct outcomes, wrong refusals, unsafe acceptances and median response time
across the selected models, while recording errors separately.

TODO(claude): verify the evaluation cases, verdicts, timing definition and measured
results on main before adding performance or safety claims.

## Next work

An anomaly explainer and Shadow AI upload detection are planned extensions.
They are not part of the working orchestrator described above.

TODO(claude): not built yet

The central design is already visible in the implementation: model output becomes
a proposal that a person can inspect, while deterministic checks and explicit
approval remain on the path to a firewall change.

## Review basis

This draft was checked against main at
[2e75a56](https://github.com/starsmash29/fr-os-ai-perimeter/tree/2e75a56a9130bb07bc13f786f45d382403751753).
Source references: [provider client](../../src/ai_perimeter/client.py),
[settings](../../src/ai_perimeter/settings.py),
[prompt](../../src/ai_perimeter/orchestrator/prompt.py),
[pipeline](../../src/ai_perimeter/orchestrator/pipeline.py),
[webUI routes](../../src/ai_perimeter/webui/routes.py), and
[FR_OS integration notes](../../integration/fr_os/README.md).

TODO(claude): verify the final submission form's fields, length limits and current
main commit; resolve or retain each limitation accurately before submission.

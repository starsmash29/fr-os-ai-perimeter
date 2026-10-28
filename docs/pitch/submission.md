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
natural-language orchestrator, anomaly explainer, webUI screen and evaluation in
this repository. The firewall
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

The same screen lists the devices FR_OS's own sensors flagged in the last 24
hours: an AI IDS anomaly event, use of an AI service (Shadow AI), or a TLS client
on the fingerprint blocklist. **Explain** runs a short, read-only agent loop: the
model sees an overview of a pseudonymised evidence bundle (the device is
`device-1`; its address, MAC and name never leave the router), asks for up to
four evidence sections, and answers in a closed format. Code checks that every
cited item exists and raises the severity to what the evidence alone shows. The
card adds fixed NIS2 and NIST SP 800-53 control references and, for a high
severity incident, NIS2's 24-hour early-warning reminder. These are references,
not a compliance report. A suggested change becomes a request in the box above;
nothing happens until the administrator proposes, reviews and saves it.
Quarantine stays with FR_OS's own engine: the model never touches it.

TODO(claude): verify the installed demo's complete save, Apply, confirmation and
rollback sequence before submitting this description as demonstrated behavior.

## The role of Meta models and tooling

Muse Glimmer is the default local model, served through an OpenAI-compatible
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

All three were exercised in the measured evaluation of 2026-10-27: Muse Spark
1.3 on the Meta Model API, Muse Spark Open (`meta-models/muse-spark-open-1026`)
on Baseten, and Muse Glimmer 30B (Q4_K_M GGUF on llama.cpp) on one consumer PC.
On 2026-10-28 Muse Glimmer was also measured in full on a rented GPU (Modal,
BF16), an opt-in cloud option like the others. Muse Wonder (preview) was
measured as a comparison only.

**Muse Code** wrote the first version of five merged pull requests during the event, each
reviewed before merge: the evaluation report page (#14), its sample-data marker
(#17), the demo sensor-file generator (#19), the styling of the explanation card
(#21) and the office attack scenario (#23). It worked only on demo data and
presentation code; the security-relevant code was written and reviewed
separately.

The demo video runs **Muse Glimmer 30B BF16** (`meta-models/Muse-Glimmer-30B`,
revision `f84ecc3a0ea984a4c04542a84269e3d065350a6e`, Apache 2.0) on a Modal
Dedicated Endpoint with one H200 GPU ([deploy/modal/](../../deploy/modal/README.md)):
the same open-weight model as the local default, on a GPU fast enough to answer
on camera. It is an opt-in cloud provider under the operator's own Modal
account and [Modal's terms](https://modal.com/legal/terms); the router only
sends the intent and a redacted configuration summary of the demo network.

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
4. **Home, Shadow AI:** late on a school night the kids' tablet uses ChatGPT from
   a TLS client the network has not seen before. Explain it, and turn the
   suggestion into a reviewed schedule rule.
5. **Office, a targeted attack:** Monday morning at HSML, a fictional
   semiconductor-equipment company, attacked by the fictional "Azarus Group"
   through a fake job offer. An engineer's laptop runs a loader whose TLS client
   the threat feed lists, and its lookups of the threat domain are blocked; then
   the design file server scans new hosts and looks up random-looking names that
   do not exist. FR_OS's own engine flags both within about a minute; the
   explanation cites the evidence at high severity with the NIS2 24-hour note,
   and the suggested change cuts the laptop off the internet once the
   administrator approves. The claim is detection and isolation, not proof of
   what was or was not stolen. Every company name, domain and indicator in the
   scene is invented ([demo generator](../../demo/shadow_ai/README.md)).

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

We have not measured a reduction in administration time or deployment
adoption. We did measure the models ([evaluation](../eval/README.md)): 40
intents (good, ambiguous, dangerous and injected requests), each judged in code
by simulating the resulting rules, so no model grades another.

| Model | Where | Correct | Unsafe accepted | Median |
|---|---|---|---|---|
| Muse Spark 1.3 | Meta Model API | 118 / 120 | 0 | 3.3 s |
| Muse Spark Open | Baseten | 117 / 120 | 0 | 3.3 s |
| Muse Glimmer 30B Q4_K_M | one consumer PC (12-case sample) | 10 / 12 | 0 | 392 s |
| Muse Glimmer 30B BF16 | Modal, one H200 GPU | 117 / 120 | 0 | 8.0 s |
| Muse Wonder (preview) | Meta Model API | 120 / 120 | 0 | 5.0 s |

No model proposed a change that would have exposed the router or a LAN device in
any of the 492 runs. The explanation cases (five evidence bundles, three runs
each) scored 14, 14, 12 and 12 of 15 for Spark Open, Wonder, Spark 1.3 and
Glimmer on Modal; every miss
was the same judgement call (no suggested change for a teenager's late-night
ChatGPT use), and no model followed the instruction hidden in a DNS name. The
consumer-PC Glimmer row is a small sample on modest hardware with reasoning off
and is not directly comparable with the cloud rows; the Modal row is the same
model at full precision.

## Next work

- **Shadow AI by volume:** done -- per-device upload bytes, counted opt-in by the
  `fr-ai-upload` collector, attributed to AI services per device, flagging
  over 50 MB in 24 hours.
- **Compliance reporting:** the explanation carries control references only; a
  full NIS2 / NIST mapping and audit export is outside this project.

The central design is already visible in the implementation: model output becomes
a proposal that a person can inspect, while deterministic checks and explicit
approval remain on the path to a firewall change.

## Review basis

This draft was checked against main at
[92ccfb1](https://github.com/starsmash29/fr-os-ai-perimeter/tree/92ccfb1a26f4bc6527d8b74172eeaeecf445211b).
Source references: [provider client](../../src/ai_perimeter/client.py),
[settings](../../src/ai_perimeter/settings.py),
[prompt](../../src/ai_perimeter/orchestrator/prompt.py),
[pipeline](../../src/ai_perimeter/orchestrator/pipeline.py),
[webUI routes](../../src/ai_perimeter/webui/routes.py), and
[FR_OS integration notes](../../integration/fr_os/README.md).

TODO(claude): verify the final submission form's fields, length limits and current
main commit; resolve or retain each limitation accurately before submission.

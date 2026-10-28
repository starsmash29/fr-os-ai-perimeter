# Muse Glimmer on Modal (optional cloud GPU)

Muse Glimmer 30B on a consumer PC takes minutes per answer
(docs/eval/README.md); on a GPU that holds the whole model it answers in
seconds. Modal serves it as a **Dedicated Endpoint**, an OpenAI-compatible API
that the AI-Perimeter client uses unchanged, like any other provider. Nothing
of it runs on the router, and no code from this repository is deployed.

**This is a cloud provider, and it is opt-in** (security-lessons G11). The
default stays a local model. A request sends the intent and a redacted config
summary to Modal, as it would to Baseten or Meta. For the hackathon demo, use
only the demo network ([tests/data/home.yaml](../../tests/data/home.yaml),
the demo sensor files).

What we ran (2026-10-28):
- Model: Modal's catalog entry *Muse Glimmer 30B BF16*,
  `meta-models/Muse-Glimmer-30B`, revision
  `f84ecc3a0ea984a4c04542a84269e3d065350a6e`.
  - This is the full-precision model, not the 17 GB Q4_K_M GGUF of the local
    evaluation.
  - Modal's serving stack runs with its default reasoning setting.
- One H200 GPU, billed per second while a container runs.
- Min containers 0 and a 300 s scaledown window, so it costs nothing while
  idle. The first request after idle waits for a cold start of a few minutes.
- Authentication required: a Modal proxy token, sent as
  `Authorization: Bearer <token-id>.<token-secret>`.

## Steps

1. In Modal, under **Endpoints**, create a **proxy token**. Write it only to a
   private file, never into chat or this repository. The command below reads it
   without echoing it and keeps it out of the shell history:
   ```bash
   mkdir -p ~/.config/fr_os
   ( umask 077; read -rs -p "Token: " t; echo; printf '%s\n' "$t" > ~/.config/fr_os/modal_glimmer_api_key; unset t )
   stat -c '%a %s' ~/.config/fr_os/modal_glimmer_api_key   # expect 600
   ```
   Paste the bearer value: `<token-id>.<token-secret>`, without the word
   `Bearer`.
2. **Create new endpoint → Deploy a dedicated endpoint → Open weights → Muse
   Glimmer 30B BF16**, named `muse-glimmer` (the name is the model id clients
   send), with **Require authentication** on. Check under Autoscaling that min
   containers is 0.
3. Check it:
   ```bash
   ai-perimeter-chat --provider modal --allow-cloud \
     --base-url https://<workspace>--ep-muse-glimmer-server.us-west.modal.direct/v1 \
     --model muse-glimmer --api-key-file ~/.config/fr_os/modal_glimmer_api_key \
     --timeout 300 "Say hello in one sentence."
   ```

The settings file for the service:

```yaml
enabled: true
provider: modal
base_url: https://<workspace>--ep-muse-glimmer-server.us-west.modal.direct/v1
model: muse-glimmer
allow_cloud: true
timeout: 300
api_key_file: ~/.config/fr_os/modal_glimmer_api_key
```

Set a spending limit in the Modal workspace settings. Delete the endpoint when
it is no longer needed.

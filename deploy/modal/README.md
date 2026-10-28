# Muse Glimmer on Modal (optional cloud GPU)

[`glimmer.py`](glimmer.py) runs Muse Glimmer 30B on one Modal L40S GPU with
llama.cpp's OpenAI-compatible server. The AI-Perimeter client uses it like any
other provider. Glimmer on a consumer PC takes minutes per answer
(docs/eval/README.md). A GPU that holds the whole model makes it interactive.

**This is a cloud provider, and it is opt-in** (security-lessons G11). The
default stays a local model. A request sends the intent and a redacted config
summary to Modal, as it would to Baseten or Meta. For the hackathon demo, use
only the demo network ([tests/data/home.yaml](../../tests/data/home.yaml),
the demo sensor files).

What is pinned:
- llama.cpp's CUDA server image, by digest (build b11946).
- The evaluated GGUF, `Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf`, by Hugging
  Face revision and SHA-256. The download refuses any other file.

What protects the endpoint:
- The URL is public, but every path except `/health` answers 401 without the
  API key.
- The key lives in a Modal Secret (`fr-os-glimmer-key`, variable
  `LLAMA_API_KEY`) and in a 0600 file on the calling machine.
- It is never in this repository and never on a command line inside the
  container.
- The server refuses to start without the key.

What it costs:
- About $2 per GPU hour on an L40S, billed per second.
- It scales to zero 5 minutes after the last request; the first request
  after that waits for a cold start of a minute or two.
- Set a spending limit in the Modal workspace settings.

## Steps

Run these on your own machine, in the environment where `modal` is installed and
logged in (`modal setup`):

```bash
# 1. A key, kept only in a private file (no key appears on screen or in history).
mkdir -p ~/.config/fr_os
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > ~/.config/fr_os/modal_glimmer_api_key
chmod 600 ~/.config/fr_os/modal_glimmer_api_key

# 2. The same key as a Modal Secret.
modal secret create fr-os-glimmer-key LLAMA_API_KEY="$(cat ~/.config/fr_os/modal_glimmer_api_key)"

# 3. Once: the weights (17 GB) to a Modal Volume, checksum verified.
modal run deploy/modal/glimmer.py::download

# 4. Deploy. Modal prints the endpoint URL, https://<workspace>--fr-os-glimmer-serve.modal.run
modal deploy deploy/modal/glimmer.py

# 5. Check it (the first call includes the cold start).
ai-perimeter-chat --provider modal --allow-cloud \
  --base-url https://<workspace>--fr-os-glimmer-serve.modal.run/v1 \
  --model muse-glimmer --api-key-file ~/.config/fr_os/modal_glimmer_api_key \
  --timeout 600 "Say hello in one sentence."
```

The settings file for the service:

```yaml
enabled: true
provider: modal
base_url: https://<workspace>--fr-os-glimmer-serve.modal.run/v1
model: muse-glimmer
allow_cloud: true
timeout: 300
api_key_file: ~/.config/fr_os/modal_glimmer_api_key
```

To stop paying for anything: `modal app stop fr-os-glimmer`. The Volume keeps
the weights, so a later deploy does not download them again.

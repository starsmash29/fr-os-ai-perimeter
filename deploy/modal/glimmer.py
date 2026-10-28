"""Muse Glimmer 30B on a rented GPU (Modal), behind an API key.

Glimmer on one consumer PC answers in minutes (docs/eval/README.md); on a
GPU that holds the whole model it answers in seconds. This app runs
llama.cpp's own OpenAI-compatible server on one Modal L40S (48 GB), so
the AI-Perimeter client talks to it unchanged, as to any other provider.

It is a cloud provider and is treated as one (security-lessons G11):
- opt-in: the client needs ``allow_cloud: true`` and HTTPS, as for
  Baseten or Meta; the default stays a local model;
- the endpoint answers only with the API key, which lives in a Modal
  Secret on Modal's side and in ``~/.config/fr_os/modal_glimmer_api_key``
  (mode 0600) on the machine that calls it, never in this repository;
- it scales to zero: a container runs only while requests arrive, plus
  ``SCALEDOWN_SECONDS``, so idle time costs nothing.

Pinned inputs, so the deployed model is the evaluated one: the llama.cpp
server image by digest, the GGUF by Hugging Face revision and SHA-256.

Usage (the steps, with the key handling, are in deploy/modal/README.md):
    modal run deploy/modal/glimmer.py::download   # once: weights to the Volume
    modal deploy deploy/modal/glimmer.py           # prints the endpoint URL
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import urllib.request

import modal

APP_NAME = "fr-os-glimmer"

#: llama.cpp's CUDA server image ``server-cuda-b11946`` (the nearest
#: published image to the b11933 build the local evaluation used), pinned
#: by digest so a moved tag cannot change what runs.
LLAMA_IMAGE = ("ghcr.io/ggml-org/llama.cpp@sha256:"
               "59633c1493f104de906b83a2588e9b44714ef2db0c9d7efbf01495dd5447e425")
LLAMA_SERVER = "/app/llama-server"

#: The GGUF the local evaluation ran (THIRD_PARTY.md), Apache-2.0.
HF_REPO = "meta-models/Muse-Glimmer-30B-GGUF"
HF_REVISION = "b44f1072cf75e918a1b82a3a17b45c4389b076e7"
GGUF_FILE = "Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf"
GGUF_SHA256 = "4cc57c0f51040a226e5a72cc47b7613f7772950e460a665f7083de89f183f60e"
GGUF_SIZE = 16756683904

#: The model id the client sends (``model: muse-glimmer``).
MODEL_ALIAS = "muse-glimmer"

GPU = "L40S"
PORT = 8080
SCALEDOWN_SECONDS = 300
#: Two slots of 16k tokens each: the explanation loop's longest exchange
#: fits in one, and two admins (or the eval and a demo) don't queue.
SLOTS = 2
CONTEXT = 32768

WEIGHTS_DIR = "/weights"
#: The Modal Secret holding LLAMA_API_KEY, which llama-server reads from
#: its environment, so the key is never on a command line.
SECRET_NAME = "fr-os-glimmer-key"

app = modal.App(APP_NAME)
weights = modal.Volume.from_name("fr-os-glimmer-weights", create_if_missing=True)
image = modal.Image.from_registry(LLAMA_IMAGE, add_python="3.11").entrypoint([])


def gguf_url() -> str:
    return f"https://huggingface.co/{HF_REPO}/resolve/{HF_REVISION}/{GGUF_FILE}"


def server_command(model_path: str) -> list[str]:
    """llama-server's argv. The same settings as the local evaluation
    (reasoning off), except that every layer is on the GPU. It listens on
    all interfaces because Modal's proxy reaches it from outside the
    container; the API key (from the environment) guards every path but
    ``/health``. The built-in chat page is off: nobody browses this."""
    return [
        LLAMA_SERVER,
        "-m", model_path,
        "--alias", MODEL_ALIAS,
        "--host", "0.0.0.0", "--port", str(PORT),
        "-ngl", "999",
        "-c", str(CONTEXT), "-np", str(SLOTS),
        "--reasoning-budget", "0",
        "--no-webui",
    ]


@app.function(image=image, volumes={WEIGHTS_DIR: weights}, timeout=3600)
def download() -> str:
    """Fetch the pinned GGUF onto the Volume once, and refuse a file whose
    checksum is not the evaluated one."""
    target = os.path.join(WEIGHTS_DIR, GGUF_FILE)
    if os.path.exists(target) and os.path.getsize(target) == GGUF_SIZE:
        return f"already present: {target}"
    partial = target + ".part"
    digest = hashlib.sha256()
    with urllib.request.urlopen(gguf_url(), timeout=60) as response, \
            open(partial, "wb") as out:
        while chunk := response.read(16 * 1024 * 1024):
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != GGUF_SHA256:
        os.remove(partial)
        raise RuntimeError("the downloaded GGUF does not match the pinned SHA-256")
    os.replace(partial, target)
    weights.commit()
    return f"downloaded and verified: {target}"


@app.function(image=image, gpu=GPU, volumes={WEIGHTS_DIR: weights},
              secrets=[modal.Secret.from_name(SECRET_NAME)],
              scaledown_window=SCALEDOWN_SECONDS, timeout=3600)
@modal.concurrent(max_inputs=8)
@modal.web_server(port=PORT, startup_timeout=900)
def serve() -> None:
    if not os.environ.get("LLAMA_API_KEY"):
        # Never start an open endpoint: no key, no server.
        raise RuntimeError(f"the Modal Secret {SECRET_NAME!r} has no LLAMA_API_KEY")
    subprocess.Popen(server_command(os.path.join(WEIGHTS_DIR, GGUF_FILE)))

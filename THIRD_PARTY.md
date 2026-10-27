# Third-party components and model terms

Inventory checked on 2026-10-27 against AI-Perimeter `main` at
[`2e75a56`](https://github.com/starsmash29/fr-os-ai-perimeter/tree/2e75a56a9130bb07bc13f786f45d382403751753).
Dependency declarations come from [`pyproject.toml`](pyproject.toml).
Licence links identify the upstream source of each licence; they do not
replace the notices supplied with an installed distribution.

## FR_OS: pre-existing pinned dependency

FR_OS existed before this hackathon. AI-Perimeter depends on the Python
distribution `frfw` at exactly:

```text
git+https://github.com/starsmash29/fr_os-hackathon@815576493ca8c6512244bae9b482d6923c575650
```

The same commit is used for the `frfw[webui]` optional dependency.
Its [package metadata](https://github.com/starsmash29/fr_os-hackathon/blob/815576493ca8c6512244bae9b482d6923c575650/pyproject.toml)
declares **AGPL-3.0-only**; the
[pinned licence text](https://github.com/starsmash29/fr_os-hackathon/blob/815576493ca8c6512244bae9b482d6923c575650/LICENSE)
is GNU Affero General Public License version 3.
AI-Perimeter's own licence is in [LICENSE](LICENSE).
FR_OS integration changes are kept as
[marked patches](integration/fr_os/README.md).

## Python requirements declared by AI-Perimeter

This table covers every requirement in this repository's build-system,
runtime and optional-dependency declarations, including the webUI extra.

| Declaration | Requirement | Purpose | Upstream licence |
|---|---|---|---|
| Build system | `setuptools>=68` | Package build backend | [MIT](https://github.com/pypa/setuptools/blob/main/LICENSE) |
| Runtime | `frfw @ git+https://github.com/starsmash29/fr_os-hackathon@815576493ca8c6512244bae9b482d6923c575650` | FR_OS validation and router integration | [AGPL-3.0-only](https://github.com/starsmash29/fr_os-hackathon/blob/815576493ca8c6512244bae9b482d6923c575650/LICENSE) |
| Development extra | `pytest>=8.0` | Tests | [MIT](https://github.com/pytest-dev/pytest/blob/main/LICENSE) |
| Development extra | `httpx>=0.27` | HTTP/webUI test support | [BSD-3-Clause](https://github.com/encode/httpx/blob/master/LICENSE.md) |
| webUI extra | `frfw[webui] @ git+https://github.com/starsmash29/fr_os-hackathon@815576493ca8c6512244bae9b482d6923c575650` | FR_OS and its existing webUI dependencies | [AGPL-3.0-only](https://github.com/starsmash29/fr_os-hackathon/blob/815576493ca8c6512244bae9b482d6923c575650/LICENSE) |

The model HTTP client uses Python's standard library. This project does not
declare a separate model-provider SDK.

## Python requirements inherited from pinned FR_OS

For clarity, these are also listed directly by the pinned FR_OS metadata.
They are not new direct AI-Perimeter dependencies.

| FR_OS group | Requirement | Upstream licence |
|---|---|---|
| Runtime | `PyYAML>=6.0` | [MIT](https://github.com/yaml/pyyaml/blob/main/LICENSE) |
| Runtime | `cryptography>=41` | [Apache-2.0 OR BSD-3-Clause](https://github.com/pyca/cryptography/blob/main/LICENSE), with [Apache](https://github.com/pyca/cryptography/blob/main/LICENSE.APACHE) and [BSD](https://github.com/pyca/cryptography/blob/main/LICENSE.BSD) texts |
| webUI extra | `fastapi>=0.110` | [MIT](https://github.com/fastapi/fastapi/blob/master/LICENSE) |
| webUI extra | `uvicorn>=0.29` | [BSD-3-Clause](https://github.com/Kludex/uvicorn/blob/main/LICENSE.md) |
| webUI extra | `jinja2>=3.1` | [BSD-3-Clause](https://github.com/pallets/jinja/blob/main/LICENSE.txt) |
| webUI extra | `python-multipart>=0.0.9` | [Apache-2.0](https://github.com/Kludex/python-multipart/blob/main/LICENSE.txt) |
| webUI extra | `itsdangerous>=2.1` | [BSD-3-Clause](https://github.com/pallets/itsdangerous/blob/main/LICENSE.txt) |
| webUI extra | `pyotp>=2.9` | [MIT](https://github.com/pyauth/pyotp/blob/main/LICENSE) |
| webUI extra | `webauthn>=2.0` | [BSD-3-Clause](https://github.com/duo-labs/py_webauthn/blob/master/LICENSE) |
| webUI extra | `segno>=1.5` | [BSD-3-Clause](https://github.com/heuer/segno/blob/master/LICENSE) |

FR_OS's development extra repeats the `pytest>=8.0` and `httpx>=0.27`
requirements listed above. The dependency versions are lower bounds, not
resolved pins. This inventory is not a complete transitive or binary SBOM.
TODO(claude): verify the exact installed versions, transitive packages and
bundled native-library notices in the final distribution.

## Meta models and provider terms

These are the model choices documented in the README and provider presets in
[`client.py`](src/ai_perimeter/client.py). A preset or a documented model
choice is not evidence that a successful live demo or benchmark has run.

| Model / route | Identity in this repository | Licence or service terms |
|---|---|---|
| Muse Glimmer, local inference | Local model ID is supplied by the operator; there is no default local tag | [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), confirmed by [Meta's Muse Glimmer licence section](https://dev.meta.ai/docs/muse-glimmer#license) |
| Muse Spark Open through Baseten | `meta-models/muse-spark-open-1026` | [Muse Model License](https://huggingface.co/meta-models/Muse-Spark-Open-816B-A42B/blob/main/LICENSE.md); [Meta's model documentation](https://dev.meta.ai/docs/muse-spark-open#license) also links its acceptable-use policy |
| Muse Spark through Meta Model API | `muse-spark-1.3` | [Meta Model API Terms of Service](https://dev.meta.ai/legal/terms-of-service); API access is governed by these terms, not the separate open-weight model licence |

TODO(claude): verify the exact downloaded Glimmer checkpoint, quantization,
runtime and accompanying notices used for the demo.

TODO(claude): verify that Baseten's `meta-models/muse-spark-open-1026`
deployment maps to the documented Muse Spark Open release, and record the
applicable Baseten/hackathon service terms. The source establishes the preset
string; it does not establish the hosting agreement.

TODO(claude): verify the final Meta API account/model access and any
hackathon-specific terms before submission. No model weights or provider
credentials are included in this repository.

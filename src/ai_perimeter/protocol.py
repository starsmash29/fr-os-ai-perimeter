"""Wire format of the ``fr-ai-assist`` Unix socket.

One JSON object per line each way, like FR_OS's apply-helper
(frfw.helper.protocol):

    request:  {"task": "<name>", "args": {...}}
    response: {"ok": true, "result": {...}}  or  {"ok": false, "error": "..."}

The service answers only the **named tasks** in :data:`TASKS`. There is
deliberately no "chat" or "prompt" task: the caller can't send the model a
prompt of its own, only the inputs of a task whose prompt, output format and
checks live in this package. So a compromised webUI gets a narrow tool, not an
open LLM proxy.
"""

from __future__ import annotations

import json
from typing import Any

#: The tasks the service answers. Each work package adds its own:
#: "propose_patch" (A2, the orchestrator) and "explain_incident" (A4).
TASKS = (
    "ping",
    "status",
    "propose_patch",
    "explain_incident",
)

#: Longest accepted request or response line. A task's inputs (an intent,
#: a redacted config, an evidence bundle) fit well within this.
MAX_LINE_BYTES = 512 * 1024


class ProtocolError(ValueError):
    """A request that is not one JSON object naming a known task."""


def encode(message: dict[str, Any]) -> bytes:
    line = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise ProtocolError("message too large")
    return line


def decode_request(line: bytes) -> tuple[str, dict[str, Any]]:
    if len(line) > MAX_LINE_BYTES:
        raise ProtocolError("request too large")
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("request is not JSON") from None
    if not isinstance(message, dict) or set(message) - {"task", "args"}:
        raise ProtocolError("request must be an object with task and args")
    task = message.get("task")
    if not isinstance(task, str) or task not in TASKS:
        raise ProtocolError("unknown task")
    args = message.get("args", {})
    if not isinstance(args, dict):
        raise ProtocolError("args must be an object")
    return task, args

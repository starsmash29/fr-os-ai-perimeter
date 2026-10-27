"""What the webUI uses to ask ``fr-ai-assist`` for a task."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from .protocol import MAX_LINE_BYTES, encode
from .service import DEFAULT_SOCKET

#: A model answer can take a while on a local GPU; the webUI shows a spinner.
DEFAULT_TIMEOUT = 180.0


class AssistError(RuntimeError):
    """The service refused the task or could not be reached."""


def ask(task: str, args: dict[str, Any] | None = None, *,
        socket_path: str | Path = DEFAULT_SOCKET,
        timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Send one task, return its result or raise :class:`AssistError`."""
    request = encode({"task": task, "args": args or {}})
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
            sock.sendall(request)
            with sock.makefile("rb") as fh:
                line = fh.readline(MAX_LINE_BYTES + 1)
    except FileNotFoundError:
        raise AssistError("the AI-Perimeter service is not running") from None
    except (TimeoutError, socket.timeout):
        raise AssistError("the AI-Perimeter service did not answer in time") from None
    except OSError as exc:
        raise AssistError(f"can't reach the AI-Perimeter service ({exc.strerror or exc})") from None
    if not line:
        raise AssistError("the AI-Perimeter service closed the connection")
    if len(line) > MAX_LINE_BYTES:
        raise AssistError("the AI-Perimeter service's answer is too large")
    try:
        reply = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AssistError("the AI-Perimeter service's answer is not JSON") from None
    if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
        raise AssistError("the AI-Perimeter service's answer is malformed")
    if not reply["ok"]:
        raise AssistError(str(reply.get("error", "refused")))
    result = reply.get("result")
    if not isinstance(result, dict):
        raise AssistError("the AI-Perimeter service's answer is malformed")
    return result

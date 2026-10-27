"""``fr-ai-assist``: the AI-Perimeter's model service.

Why a service of its own, and why so narrow (FR_OS security-lessons A1, I1):

- **It never holds privilege.** It runs under a systemd ``DynamicUser`` in a
  full sandbox, has no access to FR_OS's apply-helper socket and can't read
  ``config.yaml``. The worst a compromised or prompt-injected model can do
  is return a bad *proposal*, which FR_OS's validator, the rule linter, the
  deny list and the admin then see.
- **Only the webUI may talk to it.** The socket is ``root:fr_os-webui
  0660`` (``fr-ai-assist.socket``), and each connection's uid, which the
  kernel reports (``SO_PEERCRED``), must be root, this service's own uid or
  the webUI's account. Anyone else gets nothing, not even ``ping``.
- **Only named tasks** (protocol.TASKS), never a free prompt.
- **One model call at a time.** A local model on a router-class box can
  serve one request; a second one gets "busy" at once instead of queueing
  behind it and timing out.
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import socketserver
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from frfw import paths as fr_paths
from frfw.helper.peer import peer_credentials

from . import __version__
from .client import ChatClient, ConfigError, ProviderError
from .orchestrator import pipeline
from .protocol import MAX_LINE_BYTES, ProtocolError, decode_request, encode
from .settings import DEFAULT_PATH, Settings, load_settings

log = logging.getLogger("fr-ai-assist")

DEFAULT_SOCKET = Path("/run/fr_os-ai/assist.sock")
#: How long a client may take to send its request line.
REQUEST_TIMEOUT = 10.0
_SD_LISTEN_FDS_START = 3


class TaskError(Exception):
    """A task could not be done; the message is safe to show the admin."""


@dataclass
class Context:
    """What a task handler gets: the settings and the one model client."""

    settings: Settings
    client: ChatClient | None = None
    _model_lock: threading.Lock = field(default_factory=threading.Lock)

    def call_model(self, fn: Callable[[ChatClient], Any]) -> Any:
        """Run ``fn(client)`` if the model is free; never wait for it."""
        if not self.settings.enabled or self.client is None:
            raise TaskError("the AI-Perimeter is off (ai-perimeter.yaml: enabled: false)")
        if not self._model_lock.acquire(blocking=False):
            raise TaskError("busy: the model is answering another request")
        try:
            return fn(self.client)
        except ProviderError as exc:
            raise TaskError(str(exc)) from None
        finally:
            self._model_lock.release()


def _task_ping(ctx: Context, args: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True, "version": __version__}


def _task_status(ctx: Context, args: dict[str, Any]) -> dict[str, Any]:
    p = ctx.settings.provider
    if not ctx.settings.enabled or p is None:
        return {"enabled": False}
    return {"enabled": True, "provider": p.name, "model": p.model,
            "cloud": p.cloud}


#: Room for a reasoning model's thinking as well as the patch itself.
PROPOSE_MAX_TOKENS = 4096


def _task_propose_patch(ctx: Context, args: dict[str, Any]) -> dict[str, Any]:
    """A2: the admin's intent and the current (redacted) config in, a
    proposal out (orchestrator.pipeline). Nothing is saved here."""
    unknown = set(args) - {"intent", "config"}
    if unknown:
        raise TaskError(f"propose_patch: unknown argument {sorted(unknown)[0]!r}")

    def ask(messages: list[dict[str, str]]) -> tuple[str, str]:
        result = ctx.call_model(lambda c: c.chat(messages, max_tokens=PROPOSE_MAX_TOKENS))
        return result.text, result.reasoning

    try:
        return pipeline.propose(args.get("intent"), args.get("config"), ask).as_dict()
    except ValueError as exc:
        raise TaskError(str(exc)) from None


#: Task name -> handler. Later work packages register theirs here.
HANDLERS: dict[str, Callable[[Context, dict[str, Any]], dict[str, Any]]] = {
    "ping": _task_ping,
    "status": _task_status,
    "propose_patch": _task_propose_patch,
}


def allowed_uids() -> frozenset[int]:
    """Root, this service's own uid (a development run) and the webUI."""
    uids = {0, os.geteuid()}
    try:
        import pwd
        uids.add(pwd.getpwnam(fr_paths.WEBUI_USER).pw_uid)
    except KeyError:
        pass
    return frozenset(uids)


class _Handler(socketserver.StreamRequestHandler):
    server: "AssistServer"

    def handle(self) -> None:
        self.connection.settimeout(REQUEST_TIMEOUT)
        try:
            line = self.rfile.readline(MAX_LINE_BYTES + 1)
        except (TimeoutError, socket.timeout, OSError):
            return
        if not line:
            return
        try:
            reply = self._answer(line)
        except Exception:  # noqa: BLE001 - one request must not stop the service
            log.exception("task failed")
            reply = {"ok": False, "error": "internal error"}
        try:
            self.wfile.write(encode(reply))
        except ProtocolError:
            self.wfile.write(encode({"ok": False, "error": "answer too large"}))
        except OSError:
            pass

    def _answer(self, line: bytes) -> dict[str, Any]:
        if len(line) > MAX_LINE_BYTES:
            return {"ok": False, "error": "request too large"}
        if not line.endswith(b"\n"):
            return {"ok": False, "error": "incomplete request"}
        try:
            task, args = decode_request(line)
        except ProtocolError as exc:
            return {"ok": False, "error": str(exc)}
        handler = HANDLERS.get(task)
        if handler is None:
            return {"ok": False, "error": "unknown task"}
        try:
            return {"ok": True, "result": handler(self.server.context, args)}
        except TaskError as exc:
            return {"ok": False, "error": str(exc)}


class AssistServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, address: str | None, context: Context, *,
                 uids: frozenset[int] | None = None,
                 sock: socket.socket | None = None):
        self.context = context
        self.uids = allowed_uids() if uids is None else uids
        if sock is not None:
            # Socket activation: systemd already bound and listens.
            super().__init__(sock.getsockname(), _Handler, bind_and_activate=False)
            self.socket.close()
            self.socket = sock
        else:
            super().__init__(address, _Handler)

    def verify_request(self, request, client_address) -> bool:
        try:
            _pid, uid, _gid = peer_credentials(request)
        except OSError:
            return False
        if uid not in self.uids:
            log.warning("refused a connection from uid %d", uid)
            return False
        return True


def _systemd_socket() -> socket.socket | None:
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    if int(os.environ.get("LISTEN_FDS", "0")) < 1:
        return None
    return socket.socket(fileno=_SD_LISTEN_FDS_START)


def build_context(settings: Settings) -> Context:
    client = ChatClient(settings.provider) if settings.enabled and settings.provider else None
    return Context(settings=settings, client=client)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr-ai-assist")
    parser.add_argument("--config", default=str(DEFAULT_PATH))
    parser.add_argument("--socket", help="listen here instead of using systemd's socket")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        context = build_context(load_settings(args.config))
    except ConfigError as exc:
        log.error("%s", exc)
        return 1
    sock = None if args.socket else _systemd_socket()
    if sock is None and not args.socket:
        log.error("no socket: start it through fr-ai-assist.socket, or pass --socket")
        return 1
    server = AssistServer(args.socket, context, sock=sock)
    p = context.settings.provider
    log.info("serving; %s", f"provider {p.name}, model {p.model}" if p else "AI-Perimeter is off")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

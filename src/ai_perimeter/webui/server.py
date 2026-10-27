"""``fr-webui-ai``: FR_OS's own ``fr-webui``, with the AI-Perimeter screen.

Why a wrapper and not a patch to FR_OS: FR_OS compares its installed files
byte for byte with the signed release they came from (FR_OS
``frfw.integrity``, SEC-15) and reports any difference on its dashboard --
the mark a patched-in implant would leave. A router running the
AI-Perimeter must not look like that, so not one FR_OS file is changed:

- this runs FR_OS's ``frfw.webui.server.main`` unchanged (its arguments,
  TLS, listen addresses and uvicorn settings), and only adds the screen to
  the app ``main`` builds, through :func:`ai_perimeter.webui.register`;
- the sidebar entry is added in memory by ``register``;
- ``systemd/fr-webui.service.d/ai-perimeter.conf`` starts this instead of
  ``fr-webui``, keeping FR_OS's unit -- its account and sandbox -- as is.

It relies on one detail of FR_OS: ``server.main`` builds the app with the
module's ``create_app`` name. ``tests/test_webui.py`` runs ``main`` against
the pinned FR_OS, so a change there turns the test red instead of quietly
dropping the screen.
"""

from __future__ import annotations

import sys

from frfw.webui import server

from . import register


def _with_screen(create_app):
    def create_app_with_screen(*args, **kwargs):
        app = create_app(*args, **kwargs)
        register(app)
        return app

    create_app_with_screen.ai_perimeter = True
    return create_app_with_screen


def main(argv: list[str] | None = None) -> int:
    if not getattr(server.create_app, "ai_perimeter", False):
        server.create_app = _with_screen(server.create_app)
    return server.main(argv)


if __name__ == "__main__":
    sys.exit(main())

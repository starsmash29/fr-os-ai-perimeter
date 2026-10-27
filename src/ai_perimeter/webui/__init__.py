"""The AI-Perimeter screen in FR_OS's webUI (work package A3).

FR_OS calls :func:`register` from ``create_app`` when this package is
installed (integration/fr_os/0001-ai-perimeter-screen.patch); without the
package, FR_OS is unchanged.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from jinja2 import ChoiceLoader, FileSystemLoader

from frfw.webui.templating import templates

from ..assist_client import DEFAULT_TIMEOUT
from ..service import DEFAULT_SOCKET
from .routes import ProposalStore, router

TEMPLATES_DIR = Path(__file__).parent / "templates"


def register(app: FastAPI, *, socket_path: Path | str = DEFAULT_SOCKET,
             timeout: float = DEFAULT_TIMEOUT) -> None:
    """Add the screen's routes and templates to FR_OS's webUI app."""
    app.state.ai_perimeter_socket = Path(socket_path)
    app.state.ai_perimeter_timeout = timeout
    app.state.ai_perimeter_proposals = ProposalStore()
    loader = templates.env.loader
    if not (isinstance(loader, ChoiceLoader)
            and any(getattr(l, "searchpath", None) == [str(TEMPLATES_DIR)] for l in loader.loaders)):
        templates.env.loader = ChoiceLoader([loader, FileSystemLoader(str(TEMPLATES_DIR))])
    app.include_router(router)

"""The AI-Perimeter screen in FR_OS's webUI (work package A3).

``fr-webui-ai`` (:mod:`ai_perimeter.webui.server`) runs FR_OS's webUI and
calls :func:`register` on its app; no FR_OS file is changed, so FR_OS's
integrity check stays clean (SEC-15). Plain ``fr-webui`` is FR_OS without
the screen.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from jinja2 import ChoiceLoader, FileSystemLoader

from frfw.webui.templating import NAV, templates

from ..assist_client import DEFAULT_TIMEOUT
from ..incident.evidence import Sources
from ..service import DEFAULT_SOCKET
from .routes import PAGE, ProposalStore, router

TEMPLATES_DIR = Path(__file__).parent / "templates"
#: The sidebar entry, in FR_OS's (label, path, icon, admin_only) form. Not
#: admin-only: a viewer sees whether the AI-Perimeter is on, and which model.
NAV_ENTRY = ("AI-Perimeter", PAGE, "psychology", False)
NAV_SECTION = "Core"


def register(app: FastAPI, *, socket_path: Path | str = DEFAULT_SOCKET,
             timeout: float = DEFAULT_TIMEOUT, sources: Sources = Sources()) -> None:
    """Add the screen's routes, templates and sidebar entry to FR_OS's
    webUI app. Safe to call more than once in a process."""
    app.state.ai_perimeter_socket = Path(socket_path)
    app.state.ai_perimeter_timeout = timeout
    app.state.ai_perimeter_proposals = ProposalStore()
    app.state.ai_perimeter_sources = sources
    loader = templates.env.loader
    if not (isinstance(loader, ChoiceLoader)
            and any(getattr(l, "searchpath", None) == [str(TEMPLATES_DIR)] for l in loader.loaders)):
        templates.env.loader = ChoiceLoader([loader, FileSystemLoader(str(TEMPLATES_DIR))])
    for section, items in NAV:
        if section == NAV_SECTION and NAV_ENTRY not in items:
            items.append(NAV_ENTRY)
    app.include_router(router)

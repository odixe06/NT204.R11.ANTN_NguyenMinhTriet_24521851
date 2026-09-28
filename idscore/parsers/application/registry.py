from idscore.parsers.application.http import HTTPParser
from idscore.parsers.base import BaseParser


def build_app_parsers() -> dict[str, BaseParser]:
    """Map each ``app_protocol`` the detector reports to a fresh parser."""
    return {"HTTP": HTTPParser()}

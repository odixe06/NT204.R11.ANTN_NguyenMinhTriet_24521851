# file này dùng để ánh xạ tên giao thức (field protocol) 
# với parser để xử lý gói tin thuộc về giao thức đó

from typing import Any

from idscore.parsers.application.dns import DNSParser
from idscore.parsers.application.http import HTTPParser
from idscore.parsers.application.smtp import SMTPParser
from idscore.parsers.base import BaseParser

# trả về dict với key là tên giao thức, value là parser
def build_app_parsers(config: dict[str, Any]) -> dict[str, BaseParser]:
    """Map each ``app_protocol`` the detector reports to a fresh parser."""
    max_body_bytes = config["parser"]["max_body_bytes"]
    return {
        "HTTP": HTTPParser(max_body_bytes),
        "DNS": DNSParser(),
        "SMTP": SMTPParser(max_body_bytes),
    }

# file này dùng để ánh xạ tên giao thức (field protocol) 
# với parser để xử lý gói tin thuộc về giao thức đó

from idscore.parsers.application.dns import DNSParser
from idscore.parsers.application.http import HTTPParser
from idscore.parsers.application.smtp import SMTPParser
from idscore.parsers.base import BaseParser

# trả về dict với key là tên giao thức, value là parser
def build_app_parsers() -> dict[str, BaseParser]:
    """Map each ``app_protocol`` the detector reports to a fresh parser."""
    return {"HTTP": HTTPParser(), "DNS": DNSParser(), "SMTP": SMTPParser()}

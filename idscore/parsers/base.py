# file này định nghĩa interface chung cho mọi parser (network, transport, application)
# định nghĩa một lớp trừu tượng BaseParser
# code xử lý từng layer cụ thể nằm ở các file con, base.py chỉ giữ interface

from abc import ABC, abstractmethod

from scapy.packet import Packet

from idscore.models.event import Event


class BaseParser(ABC):
# pipeline chỉ gọi parser qua interface này, thêm parser mới không phải sửa pipeline
    @property
    @abstractmethod # nhãn này đánh dấu những thuộc tính/hàm bắt buộc có ở class con
    def name(self) -> str:
        """Parser identifier, e.g. ``ipv4`` or ``tcp``."""
        ...
    # dùng name để biết lỗi phát sinh ở tầng nào khi ghi vào event.errors

    @abstractmethod
    def can_parse(self, packet: Packet) -> bool:
        """Report whether this parser handles ``packet``."""
        ...
    # pipeline hỏi can_parse trước khi gọi parse
    # Lưu ý: packet ARP trả về False ở parser ipv4, pipeline gán UNKNOWN thay vì crash

    @abstractmethod
    def parse(self, packet: Packet, event: Event) -> None:
        """Fill the parser's fields into ``event`` in place.

        Contract: ``parse`` must never let an exception escape. On truncated or
        invalid headers, it appends a message to ``event.errors`` and downgrades
        ``event.parse_status`` to ``MALFORMED`` without building a new ``Event``
        """
        ...
   
    # scapy đọc packet bị cắt cụt mà không báo lỗi
    # parser báo exception thì cả chương trình dừng

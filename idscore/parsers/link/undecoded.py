# file này để xử lý các frame bị hỏng ở tầng data
# thay vì ethernet parser k đọc được -> gán unknown thì sẽ đem qua đây xử lý 
# để đánh dấu thành MALFORMED 

from scapy.packet import Packet, Raw

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

# kế thừa BaseParser
class UndecodedFrameParser(BaseParser):
    """Link-layer parser for frames scapy could not decode at all."""

    @property
    def name(self) -> str:
        return "frame"


    def can_parse(self, packet: Packet) -> bool:
        """Return True only when the outermost layer itself is ``Raw``."""
        try:
            # kiểm tra lớp ngoài cùng của packet có phải raw k
            return isinstance(packet, Raw)
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Report the undecodable frame, per the ``BaseParser.parse`` contract."""
        try:
            length = len(bytes(packet))

        # nếu đọc byte bị lỗi, thêm lỗi và gắn MALFORMED
        except Exception as exc:
            self._malformed(event, f"cannot read the frame: {exc!r}")
            return
        # k thì thông báo k để decode -> thông báo độ dài của frame
        self._malformed(event, f"cannot decode the link layer: frame is {length} bytes")

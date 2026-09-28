# file này định nghĩa interface chung cho mọi parser (network, transport, application)
# định nghĩa một lớp trừu tượng BaseParser
# code xử lý từng layer cụ thể nằm ở các file con

from abc import ABC, abstractmethod

from scapy.layers.inet import TCP, UDP
from scapy.packet import NoPayload, Packet, Padding

from idscore.models.event import Event


class BaseParser(ABC):
# pipeline chỉ gọi parser qua interface này, thêm parser mới thì kế thừa  
    @property
    @abstractmethod # đánh dấu thuộc tính/hàm bắt buộc có ở class con
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

    # helper hạ xuống MALFORMED và thông báo errors messages trong event
    def _malformed(self, event: Event, message: str) -> None:
        """Append a prefixed message to ``event.errors`` and drop to MALFORMED."""
        event.errors.append(f"{self.name}: {message}")
        event.parse_status = "MALFORMED"
    
    # helper trả về byte thô ở phía layer transport (layer application)
    def _payload_bytes(self, layer: Packet) -> bytes:
        """Raw bytes above ``layer`` with Ethernet ``Padding`` stripped, ``b""`` if none.

        Reads the bytes as captured, never the port-based layers scapy guesses
        (UDP 53 becomes ``DNS``), so detection stays independent of port.
        """
        payload = layer.payload
        # TH rỗng 
        if isinstance(payload, (NoPayload, Padding)): 
            return b"" # k trả về None để detector dễ kiểm tra
        raw = bytes(payload)
        # bỏ đi phần padding
        padding = payload.getlayer(Padding)
        if padding is not None:
            pad_len = len(bytes(padding))
            if pad_len:
                raw = raw[:-pad_len]
        return raw

    # helper lấy độ dài của đoạn payload_byte ở trên 
    def _payload_len(self, layer: Packet) -> int:
        """Length of ``_payload_bytes(layer)``."""
        return len(self._payload_bytes(layer))
    
    # helper tìm layer transport trong packet (TCP/UDP)
    def _transport_layer(self, packet: Packet) -> Packet | None:
        """Return the TCP or UDP layer of ``packet``, ``None`` when it has neither."""
        for layer_type in (TCP, UDP):
            if packet.haslayer(layer_type):
                return packet[layer_type]
        return None

    # helper chuyển dữ liệu từ bytes sang string bằng UTF-8
    def _decode(self, data: bytes) -> str:
        """Decode as UTF-8, marking undecodable bytes with U+FFFD instead of raising."""
        return data.decode("utf-8", errors="replace")

    # helper hạ từ OK xuống PARTIAL khi parser đọc được một phần dữ liệu không hoàn chỉnh
    def _partial(self, event: Event, message: str) -> None:
        """Append a prefixed message to ``event.errors`` and drop OK to PARTIAL."""
        event.errors.append(f"{self.name}: {message}")
        if event.parse_status == "OK":
            event.parse_status = "PARTIAL"

# đây là parser của tầng transport cho giao thức TCP
# điền các thông tin của tầng transport vào model event.py

from scapy.layers.inet import IP, TCP
from scapy.packet import NoPayload, Packet, Padding

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

TCP_MIN_HEADER_LEN = 20
IP_PROTO_TCP = 6

# thứ tự bit từ thấp lên cao, cố định để detection engine so chuỗi
TCP_FLAG_NAMES = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]


class TCPParser(BaseParser):
    """Transport-layer parser filling the TCP fields of an ``Event``."""

    @property #name đứng đầu errors messages
    def name(self) -> str:
        return "tcp" 

    def can_parse(self, packet: Packet) -> bool:
        """Return True for a TCP layer, or an unfragmented IPv4 packet with proto 6."""
        try:
            if packet.haslayer(TCP):
                return True
            if not packet.haslayer(IP):
                return False
            ip = packet[IP]
            return int(ip.proto) == IP_PROTO_TCP and int(ip.frag) == 0
        except Exception:
            return False
    # nhận cả packet ip.proto == 6 mà scapy không dựng được layer TCP
    # đó là packet bị cắt header TCP, phải ghi MALFORMED chứ k bỏ qua
    # frag == 0 vì các mảnh IP phía sau vốn không mang TCP header, đó là packet bình thường

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill the TCP fields in place, per the ``BaseParser.parse`` contract."""
        if not packet.haslayer(TCP):
            self._malformed(
                event,
                "ip_proto is TCP but the TCP header is missing or shorter than 20 bytes",
            )
            return

        try:
            tcp = packet[TCP]
            raw = bytes(tcp)
            header_len = int(tcp.dataofs) * 4
            event.transport_protocol = "TCP"
            event.src_port = int(tcp.sport)
            event.dst_port = int(tcp.dport)
            event.seq = int(tcp.seq)
            event.ack = int(tcp.ack)
            event.window = int(tcp.window)
            event.tcp_flags = self._flags_to_str(int(tcp.flags))
            event.payload_len = self._payload_len(tcp)
        except Exception as exc:
            self._malformed(event, f"cannot read TCP header: {exc!r}")
            return

        # data offset không hợp lệ: < 20 byte hoặc > số byte thực có
        if header_len < TCP_MIN_HEADER_LEN or header_len > len(raw):
            self._malformed(
                event,
                f"invalid dataofs: header is {header_len} bytes, captured {len(raw)}",
            )

    def _flags_to_str(self, flags: int) -> str:
        return "-".join(
            name for bit, name in enumerate(TCP_FLAG_NAMES) if flags & (1 << bit)
        )
    # không bật cờ nào thì ra "" -> nhận diện được NULL scan
    # không dùng str(tcp.flags) vì scapy trả dạng viết tắt như "SA"

    def _payload_len(self, tcp: TCP) -> int:
        payload = tcp.payload
        if isinstance(payload, (NoPayload, Padding)):
            return 0
        length = len(bytes(payload))
        padding = payload.getlayer(Padding)
        if padding is not None:
            length -= len(bytes(padding))
        return length
    # trừ phần Padding vì Ethernet đệm frame cho đủ 60 byte
    # không trừ thì mọi gói ACK rỗng đều bị tính là có payload

    def _malformed(self, event: Event, message: str) -> None:
        event.errors.append(f"{self.name}: {message}")
        event.parse_status = "MALFORMED"

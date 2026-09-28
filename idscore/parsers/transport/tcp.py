# đây là parser của tầng transport cho giao thức TCP
# điền các thông tin của tầng transport vào model event.py

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

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

    def can_parse(self, packet: Packet) -> bool: # kiểm tra gói tin có thuộc TCP k
        """Return True for a TCP layer, or an unfragmented IPv4 packet with proto 6."""
        try:
            # TH scapy bóc được layer TCP
            if packet.haslayer(TCP):
                return True
            # TH gói tin k có tầng IP
            if not packet.haslayer(IP):
                return False
            # TH ip proto  = 6 (nhưng phần TCP bị cắt ngắn) 
            # -> scapy không dựng được layer TCP
            # bỏ các mảnh IP k mang TCP header
            ip = packet[IP]
            return int(ip.proto) == IP_PROTO_TCP and int(ip.frag) == 0
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill the TCP fields in place, per the ``BaseParser.parse`` contract."""
        # TH những gói tin scapy k dựng được layer TCP
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
    
    # check từng bit trong header flag để xem các cờ nào được bật
    def _flags_to_str(self, flags: int) -> str:
        return "-".join(
            name for bit, name in enumerate(TCP_FLAG_NAMES) if flags & (1 << bit)
        )
    # không bật cờ nào thì ra "" -> nhận diện được NULL scan

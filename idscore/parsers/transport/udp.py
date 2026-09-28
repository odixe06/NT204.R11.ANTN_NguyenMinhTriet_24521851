# đây là file định nghĩa parser các packet udp ở tầng transport
# kế thừa từ base.py

from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

UDP_HEADER_LEN = 8
IP_PROTO_UDP = 17


class UDPParser(BaseParser):
    """Transport-layer parser filling the UDP fields of an ``Event``."""

    @property
    def name(self) -> str:
        return "udp" # name để gắn vào errors message

    # hàm can_parse, tương tự TCP
    def can_parse(self, packet: Packet) -> bool:
        """Return True for a UDP layer, or an unfragmented IPv4 packet with proto 17."""
        try:
            if packet.haslayer(UDP):
                return True
            if not packet.haslayer(IP):
                return False
            ip = packet[IP]
            return int(ip.proto) == IP_PROTO_UDP and int(ip.frag) == 0
        except Exception:
            return False  

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill the UDP fields in place, per the ``BaseParser.parse`` contract."""
        if not packet.haslayer(UDP):
            self._malformed(
                event,
                f"ip_proto is UDP but the UDP header is missing or shorter than {UDP_HEADER_LEN} bytes",
            )
            return

        try:
            udp = packet[UDP]
            raw = bytes(udp)
            declared_len = int(udp.len)
            event.transport_protocol = "UDP"
            event.src_port = int(udp.sport)
            event.dst_port = int(udp.dport)
            event.payload_len = self._payload_len(udp)
        except Exception as exc:
            self._malformed(event, f"cannot read UDP header: {exc!r}")
            return

        # TH tổng độ dài gói UDP trong khai báo < 8 
        if declared_len < UDP_HEADER_LEN:
            self._malformed(
                event,
                f"udp_len {declared_len} is smaller than the {UDP_HEADER_LEN}-byte header",
            )
            return

        # len khai báo trong header lớn hơn len gói tin thực tế
        if declared_len > len(raw):
            self._malformed(
                event,
                f"udp_len {declared_len} exceeds the {len(raw)} bytes captured",
            )

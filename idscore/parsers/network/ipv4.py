# đây là parser của tầng network, là parser đầu tiên trong piepline
# điền các thông tin của tầng network vào model event.py

from scapy.layers.inet import IP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

IPV4_MIN_HEADER_LEN = 20


class IPv4Parser(BaseParser): 
    """Network-layer parser filling the IPv4 fields of an ``Event``."""

    @property
    def name(self) -> str:
        return "ipv4"
    # name sẽ đứng đầu message trong event.errors -> xác định lỗi ở parser tầng nào

    def can_parse(self, packet: Packet) -> bool:
        """Return True only for packets carrying an IPv4 layer."""
        try:
            return bool(packet.haslayer(IP))
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill the IPv4 fields in place, per the ``BaseParser.parse`` contract."""
        try:
            ip = packet[IP]
            raw = bytes(ip)
            header_len = int(ip.ihl) * 4
            declared_len = int(ip.len)
            event.src_ip = ip.src
            event.dst_ip = ip.dst
            event.ip_version = int(ip.version)
            event.ttl = int(ip.ttl)
            event.ip_len = declared_len
            event.ip_id = int(ip.id)
            event.ip_proto = int(ip.proto)
            event.ip_flags = str(ip.flags) # "DF", "MF", "DF+MF", ""
            event.frag_offset = int(ip.frag) 
            # offset tính bằng đơn vị 8 byte 
        except Exception as exc:
            self._malformed(event, f"cannot read IPv4 header: {exc!r}")
            return

        # các trường hợp bị hạ xuống MALFORMED:

        # header không đủ 20 byte
        if len(raw) < IPV4_MIN_HEADER_LEN:
            self._malformed(
                event,
                f"IPv4 header truncated: {len(raw)} bytes < {IPV4_MIN_HEADER_LEN}",
            )
            return

        # internet header length không hợp lệ: < 20 hoặc > captured
        if header_len < IPV4_MIN_HEADER_LEN or header_len > len(raw):
            self._malformed(
                event,
                f"invalid ihl: header is {header_len} bytes, captured {len(raw)}",
            )
            return

        # ip khai báo packet dài hơn số byte thực tế, k return nhưng hạ xuống MALFORMED
        if declared_len > len(raw):
            self._malformed(
                event,
                f"ip_len {declared_len} exceeds the {len(raw)} bytes captured",
            )

    def _malformed(self, event: Event, message: str) -> None:
        event.errors.append(f"{self.name}: {message}")
        event.parse_status = "MALFORMED"
    # hàm hạ event xuống malformed và ghi message vào errors

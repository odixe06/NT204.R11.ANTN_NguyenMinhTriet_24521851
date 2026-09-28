# đây là parser ở tầng data link, điền các địa chỉ MAC
# class kế thừa từ base.py

from scapy.layers.l2 import Ether
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser


class EthernetParser(BaseParser):
    """Link-layer parser filling the Ethernet fields of an ``Event``."""

    @property
    def name(self) -> str:
        return "ethernet"

    def can_parse(self, packet: Packet) -> bool:
        """Return True only for packets carrying an Ethernet layer."""
        try:
            return bool(packet.haslayer(Ether))
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill the MAC fields in place, per the ``BaseParser.parse`` contract."""
        try:
            ether = packet[Ether]
            event.src_mac = ether.src
            event.dst_mac = ether.dst
        except Exception as exc:
            self._malformed(event, f"cannot read Ethernet header: {exc!r}")

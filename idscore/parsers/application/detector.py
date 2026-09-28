from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

HTTP_METHODS = (
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"TRACE",
    b"CONNECT",
)
HTTP_VERSION = b"HTTP/1."


class AppProtocolDetector(BaseParser):
    """Name the application protocol of a payload without looking at ports."""

    @property
    def name(self) -> str:
        return "app_detector"

    def can_parse(self, packet: Packet) -> bool:
        """Return True only when the TCP or UDP payload carries bytes."""
        try:
            layer = self._transport_layer(packet)
            return layer is not None and bool(self._payload_bytes(layer))
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Set ``app_protocol`` and ``detection_method``; nothing else changes."""
        try:
            layer = self._transport_layer(packet)
            if layer is None:
                return
            payload = self._payload_bytes(layer)
            protocol = self._detect(payload)
        except Exception as exc:
            self._malformed(event, f"cannot inspect the payload: {exc!r}")
            return

        if protocol is not None:
            event.app_protocol = protocol
            event.detection_method = "payload"

    def _transport_layer(self, packet: Packet) -> Packet | None:
        for layer_type in (TCP, UDP):
            if packet.haslayer(layer_type):
                return packet[layer_type]
        return None

    def _detect(self, payload: bytes) -> str | None:
        if self._is_http(payload):
            return "HTTP"
        return None

    def _is_http(self, payload: bytes) -> bool:
        if payload.startswith(HTTP_VERSION):
            return True

        first_line = payload.split(b"\n", 1)[0]
        return any(
            first_line.startswith(method + b" ") for method in HTTP_METHODS
        ) and HTTP_VERSION in first_line

from scapy.layers.inet import TCP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

HEADER_SEPARATOR = b"\r\n\r\n"
LINE_SEPARATOR = "\r\n"
HTTP_VERSION_PREFIX = "HTTP/"
REQUEST_PARTS = 3
STATUS_CODE_LEN = 3


class HTTPParser(BaseParser):
    """Application parser writing the HTTP fields of a segment into ``event.app``."""

    @property
    def name(self) -> str:
        return "http"

    def can_parse(self, packet: Packet) -> bool:
        """Return True for a TCP segment carrying payload bytes."""
        try:
            if not packet.haslayer(TCP):
                return False
            return bool(self._payload_bytes(packet[TCP]))
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill ``event.app``, per the ``BaseParser.parse`` contract."""
        try:
            layer = self._transport_layer(packet)
            if layer is None:
                return

            payload = self._payload_bytes(layer)
            head, separator, body = payload.partition(HEADER_SEPARATOR)
            lines = self._decode(head).split(LINE_SEPARATOR)

            start_line = self._start_line(lines[0])
            if start_line is None:
                event.app = {
                    "message_type": "continuation",
                    "body_len": len(payload),
                }
                return

            app = dict(start_line)
            app["headers"] = self._headers(lines[1:], event)
            app["body_len"] = len(body)
            event.app = app

            if not separator:
                self._partial(event, "header has no terminating CRLF CRLF")
        except Exception as exc:
            self._partial(event, f"cannot parse the HTTP message: {exc!r}")

    def _start_line(self, line: str) -> dict | None:
        if line.startswith(HTTP_VERSION_PREFIX):
            return self._response_line(line)
        return self._request_line(line)

    def _request_line(self, line: str) -> dict | None:
        parts = line.split(" ")
        if len(parts) != REQUEST_PARTS or not parts[2].startswith(HTTP_VERSION_PREFIX):
            return None
        return {
            "message_type": "request",
            "method": parts[0],
            "uri": parts[1],
            "version": parts[2],
        }

    def _response_line(self, line: str) -> dict | None:
        parts = line.split(" ", 2)
        if len(parts) < 2:
            return None

        code = parts[1]
        if len(code) != STATUS_CODE_LEN or not code.isdigit():
            return None

        return {
            "message_type": "response",
            "version": parts[0],
            "status_code": int(code),
            "reason": parts[2] if len(parts) == REQUEST_PARTS else "",
        }

    def _headers(self, lines: list[str], event: Event) -> dict:
        headers: dict[str, str] = {}
        for line in lines:
            if not line:
                continue

            name, separator, value = line.partition(":")
            if not separator:
                self._partial(event, f"header line without a colon: {line!r}")
                continue

            key = name.strip().lower()
            value = value.strip()
            headers[key] = f"{headers[key]}, {value}" if key in headers else value
        return headers

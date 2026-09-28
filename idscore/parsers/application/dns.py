from scapy.layers.inet import UDP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

DNS_HEADER_LEN = 12
QUESTION_TAIL_LEN = 4
LABEL_KIND_MASK = 0xC0
LABEL_KIND_PLAIN = 0x00
LABEL_KIND_POINTER = 0xC0
POINTER_VALUE_MASK = 0x3F
MAX_POINTER_JUMPS = 10
ROOT_NAME = "."

DNS_FLAG_BITS = (
    (10, "AA"),
    (9, "TC"),
    (8, "RD"),
    (7, "RA"),
)
QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


class DNSParser(BaseParser):
    """Application parser reading the DNS header and questions into ``event.app``."""

    @property
    def name(self) -> str:
        return "dns"

    def can_parse(self, packet: Packet) -> bool:
        """Return True for a UDP datagram carrying payload bytes."""
        try:
            if not packet.haslayer(UDP):
                return False
            return bool(self._payload_bytes(packet[UDP]))
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Fill ``event.app``, per the ``BaseParser.parse`` contract."""
        try:
            layer = self._transport_layer(packet)
            if layer is None:
                return

            payload = self._payload_bytes(layer)
            if len(payload) < DNS_HEADER_LEN:
                self._partial(
                    event,
                    f"payload is {len(payload)} bytes, shorter than the "
                    f"{DNS_HEADER_LEN}-byte header",
                )
                return

            app = self._header(payload)
            questions: list[dict] = []
            app["questions"] = questions
            event.app = app

            self._read_questions(payload, DNS_HEADER_LEN, app["qdcount"], questions)
        except Exception as exc:
            self._partial(event, f"cannot parse the DNS message: {exc!r}")

    def _header(self, payload: bytes) -> dict:
        flags = int.from_bytes(payload[2:4], "big")
        return {
            "transaction_id": int.from_bytes(payload[0:2], "big"),
            "message_type": "response" if flags >> 15 else "query",
            "opcode": (flags >> 11) & 0x0F,
            "rcode": flags & 0x0F,
            "flags": "-".join(
                label for bit, label in DNS_FLAG_BITS if flags >> bit & 1
            ),
            "qdcount": int.from_bytes(payload[4:6], "big"),
            "ancount": int.from_bytes(payload[6:8], "big"),
            "nscount": int.from_bytes(payload[8:10], "big"),
            "arcount": int.from_bytes(payload[10:12], "big"),
        }

    def _read_questions(
        self, payload: bytes, offset: int, qdcount: int, questions: list[dict]
    ) -> int:
        for _ in range(qdcount):
            name, offset = self._read_name(payload, offset)
            if offset + QUESTION_TAIL_LEN > len(payload):
                raise ValueError(f"question is cut at offset {offset}")

            question = {
                "name": name,
                "qtype": int.from_bytes(payload[offset:offset + 2], "big"),
                "qclass": int.from_bytes(payload[offset + 2:offset + 4], "big"),
            }
            qtype_name = QTYPE_NAMES.get(question["qtype"])
            if qtype_name is not None:
                question["qtype_name"] = qtype_name

            questions.append(question)
            offset += QUESTION_TAIL_LEN
        return offset

    def _read_name(self, payload: bytes, offset: int) -> tuple[str, int]:
        """Read one domain name, following at most ``MAX_POINTER_JUMPS`` pointers."""
        labels: list[str] = []
        after_pointer = None
        jumps = 0

        while True:
            if offset >= len(payload):
                raise ValueError(f"name exceeds payload at offset {offset}")

            length = payload[offset]
            kind = length & LABEL_KIND_MASK

            if kind == LABEL_KIND_POINTER:
                if offset + 1 >= len(payload):
                    raise ValueError(f"pointer exceeds payload at offset {offset}")

                jumps += 1
                if jumps > MAX_POINTER_JUMPS:
                    raise ValueError(f"too many compression pointers at offset {offset}")

                if after_pointer is None:
                    after_pointer = offset + 2
                offset = ((length & POINTER_VALUE_MASK) << 8) | payload[offset + 1]
                continue

            if kind != LABEL_KIND_PLAIN:
                raise ValueError(f"reserved label length at offset {offset}")

            if length == 0:
                offset += 1
                break

            end = offset + 1 + length
            if end > len(payload):
                raise ValueError(f"label exceeds payload at offset {offset}")

            labels.append(self._decode(payload[offset + 1:end]))
            offset = end

        name = ".".join(labels) if labels else ROOT_NAME
        return name, after_pointer if after_pointer is not None else offset

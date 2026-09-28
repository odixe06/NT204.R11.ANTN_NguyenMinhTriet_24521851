# file này là parser của dns
# trích thông tin từ packet để ghi vào field app của event

import ipaddress

from scapy.layers.inet import UDP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

DNS_HEADER_LEN = 12

# sau QNAME của question còn qtype 2 byte và qclass 2 byte
QUESTION_TAIL_LEN = 4
LABEL_KIND_MASK = 0xC0
LABEL_KIND_PLAIN = 0x00
LABEL_KIND_POINTER = 0xC0
POINTER_VALUE_MASK = 0x3F
MAX_POINTER_JUMPS = 10
MAX_NAME_LEN = 255
RECORD_FIXED_LEN = 10
MX_PREFERENCE_LEN = 2
IPV4_RDLENGTH = 4
IPV6_RDLENGTH = 16

# mã các DNS Record
TYPE_A = 1
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
NAME_TYPES = frozenset({2, 5, 12})
ROOT_NAME = "."

DNS_FLAG_BITS = (
    (10, "AA"),
    (9, "TC"),
    (8, "RD"),
    (7, "RA"),
)
TYPE_NAMES = {
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

    # kiểm tra có parse được k
    def can_parse(self, packet: Packet) -> bool:
        """Return True for a UDP datagram carrying payload bytes."""
        try:
            # kiểm tra packet udp và có payload udp k
            if not packet.haslayer(UDP):
                return False
            return bool(self._payload_bytes(packet[UDP]))
        except Exception:
            return False

    # parse thông tin vào dict
    def parse(self, packet: Packet, event: Event) -> None:
        """Fill ``event.app``, per the ``BaseParser.parse`` contract."""
        try:
            layer = self._transport_layer(packet)
            if layer is None:
                return

            payload = self._payload_bytes(layer)
            # nếu payload nhỏ hơn 12 byte -> parser k đủ dữ liệu để đọc header
            if len(payload) < DNS_HEADER_LEN:
                # hạ xuống partial
                self._partial(
                    event,
                    f"payload is {len(payload)} bytes, shorter than the "
                    f"{DNS_HEADER_LEN}-byte header",
                )
                return

            # đọc header và điền vào dict
            app = self._header(payload)
            questions: list[dict] = []
            app["questions"] = questions
            event.app = app

            offset = self._read_questions(
                payload, DNS_HEADER_LEN, app["qdcount"], questions
            )

            answers: list[dict] = []
            app["answers"] = answers
            self._read_answers(payload, offset, app["ancount"], answers)
        except Exception as exc:
            self._partial(event, f"cannot parse the DNS message: {exc!r}")

    # hàm đọc header
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
            qtype_name = TYPE_NAMES.get(question["qtype"])
            if qtype_name is not None:
                question["qtype_name"] = qtype_name

            questions.append(question)
            offset += QUESTION_TAIL_LEN
        return offset

    def _read_answers(
        self, payload: bytes, offset: int, ancount: int, answers: list[dict]
    ) -> int:
        """Read the answer section; authority and additional records are skipped."""
        for _ in range(ancount):
            name, offset = self._read_name(payload, offset)
            if offset + RECORD_FIXED_LEN > len(payload):
                raise ValueError(f"record header is cut at offset {offset}")

            record_type = int.from_bytes(payload[offset:offset + 2], "big")
            rdlength = int.from_bytes(payload[offset + 8:offset + 10], "big")
            rdata_start = offset + RECORD_FIXED_LEN
            if rdata_start + rdlength > len(payload):
                raise ValueError(
                    f"rdata of {rdlength} bytes exceeds payload at offset {rdata_start}"
                )

            answer = {
                "name": name,
                "type": record_type,
                "class": int.from_bytes(payload[offset + 2:offset + 4], "big"),
                "ttl": int.from_bytes(payload[offset + 4:offset + 8], "big"),
            }
            type_name = TYPE_NAMES.get(record_type)
            if type_name is not None:
                answer["type_name"] = type_name
            answer.update(self._rdata(payload, record_type, rdata_start, rdlength))

            answers.append(answer)
            offset = rdata_start + rdlength
        return offset

    def _rdata(
        self, payload: bytes, record_type: int, start: int, rdlength: int
    ) -> dict:
        """Decode rdata into a string; names are read against the whole message."""
        end = start + rdlength

        if record_type == TYPE_A:
            if rdlength != IPV4_RDLENGTH:
                raise ValueError(f"A record has rdlength {rdlength}, not {IPV4_RDLENGTH}")
            return {"rdata": str(ipaddress.IPv4Address(payload[start:end]))}

        if record_type == TYPE_AAAA:
            if rdlength != IPV6_RDLENGTH:
                raise ValueError(
                    f"AAAA record has rdlength {rdlength}, not {IPV6_RDLENGTH}"
                )
            return {"rdata": str(ipaddress.IPv6Address(payload[start:end]))}

        if record_type in NAME_TYPES:
            name, _ = self._read_name(payload, start)
            return {"rdata": name}

        if record_type == TYPE_MX:
            if rdlength < MX_PREFERENCE_LEN:
                raise ValueError(f"MX record has rdlength {rdlength}, too short")
            name, _ = self._read_name(payload, start + MX_PREFERENCE_LEN)
            return {
                "preference": int.from_bytes(
                    payload[start:start + MX_PREFERENCE_LEN], "big"
                ),
                "rdata": name,
            }

        if record_type == TYPE_TXT:
            return {"rdata": self._read_txt(payload, start, end)}

        return {"rdata": payload[start:end].hex()}

    def _read_txt(self, payload: bytes, start: int, end: int) -> str:
        parts = []
        offset = start
        while offset < end:
            length = payload[offset]
            offset += 1
            if offset + length > end:
                raise ValueError(f"TXT string exceeds rdata at offset {offset}")
            parts.append(self._decode(payload[offset:offset + length]))
            offset += length
        return "".join(parts)

    def _read_name(self, payload: bytes, offset: int) -> tuple[str, int]:
        """Read one domain name, following at most ``MAX_POINTER_JUMPS`` pointers."""
        labels: list[str] = []
        after_pointer = None
        jumps = 0
        used = 0

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

            used += 1 + length
            if used > MAX_NAME_LEN:
                raise ValueError(f"name is longer than {MAX_NAME_LEN} bytes at offset {offset}")

            labels.append(self._decode(payload[offset + 1:end]))
            offset = end

        name = ".".join(labels) if labels else ROOT_NAME
        return name, after_pointer if after_pointer is not None else offset

from scapy.layers.inet import TCP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.application.detector import (
    SMTP_CODE_LEN,
    SMTP_MAX_CODE,
    SMTP_MIN_CODE,
    SMTP_VERBS,
)
from idscore.parsers.base import BaseParser

CRLF = b"\r\n"
VERB_NAMES = frozenset(verb.decode() for verb in SMTP_VERBS)
ADDRESS_VERBS = frozenset({"MAIL", "RCPT"})
CONTINUATION_MARK = "-"


class SMTPParser(BaseParser):
    """Application parser writing the SMTP fields of a segment into ``event.app``."""

    @property
    def name(self) -> str:
        return "smtp"

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
            raw_lines = payload.split(CRLF)
            terminated = raw_lines[-1] == b""
            if terminated:
                raw_lines = raw_lines[:-1]
            lines = [self._decode(line) for line in raw_lines]

            if not lines or self._is_data(lines[0]):
                event.app = {"message_type": "data", "data_len": len(payload)}
                return

            if self._reply_code(lines[0]) is not None:
                event.app = self._response(lines, event)
            else:
                event.app = self._commands(lines, event)

            if not terminated:
                self._partial(event, "last line has no terminating CRLF")
        except Exception as exc:
            self._partial(event, f"cannot parse the SMTP message: {exc!r}")

    def _is_data(self, line: str) -> bool:
        return self._reply_code(line) is None and self._verb(line) is None

    def _commands(self, lines: list[str], event: Event) -> dict:
        commands = []
        for line in lines:
            parsed = self._verb(line)
            if parsed is None:
                self._partial(event, f"line is not an SMTP command: {line!r}")
                continue

            verb, argument = parsed
            command = {"verb": verb, "argument": argument}
            if verb in ADDRESS_VERBS:
                address = self._address(argument)
                if address is not None:
                    command["address"] = address
            commands.append(command)
        return {"message_type": "command", "commands": commands}

    def _response(self, lines: list[str], event: Event) -> dict:
        code = None
        messages = []
        final = False

        for line in lines:
            line_code = self._reply_code(line)
            if line_code is None:
                self._partial(event, f"line is not an SMTP reply: {line!r}")
                continue

            if code is None:
                code = line_code
            elif line_code != code:
                self._partial(event, f"reply code {line_code} differs from {code}")

            rest = line[SMTP_CODE_LEN:]
            final = not rest.startswith(CONTINUATION_MARK)
            messages.append(rest[1:].strip() if rest else "")

        return {
            "message_type": "response",
            "code": code,
            "messages": messages,
            "final": final,
        }

    def _reply_code(self, line: str) -> int | None:
        code = line[:SMTP_CODE_LEN]
        if len(code) != SMTP_CODE_LEN or not (code.isascii() and code.isdigit()):
            return None
        if not SMTP_MIN_CODE <= ord(code[0]) <= SMTP_MAX_CODE:
            return None

        rest = line[SMTP_CODE_LEN:]
        if rest and rest[0] not in (" ", CONTINUATION_MARK):
            return None
        return int(code)

    def _verb(self, line: str) -> tuple[str, str] | None:
        verb, _, argument = line.partition(" ")
        name = verb.upper()
        if name not in VERB_NAMES:
            return None
        return name, argument.strip()

    def _address(self, argument: str) -> str | None:
        start = argument.find("<")
        end = argument.find(">", start + 1)
        if start == -1 or end == -1:
            return None
        return argument[start + 1:end]

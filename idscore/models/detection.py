# schema cho detection event, kết quả khi matching engine khớp một rule với một event
# có to_dict() để dùng lại JsonlWriter cho alert/logging

from dataclasses import dataclass, field

HEX_SEPARATOR = " "
# byte in được nhưng có nghĩa đặc biệt trong cú pháp content, phải viết dạng hex
PATTERN_RESERVED = frozenset(b'|";\\')


def format_pattern(pattern: bytes) -> str:
    """Readable form of ``pattern`` as written in a rule: ASCII as is, the rest as ``|41 42|``."""
    parts: list[str] = []
    hex_run: list[str] = []
    for byte in pattern:
        if 0x20 <= byte < 0x7F and byte not in PATTERN_RESERVED:
            if hex_run:
                parts.append(f"|{HEX_SEPARATOR.join(hex_run)}|")
                hex_run = []
            parts.append(chr(byte))
        else:
            hex_run.append(f"{byte:02X}")
    if hex_run:
        parts.append(f"|{HEX_SEPARATOR.join(hex_run)}|")
    return "".join(parts)


@dataclass
class ContentMatch:
    pattern: bytes # content đã match
    buffer: str # buffer hoặc field đã match, ví dụ "payload"
    start: int # vị trí byte bắt đầu trong buffer
    end: int # vị trí byte kết thúc (không tính) trong buffer

    def to_dict(self) -> dict:
        return {
            "content": format_pattern(self.pattern),
            "buffer": self.buffer,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class DetectionEvent:
    packet_id: int # tra ngược về dòng trong events.jsonl
    timestamp: float # lấy từ event, không phải giờ hệ thống
    sid: int
    rev: int
    msg: str

    priority: int | None = None
    classtype: str | None = None

    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    application_protocol: str | None = None
    flow_id: str | None = None

    matches: list[ContentMatch] = field(default_factory=list)

    def to_dict(self) -> dict:
        # khác Event.to_dict: luôn giữ đủ key, thiếu giá trị thì ghi null,
        # để schema của detection event cố định cho alert/logging
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "sid": self.sid,
            "rev": self.rev,
            "msg": self.msg,
            "priority": self.priority,
            "classtype": self.classtype,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "flow_id": self.flow_id,
            "matches": [match.to_dict() for match in self.matches],
        }

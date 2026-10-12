# file này định nghĩa các hàm kiểm tra tính hợp lệ của các field trong event
import ipaddress
import math
from typing import Any

from idscore.models.event import (
    DECODE_FAILED,
    DECODE_PARTIAL,
    PARSE_MALFORMED,
    PARSE_PARTIAL,
    PARSE_UNKNOWN,
    PREPROCESS_INVALID,
    PREPROCESS_PARTIAL,
    UNKNOWN_APP_PROTOCOL,
    Event,
)

# trả về một cặp [status, reason]
Issue = tuple[str, str]

SOURCE_TYPES = frozenset({"pcap", "live"})
TRANSPORT_IP_PROTO = {"TCP": 6, "UDP": 17}
TCP_APP_PROTOCOLS = frozenset({"HTTP", "SMTP"})
UDP_APP_PROTOCOLS = frozenset({"DNS"})
VALID_APP_PROTOCOLS = TCP_APP_PROTOCOLS | UDP_APP_PROTOCOLS | {UNKNOWN_APP_PROTOCOL}
MIN_PORT = 0
MAX_PORT = 65535

# mỗi hàm đều nhận 1 event -> trả về 1 cặp status:reason
# không sửa event

# phải kiểm tra toàn bộ các điều kiện, k dừng lại dù gặp lỗi
# -> đưa ra reason đầy đủ

# 2 mức trạng thái:
# invalid: thiếu hoặc sai field mà flow tracker cần
# partial: các field ổn nhưng nội dung k đủ hoặc thiếu nhất quán

# trả về danh sách các lí do ở từng nhóm field một
def validate_event(event: Event) -> list[Issue]:
    issues = validate_metadata(event)
    if event.parse_status != PARSE_UNKNOWN:
        issues += validate_network(event)
        issues += validate_transport(event)
    issues += validate_consistency(event)
    issues += validate_inherited(event)
    return issues



def check_supported(event: Event) -> str | None:
    # nếu parse status unknown -> unsupported (ipv6, arp...)
    if event.parse_status == PARSE_UNKNOWN:
        return f"unsupported: parse_status {event.parse_status}"

    ip_version = event.ip_version
    if ip_version is not None and (not _is_int(ip_version) or ip_version != 4):
        return f"unsupported: ip_version {ip_version!r}"

    for name in ("src_ip", "dst_ip"):
        value = getattr(event, name)
        if isinstance(value, str) and _is_ipv6(value):
            return f"unsupported: {name} is IPv6 {value!r}"
    return None

# app protocol unknown thì k xem là unsupported

def validate_metadata(event: Event) -> list[Issue]:
    issues: list[Issue] = []

    packet_id = event.packet_id
    if not _is_int(packet_id) or packet_id <= 0:
        issues.append(
            (PREPROCESS_INVALID, f"packet_id: not a positive integer {packet_id!r}")
        )

    timestamp = event.timestamp
    if not isinstance(timestamp, float):
        issues.append((PREPROCESS_INVALID, f"timestamp: not a float {timestamp!r}"))
    elif not math.isfinite(timestamp):
        issues.append((PREPROCESS_INVALID, f"timestamp: not finite {timestamp!r}"))
    elif timestamp < 0:
        issues.append((PREPROCESS_INVALID, f"timestamp: negative {timestamp!r}"))

    source_type = event.source_type
    if not isinstance(source_type, str) or source_type not in SOURCE_TYPES:
        issues.append(
            (PREPROCESS_INVALID, f"source_type: unsupported value {source_type!r}")
        )
    return issues


def validate_network(event: Event) -> list[Issue]:
    issues: list[Issue] = []
    for name in ("src_ip", "dst_ip"):
        problem = _ip_problem(getattr(event, name))
        if problem:
            issues.append((PREPROCESS_INVALID, f"{name}: {problem}"))
    return issues


def validate_transport(event: Event) -> list[Issue]:
    issues: list[Issue] = []

    protocol = event.transport_protocol
    known_protocol = isinstance(protocol, str) and protocol in TRANSPORT_IP_PROTO
    if protocol is None:
        issues.append((PREPROCESS_INVALID, "transport_protocol: missing"))
    elif not known_protocol:
        issues.append(
            (PREPROCESS_INVALID, f"transport_protocol: unsupported value {protocol!r}")
        )

    for name in ("src_port", "dst_port"):
        problem = _port_problem(getattr(event, name))
        if problem:
            issues.append((PREPROCESS_INVALID, f"{name}: {problem}"))

    ip_proto = event.ip_proto
    if ip_proto is not None and known_protocol:
        expected = TRANSPORT_IP_PROTO[protocol]
        if not _is_int(ip_proto) or ip_proto != expected:
            issues.append(
                (
                    PREPROCESS_INVALID,
                    f"ip_proto: {ip_proto!r} does not match "
                    f"transport_protocol {protocol!r}",
                )
            )
    return issues


def validate_consistency(event: Event) -> list[Issue]:
    issues: list[Issue] = []
    protocol = event.transport_protocol
    app_protocol = event.app_protocol

    if app_protocol is not None:
        if not isinstance(app_protocol, str) or app_protocol not in VALID_APP_PROTOCOLS:
            issues.append(
                (PREPROCESS_PARTIAL, f"app_protocol: unsupported value {app_protocol!r}")
            )
        elif protocol == "UDP" and app_protocol in TCP_APP_PROTOCOLS:
            issues.append(
                (PREPROCESS_PARTIAL, f"app_protocol: {app_protocol!r} over UDP")
            )
        elif protocol == "TCP" and app_protocol in UDP_APP_PROTOCOLS:
            issues.append(
                (PREPROCESS_PARTIAL, f"app_protocol: {app_protocol!r} over TCP")
            )

    if protocol == "TCP" and event.tcp_flags is None:
        issues.append((PREPROCESS_PARTIAL, "tcp_flags: missing on a TCP event"))
    return issues


def validate_inherited(event: Event) -> list[Issue]:
    issues: list[Issue] = []
    if event.parse_status == PARSE_MALFORMED:
        issues.append((PREPROCESS_INVALID, f"parse_status: {event.parse_status}"))
    elif event.parse_status == PARSE_PARTIAL:
        issues.append((PREPROCESS_PARTIAL, f"parse_status: {event.parse_status}"))

    if event.decode_status in (DECODE_PARTIAL, DECODE_FAILED):
        issues.append((PREPROCESS_PARTIAL, f"decode_status: {event.decode_status}"))
    return issues


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _ip_problem(value: Any) -> str | None:
    if value is None:
        return "missing"
    if not isinstance(value, str):
        return f"not a string {value!r}"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return f"invalid address {value!r}"
    return None


def _port_problem(value: Any) -> str | None:
    if value is None:
        return "missing"
    if not _is_int(value):
        return f"not an integer {value!r}"
    if not MIN_PORT <= value <= MAX_PORT:
        return f"out of range {value!r}"
    return None

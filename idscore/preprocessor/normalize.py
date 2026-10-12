# file này định nghĩa quy trình chuẩn hóa các field trong event

import ipaddress
import math
from typing import Any

from idscore.models.event import Event
from idscore.parsers.application.dns import NAME_TYPES, ROOT_NAME

PATH_SEPARATOR = "/"
QUERY_SEPARATOR = "?"
HEADER_VALUE_SEPARATOR = ", "
IPV6_LITERAL_START = "["
IPV6_LITERAL_END = "]"
HOST_HEADER = "host"
MESSAGE_COLLECTIONS: dict[tuple[str, str | None], tuple[tuple[str, type], ...]] = {
    ("HTTP", "request"): (("headers", dict),),
    ("HTTP", "response"): (("headers", dict),),
    ("DNS", None): (("questions", list), ("answers", list)),
    ("SMTP", "command"): (("commands", list),),
    ("SMTP", "response"): (("messages", list),),
}

# dùng để fill các field k có giá trị
def fill_missing(event: Event) -> None:
    # error hoặc reason là none -> chuyển về []
    if event.errors is None:
        event.errors = []
    if event.reason is None:
        event.reason = []

    # nếu app là dict
    app = event.app
    if not isinstance(app, dict):
        return

    # xóa các key có giá trị none
    for key in [key for key, value in app.items() if value is None]:
        del app[key]

    # bổ sung các giá trị trong dict theo chuẩn sau
    # (chỉ bổ sung khi thiếu hoặc none, giá trị sai giữ)
    # chuỗi rỗng giữ nguyên
    protocol = normalize_protocol(event.app_protocol)
    message_type = app.get("message_type")
    if protocol == "DNS":
        message_type = None
    if not isinstance(protocol, str) or not (
        message_type is None or isinstance(message_type, str)
    ):
        return

    for key, factory in MESSAGE_COLLECTIONS.get((protocol, message_type), ()):
        app.setdefault(key, factory())

# quy tắc chung: nếu input k hợp lệ
# trả về giá trị ban đầu

# chuẩn hóa tên giao thức, input là 1 protocol
# xóa trắng -> in hoa
def normalize_protocol(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return value.strip().upper()

# chuẩn hóa IP, input là 1 IP
def normalize_ip(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value

# chuẩn hóa 1 domain
# xóa trắng -> viết thường
def normalize_domain(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    lowered = value.strip().lower()
    trimmed = lowered.rstrip(".")
    return trimmed if trimmed else lowered

# chuẩn hóa HTTP Host Header
def normalize_host(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    parts = [_normalize_host_part(part) for part in value.split(",")]
    return HEADER_VALUE_SEPARATOR.join(parts)

# chuẩn hóa dict chứa HTTP header
def normalize_headers(headers: Any) -> Any:
    if not isinstance(headers, dict):
        return headers

    merged: dict[Any, Any] = {}
    for key, value in headers.items():
        name = key.strip().lower() if isinstance(key, str) else key
        if name in merged and isinstance(merged[name], str) and isinstance(value, str):
            merged[name] = f"{merged[name]}{HEADER_VALUE_SEPARATOR}{value}"
        else:
            merged[name] = value

    if HOST_HEADER in merged:
        merged[HOST_HEADER] = normalize_host(merged[HOST_HEADER])
    return merged

# chuẩn hóa URI
def normalize_uri_path(uri: Any) -> Any:
    if not isinstance(uri, str) or not uri.startswith(PATH_SEPARATOR):
        return uri

    path, separator, query = uri.partition(QUERY_SEPARATOR)
    segments = path.split(PATH_SEPARATOR)[1:]
    stack: list[str] = []
    trailing = False
    for index, segment in enumerate(segments):
        is_last = index == len(segments) - 1
        if segment in ("", "."):
            trailing = is_last
        elif segment == "..":
            if stack:
                stack.pop()
            trailing = is_last
        else:
            stack.append(segment)
            trailing = False

    normalized = PATH_SEPARATOR + PATH_SEPARATOR.join(stack)
    if trailing and stack:
        normalized += PATH_SEPARATOR
    return f"{normalized}{separator}{query}"

# chuẩn hóa timestamp thành float
def normalize_timestamp(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return value
    try:
        result = float(value.strip() if isinstance(value, str) else value)
    except (ValueError, OverflowError):
        return value
    return result if math.isfinite(result) else value

# chuẩn hóa domain trong DNS event
def normalize_dns_names(app: dict) -> None:
    for key in ("questions", "answers"):
        records = app.get(key)
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            if "name" in record:
                record["name"] = normalize_domain(record["name"])
            record_type = record.get("type")
            is_name_type = isinstance(record_type, int) and record_type in NAME_TYPES
            if key == "answers" and is_name_type and "rdata" in record:
                record["rdata"] = normalize_domain(record["rdata"])

# chuẩn hóa host riêng lẻ 
def _normalize_host_part(part: str) -> str:
    text = part.strip()
    if text.startswith(IPV6_LITERAL_START):
        end = text.find(IPV6_LITERAL_END)
        if end == -1:
            return text.lower()
        return text[: end + 1].lower() + text[end + 1 :]

    if text.count(":") == 1:
        host, colon, port = text.partition(":")
        return f"{normalize_domain(host)}{colon}{port}"
    return normalize_domain(text)

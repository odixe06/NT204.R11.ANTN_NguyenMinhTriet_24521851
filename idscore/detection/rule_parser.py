# file này là Rule Parser & Validator: chuyển một dòng rule thành một Rule
# hợp đồng của module; Phase 3 đang viết dần phần parse (hiện có: khung, tách header/options, parse header)
#
# chiều phụ thuộc: rule_parser chỉ dùng idscore.models.rule, không import module khác trong detection/
#
# input : một dòng text, source_file, line_no
# output: một Rule (idscore.models.rule.Rule), luôn trả về kể cả khi lỗi:
#   - valid       : đủ cú pháp và nằm trong phạm vi hỗ trợ
#   - invalid     : sai cú pháp hoặc vi phạm quy ước, ví dụ rule ip có port khác any,
#                   thiếu sid hoặc msg; ghi lý do vào Rule.reasons
#   - unsupported : đúng cú pháp Snort nhưng dùng keyword/cú pháp ngoài phạm vi,
#                   ví dụ !, list [...], biến $HOME_NET
#   Rule luôn mang source_file, line_no, raw để cảnh báo chỉ ra rule nằm ở đâu
#
# việc của rule_parser:
#   - parse IP, port, content (đổi |hex| sang bytes) một lần, để matcher không parse lại
#   - điền Rule.sid cả khi rule invalid/unsupported vì lý do khác, nếu sid đọc được,
#     để loader tắt được rule hỏng bằng detection.disabled_sids
#
# rule_parser KHÔNG được:
#   - raise exception ra ngoài vì một dòng sai
#   - đọc file, in hoặc ghi log (việc của loader)
#   - đụng tới Event, FlowContext hay DetectionEvent

import re
from ipaddress import IPv4Network
from typing import NamedTuple

from idscore.models.rule import (
    RULE_DIRECTIONS,
    RULE_INVALID,
    RULE_PROTO_IP,
    RULE_PROTO_TCP,
    RULE_PROTO_UDP,
    RULE_UNSUPPORTED,
    RULE_VALID,
    PortRange,
    Rule,
)

HEADER_OPTIONS_OPEN = "("
OPTIONS_CLOSE = ")"
OPTION_SEPARATOR = ";"
KEYWORD_SEPARATOR = ":"
QUOTE = '"'
ESCAPE = "\\"

HEADER_TOKENS = 7
ACTION_ALERT = "alert"
# action có thật trong Snort nhưng ngoài phạm vi (đề chỉ yêu cầu alert)
UNSUPPORTED_ACTIONS = frozenset({"log", "pass", "drop", "reject", "sdrop"})
PROTOCOLS = {"tcp": RULE_PROTO_TCP, "udp": RULE_PROTO_UDP, "ip": RULE_PROTO_IP}
UNSUPPORTED_PROTOCOLS = frozenset({"icmp"})
ANY = "any"
PORT_MAX = 65535
# a.b.c.d hoặc a.b.c.d/n; IPv4Network còn nhận netmask (10.0.0.0/255.0.0.0), rộng hơn CIDR của đề
IPV4_PATTERN = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?")
# [0-9] thay vì \d / isdigit / int(): tránh "+80", "8_0", "²"
PORT_NUMBER = re.compile(r"[0-9]+")
PORT_RANGE = re.compile(r"([0-9]*):([0-9]*)")


# bộ ghi lỗi của một lần parse: các bước chỉ ghi lỗi vào đây và đi tiếp, không return sớm,
# để vẫn đọc được sid khi rule hỏng ở chỗ khác và người viết rule thấy đủ lỗi trong một lượt
class _Problems:
    def __init__(self) -> None:
        self.invalid: list[str] = []
        self.unsupported: list[str] = []

    def add_invalid(self, message: str) -> None:
        self.invalid.append(message)

    def add_unsupported(self, message: str) -> None:
        self.unsupported.append(message)

    # sai cú pháp được ưu tiên hơn ngoài phạm vi; lý do invalid đứng trước unsupported
    @property
    def status(self) -> str:
        if self.invalid:
            return RULE_INVALID
        if self.unsupported:
            return RULE_UNSUPPORTED
        return RULE_VALID

    @property
    def reasons(self) -> list[str]:
        return self.invalid + self.unsupported


# một option đã tách: index đếm từ 1 theo thứ tự khai báo, dùng để ghi lý do "option #5"
# value giữ nguyên text gốc (cả ngoặc kép và \), chưa unescape; None nếu không có dấu ":"
class _Option(NamedTuple):
    index: int
    keyword: str
    value: str | None


# tách header và options body
# header là phần trước "(" đầu tiên (header Snort không chứa "("), body là phần giữa "(" đầu
# và ")" cuối (content có thể chứa ")"). Rule nhiều dòng bằng \ cuối dòng rơi vào trường hợp
# không kết thúc bằng ")". Trả body None khi không có "(" nên không có options để đọc
def _split_header_options(line: str, problems: _Problems) -> tuple[str, str | None]:
    open_at = line.find(HEADER_OPTIONS_OPEN)
    if open_at == -1:
        problems.add_invalid(f"missing '{HEADER_OPTIONS_OPEN}' that starts the options")
        return line.strip(), None

    header = line[:open_at].strip()
    if not header:
        problems.add_invalid("rule header is empty")

    if line.endswith(OPTIONS_CLOSE):
        return header, line[open_at + 1 : -1]
    problems.add_invalid(f"rule must end with '{OPTIONS_CLOSE}'")
    return header, line[open_at + 1 :]


# tách options body thành list _Option theo đúng thứ tự khai báo
# quét từng ký tự với trạng thái trong/ngoài ngoặc kép và ký tự trước có phải \ không,
# chỉ tách ở ";" ngoài ngoặc kép; \" không đóng ngoặc kép
# (chọn chấp nhận ";" chưa escape trong ngoặc kép, chưa chắc Snort 2 có chấp nhận)
def _split_options(body: str, problems: _Problems) -> list[_Option]:
    options: list[_Option] = []
    count = 0
    current: list[str] = []
    in_quote = False
    escaped = False

    def flush() -> None:
        nonlocal count
        segment = "".join(current).strip()
        current.clear()
        if not segment:  # ";;" hoặc ";" cuối trước ")" là bình thường
            return
        count += 1
        keyword, separator, value = segment.partition(KEYWORD_SEPARATOR)
        keyword = keyword.strip()
        if not keyword:
            problems.add_invalid(f"option #{count}: keyword is empty")
            return
        # keyword so khớp chính xác, chữ thường, không đổi hoa thường (quy ước của bài làm)
        options.append(_Option(count, keyword, value.strip() if separator else None))

    for char in body:
        if escaped:
            escaped = False
        elif char == ESCAPE:
            escaped = True
        elif char == QUOTE:
            in_quote = not in_quote
        elif char == OPTION_SEPARATOR and not in_quote:
            flush()
            continue
        current.append(char)

    # option cuối không có ";" vẫn nhận; option dở dang thì bỏ vì value không đáng tin
    if in_quote:
        problems.add_invalid(f"option #{count + 1}: quote is not closed")
    elif escaped:
        problems.add_invalid(f"option #{count + 1}: ends with a lone '{ESCAPE}'")
    else:
        flush()
    return options


# token chứa ! (phủ định), [ (list), $ (biến) là cú pháp Snort đúng nhưng ngoài phạm vi
def _unsupported_syntax(token: str) -> str | None:
    if "!" in token:
        return "negation '!'"
    if token.startswith("["):
        return "list '[...]'"
    if token.startswith("$"):
        return "variable '$...'"
    return None


# IP: any -> None; IP đơn là mạng /32. Trả (ok, network)
# quy ước của bài làm: IP có host bits (192.168.1.5/24) là invalid, không tự đưa về 192.168.1.0/24
def _parse_ip(token: str, field: str, problems: _Problems) -> tuple[bool, IPv4Network | None]:
    if token == ANY:
        return True, None
    feature = _unsupported_syntax(token)
    if feature is None and ":" in token:
        feature = "IPv6 address"
    if feature is not None:
        problems.add_unsupported(f"{field}: {feature} is not supported, got {token!r}")
        return False, None
    if not IPV4_PATTERN.fullmatch(token):
        problems.add_invalid(f"{field}: {token!r} is not 'any', an IPv4 address or a CIDR")
        return False, None
    try:
        return True, IPv4Network(token)
    except ValueError as error:
        problems.add_invalid(f"{field}: {token!r} is not a valid IPv4 network ({error})")
        return False, None


# port: any -> None; 80 -> (80, 80); a:b; :b -> (0, b); a: -> (a, 65535)
# quy ước của bài làm: cận dưới bỏ trống là 0 (chưa chắc Snort lấy 0 hay 1). Trả (ok, range)
def _parse_port(token: str, field: str, problems: _Problems) -> tuple[bool, PortRange | None]:
    if token == ANY:
        return True, None
    feature = _unsupported_syntax(token)
    if feature is not None:
        problems.add_unsupported(f"{field}: {feature} is not supported, got {token!r}")
        return False, None

    if PORT_NUMBER.fullmatch(token):
        low = high = int(token)
    else:
        match = PORT_RANGE.fullmatch(token)
        if not match or token == ":":
            problems.add_invalid(f"{field}: {token!r} is not 'any', a port or a port range")
            return False, None
        low = int(match.group(1)) if match.group(1) else 0
        high = int(match.group(2)) if match.group(2) else PORT_MAX

    if not (0 <= low <= PORT_MAX and 0 <= high <= PORT_MAX):
        problems.add_invalid(f"{field}: {token!r} is outside 0-{PORT_MAX}")
        return False, None
    if low > high:
        problems.add_invalid(f"{field}: {token!r} has low greater than high")
        return False, None
    return True, (low, high)


# parse 7 token của header, chỉ gán vào Rule field nào parse thành công
def _parse_header(header: str, rule: Rule, problems: _Problems) -> None:
    tokens = header.split()
    if len(tokens) != HEADER_TOKENS:
        problems.add_invalid(
            f"header: expected {HEADER_TOKENS} tokens (action protocol src_ip src_port "
            f"direction dst_ip dst_port), got {len(tokens)}"
        )
        return
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = tokens

    if action == ACTION_ALERT:
        rule.action = action
    elif action in UNSUPPORTED_ACTIONS:
        problems.add_unsupported(f"action: {action!r} is not supported, only 'alert'")
    else:
        problems.add_invalid(f"action: unknown action {action!r}")

    proto = None
    if protocol in PROTOCOLS:
        proto = rule.protocol = PROTOCOLS[protocol]
    elif protocol in UNSUPPORTED_PROTOCOLS:
        problems.add_unsupported(f"protocol: {protocol!r} is not supported, only tcp, udp, ip")
    else:
        problems.add_invalid(f"protocol: unknown protocol {protocol!r}")

    if direction in RULE_DIRECTIONS:
        rule.direction = direction
    else:
        problems.add_invalid(f"direction: {direction!r} is not '->' or '<>'")

    _, rule.src_ip = _parse_ip(src_ip, "src_ip", problems)
    _, rule.dst_ip = _parse_ip(dst_ip, "dst_ip", problems)
    src_ok, rule.src_port = _parse_port(src_port, "src_port", problems)
    dst_ok, rule.dst_port = _parse_port(dst_port, "dst_port", problems)

    # rule ip bắt buộc port any; chỉ báo khi port đã parse được, tránh lỗi nhiễu
    if proto == RULE_PROTO_IP and src_ok and dst_ok and (rule.src_port or rule.dst_port):
        problems.add_invalid("protocol: rule 'ip' requires src_port and dst_port to be 'any'")


# interface mà loader gọi cho từng dòng rule
# loader truyền line đã strip(), không có ký tự xuống dòng
# line_no đếm từ 1 theo dòng thật trong file, kể cả dòng trống và comment
# không bọc try/except Exception: chỉ bắt lỗi dự kiến tại chỗ; bug lập trình để loader
# (_parse_safely) log error kèm traceback, tránh trông giống rule viết sai
def parse_rule(line: str, source_file: str, line_no: int) -> Rule:
    rule = Rule(source_file=source_file, line_no=line_no, raw=line)
    problems = _Problems()

    header, body = _split_header_options(line, problems)
    options = _split_options(body, problems) if body is not None else []
    if header:  # header rỗng đã bị ghi lỗi ở _split_header_options
        _parse_header(header, rule, problems)
    # các bước sau đọc options, ghi lỗi vào problems rồi chốt status ở đây
    del options

    rule.status = problems.status
    rule.reasons = problems.reasons
    return rule

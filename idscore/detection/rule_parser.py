# file này là Rule Parser & Validator: chuyển một dòng rule thành một Rule
# hợp đồng của module; Phase 3 đang viết dần phần parse (hiện có: khung, tách header/options, parse header, options, validator)
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
    DSIZE_EQ,
    DSIZE_GT,
    DSIZE_LT,
    DSIZE_RANGE,
    DSIZE_RANGE_INCL,
    FLOW_TO_CLIENT,
    FLOW_TO_SERVER,
    Content,
    DSize,
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

POSITIVE_INT = re.compile(r"[0-9]+")
SIGNED_INT = re.compile(r"-?[0-9]+")
CLASSTYPE = re.compile(r"[A-Za-z0-9_-]+")
HEX_BYTES = re.compile(r"([0-9A-Fa-f]{2})+")
HEX_DELIMITER = "|"
# ký tự được phép đứng sau \ trong chuỗi trong ngoặc kép (msg và content dùng chung)
ESCAPABLE = frozenset({QUOTE, ESCAPE, OPTION_SEPARATOR})
NOT_PREFIX = "!"
KEYWORD_CONTENT = "content"
KEYWORD_NOCASE = "nocase"
# modifier số của content; depth và within phải lớn hơn 0, offset và distance được âm
CONTENT_INT_MODIFIERS = ("offset", "depth", "distance", "within")
POSITIVE_MODIFIERS = frozenset({"depth", "within"})

FLAG_LETTERS = frozenset("FSRPAUCE")
FLAG_NONE = "0"
FLAG_MODIFIERS = "+*!"
FLAG_MASK_SEPARATOR = ","
DSIZE_NUMBER = re.compile(r"[0-9]+")
DSIZE_COMPARE = re.compile(r"([<>])([0-9]+)")
DSIZE_RANGE_PATTERN = re.compile(r"([0-9]+)(<>|<=>)([0-9]+)")
# Snort 3 còn có >=, <=, !; model DSize không biểu diễn được nên xếp unsupported thay vì lỗi gõ
DSIZE_UNSUPPORTED_PREFIXES = (">=", "<=", "!")
FLOW_SEPARATOR = ","
FLOW_DIRECTION_WORDS = {
    "to_server": FLOW_TO_SERVER,
    "from_client": FLOW_TO_SERVER, # bí danh cùng nghĩa
    "to_client": FLOW_TO_CLIENT,
    "from_server": FLOW_TO_CLIENT,
}
FLOW_STATE_WORDS = {"established": True, "not_established": False}
FLOW_UNSUPPORTED_WORDS = frozenset(
    {"stateless", "no_stream", "only_stream", "no_frag", "only_frag"}
)

# keyword nhận diện và đọc được (identification, content, packet, flow)
SUPPORTED_KEYWORDS = frozenset(
    {"msg", "sid", "rev", "priority", "classtype", "content", "nocase", "offset", "depth",
     "distance", "within", "flags", "dsize", "flow"}
)
# keyword mang thông tin, không ảnh hưởng so khớp: bỏ qua không báo lỗi, ghi trong README.
# Muốn coi là unsupported thì để tập này rỗng; chọn bỏ qua vì gần như mọi rule chính thức có chúng
IGNORED_KEYWORDS = frozenset({"reference", "metadata"})
# keyword Snort có thật nhưng ngoài phạm vi; nhiều keyword đổi vùng tìm của content nên bỏ qua
# sẽ sinh cảnh báo sai
SNORT_UNSUPPORTED_KEYWORDS = frozenset(
    {"pcre", "byte_test", "byte_jump", "byte_extract", "byte_math", "isdataat", "uricontent",
     "urilen", "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_method",
     "http_cookie", "http_raw_cookie", "http_client_body", "http_stat_code", "http_stat_msg",
     "http_encode", "flowbits", "flowint", "threshold", "detection_filter", "fast_pattern",
     "rawbytes", "gid", "ack", "seq", "ttl", "tos", "id", "ipopts", "fragbits", "fragoffset",
     "sameip", "window", "itype", "icode", "icmp_id", "icmp_seq", "ip_proto", "stream_size",
     "replace", "tag", "sd_pattern", "file_data", "pkt_data", "base64_decode", "base64_data",
     "bufferlen", "startswith", "endswith", "service", "session", "react", "resp", "logto",
     "content_list", "asn1", "cvs", "ftpbounce", "dce_iface", "dce_opnum", "dce_stub_data",
     "sip_method", "sip_header", "sip_body", "ssl_state", "ssl_version", "tls_cert_common",
     "dnp3_func", "modbus_func", "cip_attribute", "file_type", "file_id", "protected_content",
     "hash", "luajit", "pcre2", "stream_reassemble", "attribute_table", "activates",
     "activated_by", "count", "ack_win", "rpc", "dns_query", "dns_type", "dns_opcode", "http_version",
     "http_trailer", "http_param", "http_num_headers", "http_header_test", "http_true_ip"}
)


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


# lỗi cú pháp dự kiến của một chuỗi trong ngoặc kép, được bắt ngay nơi gọi _scan_quoted
class _QuotedError(ValueError):
    pass


# đọc chuỗi trong ngoặc kép, dùng chung cho msg và content để quy tắc escape không lệch nhau
# bắt buộc mở và đóng bằng ", không có gì sau ngoặc đóng; unescape \" \\ \;, \ đi với ký tự khác
# là lỗi (quy ước của bài làm, chưa chắc Snort có bỏ qua \ đó không)
# hex_allowed: |41 42| đổi thành byte (content); với msg thì | chỉ là ký tự thường
# quét một lượt vì phải phân biệt | mở đoạn hex với ký tự trong chuỗi
def _scan_quoted(value: str | None, hex_allowed: bool) -> bytes:
    if value is None or len(value) < 2 or value[0] != QUOTE:
        raise _QuotedError("value must be a string in double quotes")
    out = bytearray()
    last = len(value) - 1
    i = 1
    while i <= last:
        char = value[i]
        if char == QUOTE:
            if i != last:
                raise _QuotedError("unexpected text after the closing quote")
            return bytes(out)
        if char == ESCAPE:
            if i + 1 > last or value[i + 1] not in ESCAPABLE:
                raise _QuotedError(f"'{ESCAPE}' must be followed by one of {sorted(ESCAPABLE)}")
            out += value[i + 1].encode("utf-8")
            i += 2
        elif char == HEX_DELIMITER and hex_allowed:
            end = value.find(HEX_DELIMITER, i + 1)
            if end == -1:
                raise _QuotedError(f"hex section opened by '{HEX_DELIMITER}' is not closed")
            for token in value[i + 1 : end].split():
                if not HEX_BYTES.fullmatch(token):
                    raise _QuotedError(f"{token!r} in hex section is not whole hex bytes")
                out += bytes.fromhex(token)
            i = end + 1
        else:
            out += char.encode("utf-8")
            i += 1
    raise _QuotedError("closing quote is missing")


def _positive_int(option: "_Option", problems: _Problems) -> int | None:
    if option.value is None or not POSITIVE_INT.fullmatch(option.value) or int(option.value) <= 0:
        problems.add_invalid(
            f"option #{option.index} ({option.keyword}): must be an integer greater than 0, "
            f"got {option.value!r}"
        )
        return None
    return int(option.value)


# các keyword identification và classification, mỗi keyword một hàm; keyword lặp: giữ giá trị đầu
# (việc báo trùng thuộc validator tổng hợp)
def _opt_msg(option: "_Option", rule: Rule, problems: _Problems) -> None:
    try:
        text = _scan_quoted(option.value, hex_allowed=False).decode("utf-8")
    except _QuotedError as error:
        problems.add_invalid(f"option #{option.index} (msg): {error}")
        return
    if not text:
        problems.add_invalid(f"option #{option.index} (msg): must not be empty")
        return
    rule.msg = text


def _opt_sid(option: "_Option", rule: Rule, problems: _Problems) -> None:
    # gán ngay khi đọc được, để disabled_sids tắt được rule hỏng vì lý do khác
    # không cảnh báo sid < 1000000: rule chính thức của Snort có sid thấp
    value = _positive_int(option, problems)
    if value is not None:
        rule.sid = value


def _opt_rev(option: "_Option", rule: Rule, problems: _Problems) -> None:
    value = _positive_int(option, problems)
    if value is not None:
        rule.rev = value


def _opt_priority(option: "_Option", rule: Rule, problems: _Problems) -> None:
    value = _positive_int(option, problems)
    if value is not None:
        rule.priority = value


# chỉ kiểm tra dạng token, không đối chiếu classification.config của Snort
def _opt_classtype(option: "_Option", rule: Rule, problems: _Problems) -> None:
    if option.value is None or not CLASSTYPE.fullmatch(option.value):
        problems.add_invalid(
            f"option #{option.index} (classtype): must be one token of [A-Za-z0-9_-], "
            f"got {option.value!r}"
        )
        return
    rule.classtype = option.value




# flags:SA, flags:A+, flags:+A, flags:0; chỉ lưu tập cờ của rule dạng ký hiệu Snort,
# việc đổi event.tcp_flags (SYN-ACK) sang ký hiệu này là của matcher
# nhận modifier ở đầu hoặc cuối vì chưa chắc Snort chấp nhận những vị trí nào
def _opt_flags(option: "_Option", rule: Rule, problems: _Problems) -> None:
    prefix = f"option #{option.index} (flags)"
    value = option.value
    if not value:
        problems.add_invalid(f"{prefix}: needs a value")
        return
    if FLAG_MASK_SEPARATOR in value:
        problems.add_unsupported(f"{prefix}: mask after ',' is not supported, got {value!r}")
        return
    if rule.protocol is not None and rule.protocol != RULE_PROTO_TCP:
        problems.add_invalid(f"{prefix}: only valid for a tcp rule, rule protocol is {rule.protocol}")
        return

    modifier = None
    if value[0] in FLAG_MODIFIERS:
        modifier, value = value[0], value[1:]
    elif value[-1] in FLAG_MODIFIERS:
        modifier, value = value[-1], value[:-1]
    letters = value.upper()
    if not letters or any(char in FLAG_MODIFIERS for char in letters):
        problems.add_invalid(f"{prefix}: {option.value!r} has a missing letter or more than one modifier")
        return
    if letters == FLAG_NONE:
        flags = frozenset()
    elif len(set(letters)) != len(letters):
        problems.add_invalid(f"{prefix}: repeated flag in {option.value!r}")
        return
    elif not set(letters) <= FLAG_LETTERS:
        problems.add_invalid(
            f"{prefix}: {option.value!r} has a letter outside {''.join(sorted(FLAG_LETTERS))} "
            f"(or '{FLAG_NONE}' mixed with other flags)"
        )
        return
    else:
        flags = frozenset(letters)
    rule.flags = flags
    rule.flags_modifier = modifier


# dsize:N, >N, <N, N<>M (khoảng mở), N<=>M (khoảng đóng); số từ 0 đến 65535
def _opt_dsize(option: "_Option", rule: Rule, problems: _Problems) -> None:
    prefix = f"option #{option.index} (dsize)"
    value = option.value
    if not value:
        problems.add_invalid(f"{prefix}: needs a value")
        return
    if value.startswith(DSIZE_UNSUPPORTED_PREFIXES):
        problems.add_unsupported(f"{prefix}: {value!r} is not supported, use N, >N, <N, N<>M or N<=>M")
        return

    if DSIZE_NUMBER.fullmatch(value):
        dsize = DSize(DSIZE_EQ, int(value))
    elif DSIZE_COMPARE.fullmatch(value):
        sign, number = DSIZE_COMPARE.fullmatch(value).groups()
        dsize = DSize(DSIZE_GT if sign == ">" else DSIZE_LT, int(number))
    elif DSIZE_RANGE_PATTERN.fullmatch(value):
        low, op, high = DSIZE_RANGE_PATTERN.fullmatch(value).groups()
        dsize = DSize(DSIZE_RANGE if op == "<>" else DSIZE_RANGE_INCL, int(low), int(high))
        if dsize.low > dsize.high or (op == "<>" and dsize.low == dsize.high):
            problems.add_invalid(f"{prefix}: {value!r} is an empty range")
            return
    else:
        problems.add_invalid(f"{prefix}: {value!r} is not N, >N, <N, N<>M or N<=>M")
        return

    if not all(0 <= n <= PORT_MAX for n in (dsize.low, dsize.high or 0)):
        problems.add_invalid(f"{prefix}: {value!r} is outside 0-{PORT_MAX}")
        return
    rule.dsize = dsize


# flow:to_server,established; from_client/from_server là bí danh của to_server/to_client
def _opt_flow(option: "_Option", rule: Rule, problems: _Problems) -> None:
    prefix = f"option #{option.index} (flow)"
    if not option.value:
        problems.add_invalid(f"{prefix}: needs a value")
        return
    directions: set[str] = set()
    states: set[bool] = set()
    seen: set[str] = set()
    errors = 0
    for word in (part.strip() for part in option.value.split(FLOW_SEPARATOR)):
        if not word:
            problems.add_invalid(f"{prefix}: empty item in {option.value!r}")
            errors += 1
        elif word in seen:
            problems.add_invalid(f"{prefix}: {word!r} is repeated")
            errors += 1
        elif word in FLOW_DIRECTION_WORDS:
            directions.add(FLOW_DIRECTION_WORDS[word])
        elif word in FLOW_STATE_WORDS:
            states.add(FLOW_STATE_WORDS[word])
        elif word in FLOW_UNSUPPORTED_WORDS:
            problems.add_unsupported(f"{prefix}: {word!r} is not supported")
            errors += 1
        else:
            problems.add_invalid(f"{prefix}: unknown item {word!r}")
            errors += 1
        seen.add(word)
    if len(directions) > 1:
        problems.add_invalid(f"{prefix}: to_server and to_client cannot be combined")
        errors += 1
    if len(states) > 1:
        problems.add_invalid(f"{prefix}: established and not_established cannot be combined")
        errors += 1
    if errors:
        return
    rule.flow_direction = next(iter(directions), None)
    rule.flow_established = next(iter(states), None)


OPTION_PARSERS = {
    "msg": _opt_msg,
    "sid": _opt_sid,
    "rev": _opt_rev,
    "priority": _opt_priority,
    "classtype": _opt_classtype,
    "flags": _opt_flags,
    "dsize": _opt_dsize,
    "flow": _opt_flow,
}


# bộ đệm của content đang đọc: Content là frozen nên modifier không gán dần vào được
# pattern None nghĩa là pattern của content này đã lỗi hoặc unsupported, modifier đi sau vẫn gắn vào đây
class _ContentBuilder:
    def __init__(self, index: int, ordinal: int, pattern: bytes | None) -> None:
        self.index = index # số thứ tự option, để ghi lý do
        self.ordinal = ordinal # content thứ mấy trong rule, tính từ 1
        self.pattern = pattern
        self.nocase = False
        self.numbers: dict[str, int] = {}


def _start_content(option: "_Option", ordinal: int, problems: _Problems) -> _ContentBuilder:
    prefix = f"option #{option.index} (content)"
    value = option.value
    pattern = None
    if value is not None and value.startswith(NOT_PREFIX):
        problems.add_unsupported(f"{prefix}: negated content '!' is not supported")
    else:
        try:
            pattern = _scan_quoted(value, hex_allowed=True)
            if not pattern:
                problems.add_invalid(f"{prefix}: pattern must not be empty")
                pattern = None
        except _QuotedError as error:
            problems.add_invalid(f"{prefix}: {error}")
    return _ContentBuilder(option.index, ordinal, pattern)


def _apply_modifier(
    builder: _ContentBuilder | None, option: "_Option", problems: _Problems
) -> None:
    prefix = f"option #{option.index} ({option.keyword})"
    if builder is None:
        problems.add_invalid(f"{prefix}: must come after a content")
        return
    keyword = option.keyword
    if keyword == KEYWORD_NOCASE:
        if option.value is not None:
            problems.add_invalid(f"{prefix}: takes no value, got {option.value!r}")
        elif builder.nocase:
            problems.add_invalid(f"{prefix}: repeated on the same content")
        else:
            builder.nocase = True # không đổi pattern về chữ thường, matcher tự xử lý
        return

    value = option.value
    if value is None or not SIGNED_INT.fullmatch(value):
        problems.add_invalid(f"{prefix}: must be an integer, got {value!r}")
    elif keyword in POSITIVE_MODIFIERS and int(value) <= 0:
        problems.add_invalid(f"{prefix}: must be greater than 0, got {value}")
    elif keyword in builder.numbers:
        problems.add_invalid(f"{prefix}: repeated on the same content")
    else:
        builder.numbers[keyword] = int(value)


# chốt một content: kiểm tra ràng buộc kết hợp rồi thêm vào Rule.contents
# chặn ngay ở parser để matcher chỉ có một mốc vị trí cho mỗi content (quy ước của bài làm)
def _finish_content(builder: _ContentBuilder, rule: Rule, problems: _Problems) -> None:
    pattern = builder.pattern
    if pattern is None:
        return
    prefix = f"option #{builder.index} (content)"
    numbers = builder.numbers
    for keyword in POSITIVE_MODIFIERS:
        if keyword in numbers and numbers[keyword] < len(pattern):
            problems.add_invalid(
                f"{prefix}: {keyword} {numbers[keyword]} is shorter than the "
                f"{len(pattern)}-byte pattern, it can never match"
            )
    if builder.ordinal == 1 and ("distance" in numbers or "within" in numbers):
        problems.add_invalid(f"{prefix}: distance/within on the first content has nothing to follow")
    if ("offset" in numbers or "depth" in numbers) and ("distance" in numbers or "within" in numbers):
        problems.add_invalid(f"{prefix}: offset/depth cannot be combined with distance/within")
    rule.contents.append(
        Content(
            pattern=pattern,
            nocase=builder.nocase,
            offset=numbers.get("offset"),
            depth=numbers.get("depth"),
            distance=numbers.get("distance"),
            within=numbers.get("within"),
        )
    )


# duyệt options theo thứ tự khai báo; modifier gắn vào content đứng ngay trước
def _parse_options(options: list["_Option"], rule: Rule, problems: _Problems) -> None:
    seen: set[str] = set()
    builder: _ContentBuilder | None = None
    ordinal = 0
    for option in options:
        keyword = option.keyword
        if keyword in OPTION_PARSERS:
            if keyword in seen:
                # giữ giá trị đầu, nhưng rule có hai sid/msg/... là rule viết sai nên báo lỗi
                problems.add_invalid(f"option #{option.index} ({keyword}): repeated")
            else:
                seen.add(keyword)
                OPTION_PARSERS[keyword](option, rule, problems)
        elif keyword == KEYWORD_CONTENT:
            if builder is not None:
                _finish_content(builder, rule, problems)
            ordinal += 1
            builder = _start_content(option, ordinal, problems)
        elif keyword == KEYWORD_NOCASE or keyword in CONTENT_INT_MODIFIERS:
            _apply_modifier(builder, option, problems)
        elif keyword in IGNORED_KEYWORDS:
            continue
        elif keyword in SNORT_UNSUPPORTED_KEYWORDS:
            problems.add_unsupported(f"option #{option.index} ({keyword}): keyword is not supported")
        else:
            problems.add_invalid(f"option #{option.index} ({keyword}): unknown keyword")
    if builder is not None:
        _finish_content(builder, rule, problems)

    # sid và msg bắt buộc (quy ước của bài làm); chỉ báo thiếu khi keyword không xuất hiện,
    # keyword có mặt mà value sai đã có lý do riêng
    for required in ("sid", "msg"):
        if required not in seen:
            problems.add_invalid(f"missing required option '{required}'")


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
    _parse_options(options, rule, problems)

    rule.status = problems.status
    rule.reasons = problems.reasons
    return rule

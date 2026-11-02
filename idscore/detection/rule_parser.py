# file này là Rule Parser & Validator: chuyển một dòng rule thành một Rule
# hợp đồng của module; Phase 3 đang viết dần phần parse (hiện có: khung, tách header/options)
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

from typing import NamedTuple

from idscore.models.rule import (
    RULE_INVALID,
    RULE_UNSUPPORTED,
    RULE_VALID,
    Rule,
)

HEADER_OPTIONS_OPEN = "("
OPTIONS_CLOSE = ")"
OPTION_SEPARATOR = ";"
KEYWORD_SEPARATOR = ":"
QUOTE = '"'
ESCAPE = "\\"


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
    # các bước sau đọc header và options, ghi lỗi vào problems rồi chốt status ở đây
    del header, options

    rule.status = problems.status
    rule.reasons = problems.reasons
    return rule

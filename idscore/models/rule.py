# schema cho rule, ghi dữ liệu rule loader/parser phân tích từ một dòng trong file .rules
# IP, port, content được parse một lần lúc nạp, matching engine chỉ so sánh

from dataclasses import dataclass, field
from ipaddress import IPv4Network

# các trạng thái của rule (mục phân loại rule khi nạp)
RULE_VALID = "valid"
RULE_INVALID = "invalid"
RULE_UNSUPPORTED = "unsupported"
RULE_STATUSES = (RULE_VALID, RULE_INVALID, RULE_UNSUPPORTED)

# chiều của rule header
RULE_DIR_UNI = "->"
RULE_DIR_BI = "<>"
RULE_DIRECTIONS = (RULE_DIR_UNI, RULE_DIR_BI)

# chiều của option flow
FLOW_TO_SERVER = "to_server"
FLOW_TO_CLIENT = "to_client"
FLOW_RULE_DIRECTIONS = (FLOW_TO_SERVER, FLOW_TO_CLIENT)

# toán tử của option dsize
DSIZE_EQ = "="
DSIZE_GT = ">"
DSIZE_LT = "<"
DSIZE_RANGE = "<>"
DSIZE_OPS = (DSIZE_EQ, DSIZE_GT, DSIZE_LT, DSIZE_RANGE)

# port đã parse: None là any, còn lại là (low, high), port đơn có low == high
PortRange = tuple[int, int]

# rev mặc định khi rule không khai báo (quy ước của bài làm)
DEFAULT_REV = 1


@dataclass(frozen=True)
class Content:
    # một option content cùng các modifier đứng ngay sau nó
    pattern: bytes # byte thô để so trực tiếp với event.payload, đã đổi phần |hex|
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass(frozen=True)
class DSize:
    # dsize:300 -> (=, 300), dsize:>500 -> (>, 500), dsize:<10 -> (<, 10)
    # dsize:300<>400 -> (<>, 300, 400); high chỉ có ở dạng range
    op: str
    low: int
    high: int | None = None


@dataclass
class Rule:
    # metadata và trạng thái, để cảnh báo lúc nạp chỉ ra rule nằm ở đâu và vì sao
    source_file: str
    line_no: int
    raw: str # text gốc của rule
    status: str = RULE_VALID
    reasons: list[str] = field(default_factory=list)

    # header; IP None là any, IP đơn là mạng /32
    # protocol viết hoa như Event.transport_protocol (TCP, UDP, ...)
    action: str | None = None
    protocol: str | None = None
    src_ip: IPv4Network | None = None
    src_port: PortRange | None = None
    direction: str | None = None
    dst_ip: IPv4Network | None = None
    dst_port: PortRange | None = None

    # identification và classification
    # sid và msg bắt buộc, thiếu rev thì mặc định 1 (quy ước của bài làm)
    msg: str | None = None
    sid: int | None = None
    rev: int = DEFAULT_REV
    classtype: str | None = None
    priority: int | None = None

    # content theo đúng thứ tự khai báo, vì distance/within tính theo content trước đó
    contents: list[Content] = field(default_factory=list)

    # packet và flow
    # flags: ký hiệu Snort (F S R P A U C E), rỗng là flags:0; None là rule không có option
    flags: frozenset[str] | None = None
    flags_modifier: str | None = None # "+", "*", "!" hoặc None
    dsize: DSize | None = None
    flow_direction: str | None = None # to_server, to_client hoặc None
    flow_established: bool | None = None # True, False hoặc None

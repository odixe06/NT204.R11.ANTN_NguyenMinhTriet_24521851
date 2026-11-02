# file này là Rule Matching Engine: kiểm tra một Rule có khớp một Event hay không
# hợp đồng của module; match() đã có khung, đã so khớp header, flags, dsize; flow và content đang điền dần
#
# chiều phụ thuộc: matcher chỉ dùng idscore.models (Rule, Event, FlowContext, ContentMatch);
# matcher KHÔNG import generator, không import Scapy
#
# input : Rule, Event (dùng Event.payload dạng bytes), FlowContext | None
# output: danh sách ContentMatch nếu khớp (rule không có content thì danh sách rỗng),
#         hoặc None nếu không khớp
#
# việc của matcher:
#   - so khớp header, flags, dsize, flow, content theo đúng thứ tự khai báo
#   - diễn giải flow từ dữ kiện của FlowContext (to_server, established, ...)
#
# matcher KHÔNG được:
#   - in cảnh báo hoặc ghi log kết quả match
#   - sửa Event, FlowContext hay Rule
#   - đọc packet thô (Scapy) hay parse lại rule cho mỗi packet
#   - dựng DetectionEvent (việc của generator)

from ipaddress import IPv4Network, ip_address

from idscore.models.detection import ContentMatch
from idscore.models.event import Event
from idscore.models.flow import FlowContext
from idscore.models.rule import (
    DSIZE_EQ,
    DSIZE_GT,
    DSIZE_LT,
    DSIZE_RANGE,
    DSIZE_RANGE_INCL,
    RULE_DIR_BI,
    RULE_PROTO_IP,
    PortRange,
    Rule,
)

TRANSPORT_PROTOCOLS = ("TCP", "UDP")

# tên cờ do TCPParser sinh ra (event.tcp_flags, ví dụ "SYN-ACK") -> ký hiệu Snort trong rule.flags
# C là CWR và E là ECE theo quy ước tôi biết của Snort, chưa chắc đúng cho mọi phiên bản
FLAG_SYMBOLS = {
    "FIN": "F", "SYN": "S", "RST": "R", "PSH": "P",
    "ACK": "A", "URG": "U", "CWR": "C", "ECE": "E",
}
TCP_FLAG_SEPARATOR = "-"


# hàm công khai duy nhất: rule khớp event thì trả danh sách ContentMatch (rỗng nếu rule không có
# content), không khớp thì trả None
# thứ tự cố định header -> flags -> dsize -> flow -> content, sai nhóm nào trả None ngay: các nhóm
# đầu chỉ so số và chuỗi ngắn, content phải quét payload nên tốn nhất và để cuối
# event thiếu dữ liệu mà rule cần (ip/port None, payload None, ctx None) thì nhóm đó không khớp,
# không raise: rule đòi điều kiện mà event không chứng minh được thì không báo, tránh false positive
def match(rule: Rule, event: Event, ctx: FlowContext | None) -> list[ContentMatch] | None:
    if not _match_header(rule, event):
        return None
    if not _match_flags(rule, event):
        return None
    if not _match_dsize(rule, event):
        return None
    if not _match_flow(rule, ctx):
        return None
    return _match_contents(rule, event)


# header: protocol, IP, port, direction
def _match_header(rule: Rule, event: Event) -> bool:
    # repository đã lọc theo protocol nhưng chỉ là tập thừa; kiểm lại để match đúng khi gọi độc lập
    protocol = event.transport_protocol
    if rule.protocol == RULE_PROTO_IP:
        if protocol not in TRANSPORT_PROTOCOLS:
            return False
    elif rule.protocol != protocol:
        return False

    forward = _side_matches(rule.src_ip, rule.src_port, event.src_ip, event.src_port) and (
        _side_matches(rule.dst_ip, rule.dst_port, event.dst_ip, event.dst_port)
    )
    if forward or rule.direction != RULE_DIR_BI:
        return forward
    # <>: đảo src và dst của event rồi so lại, để bắt cả gói ngược chiều
    return _side_matches(rule.src_ip, rule.src_port, event.dst_ip, event.dst_port) and (
        _side_matches(rule.dst_ip, rule.dst_port, event.src_ip, event.src_port)
    )


# một phía (IP + port) của rule với một phía của event
def _side_matches(
    network: IPv4Network | None, ports: PortRange | None, ip: str | None, port: int | None
) -> bool:
    return _ip_matches(network, ip) and _port_matches(ports, port)


# rule IP None là any; IP đơn đã là mạng /32 nên một phép "in" xử lý cả IP đơn lẫn CIDR
# event malformed có thể mang chuỗi IP lỗi: coi là không khớp, không crash
def _ip_matches(network: IPv4Network | None, text: str | None) -> bool:
    if network is None:
        return True
    if not isinstance(text, str):
        return False
    try:
        return ip_address(text) in network
    except ValueError:
        return False


# rule port None là any; port đơn lưu dạng (p, p) nên đơn và range dùng chung một điều kiện
def _port_matches(ports: PortRange | None, port: int | None) -> bool:
    if ports is None:
        return True
    if not isinstance(port, int) or isinstance(port, bool):
        return False
    return ports[0] <= port <= ports[1]


# các nhóm sau: thân hàm tạm, True nghĩa là không loại; được điền ở các bước tiếp theo
# tcp_flags của event -> frozenset ký hiệu Snort
# None khi không phải TCP hoặc có tên cờ lạ (dữ liệu không đáng tin); "" là gói không mang cờ nào
def _event_flags(event: Event) -> frozenset[str] | None:
    text = event.tcp_flags
    if not isinstance(text, str):
        return None
    if not text:
        return frozenset()
    symbols = [FLAG_SYMBOLS.get(name) for name in text.split(TCP_FLAG_SEPARATOR)]
    if None in symbols:
        return None
    return frozenset(symbols)


# R là tập cờ của rule, P là tập cờ của packet (ngữ nghĩa theo tài liệu Snort):
#   không modifier: P == R (flags:0 có R rỗng nên chỉ khớp gói không cờ)
#   +: R <= P   *: R & P khác rỗng
#   !: chọn "không cờ nào của rule được bật" (R & P rỗng), sát câu chữ tài liệu nhất;
#      tài liệu hiểu được theo hai cách (cách kia là P != R), chưa chắc Snort cài đặt cách nào
def _match_flags(rule: Rule, event: Event) -> bool:
    if rule.flags is None:
        return True
    packet = _event_flags(event)
    if packet is None:
        return False
    flags, modifier = rule.flags, rule.flags_modifier
    if modifier is None:
        return packet == flags
    if modifier == "+":
        return flags <= packet
    if modifier == "*":
        return bool(flags & packet)
    if modifier == "!":
        return not (flags & packet)
    return False


# kích thước lấy từ len(payload), cùng nguồn với content để dsize và offset/depth luôn nhất quán
def _match_dsize(rule: Rule, event: Event) -> bool:
    dsize = rule.dsize
    if dsize is None:
        return True
    if not isinstance(event.payload, bytes):
        return False
    size, low, high = len(event.payload), dsize.low, dsize.high
    if dsize.op == DSIZE_EQ:
        return size == low
    if dsize.op == DSIZE_GT:
        return size > low
    if dsize.op == DSIZE_LT:
        return size < low
    if high is None:  # dạng range mà thiếu high: parser không sinh ra, phòng thủ
        return False
    if dsize.op == DSIZE_RANGE:
        return low < size < high
    if dsize.op == DSIZE_RANGE_INCL:
        return low <= size <= high
    return False


def _match_flow(rule: Rule, ctx: FlowContext | None) -> bool:
    return True


def _match_contents(rule: Rule, event: Event) -> list[ContentMatch] | None:
    return []

# file này là Rule Parser & Validator: chuyển một dòng rule thành một Rule
# hợp đồng của module; parse_rule bên dưới hiện mới là thân hàm tạm, Phase 3 mới viết phần parse
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
#
# rule_parser KHÔNG được:
#   - raise exception ra ngoài vì một dòng sai
#   - đọc file, in hoặc ghi log (việc của loader)
#   - đụng tới Event, FlowContext hay DetectionEvent

from idscore.models.rule import Rule


# interface mà loader gọi cho từng dòng rule
# loader truyền line đã strip(), không có ký tự xuống dòng
# line_no đếm từ 1 theo dòng thật trong file, kể cả dòng trống và comment
def parse_rule(line: str, source_file: str, line_no: int) -> Rule:
    # thân hàm tạm thời: chưa đọc header hay option nào, status mặc định là valid
    # Phase 3 thay thân hàm này, chữ ký giữ nguyên để loader không phải sửa
    return Rule(source_file=source_file, line_no=line_no, raw=line)

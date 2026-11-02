# file này là Rule Parser & Validator: chuyển một dòng rule thành một Rule
# chưa có code, đây là hợp đồng để các phase sau làm theo
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

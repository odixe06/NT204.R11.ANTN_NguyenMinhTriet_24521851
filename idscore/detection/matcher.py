# file này là Rule Matching Engine: kiểm tra một Rule có khớp một Event hay không
# chưa có code, đây là hợp đồng để các phase sau làm theo
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

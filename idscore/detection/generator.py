# file này là Detection Event Generator: dựng DetectionEvent từ một rule đã khớp
# chưa có code, đây là hợp đồng để các phase sau làm theo
#
# chiều phụ thuộc: generator chỉ dùng idscore.models (Rule, Event, FlowContext, DetectionEvent,
# ContentMatch); không import matcher, repository hay engine
#
# input : Rule, Event, FlowContext | None, list[ContentMatch]
# output: DetectionEvent đầy đủ field mục 4.6, field thiếu giá trị ghi None
#         (timestamp lấy từ Event, không lấy giờ hệ thống; có packet_id để tra về events.jsonl)
#
# generator KHÔNG được:
#   - so khớp rule (việc của matcher)
#   - in, ghi file hay gửi cảnh báo
#   - sửa Rule, Event hay FlowContext

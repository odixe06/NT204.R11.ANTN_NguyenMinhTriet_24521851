# file này là Rule Evaluation Engine: điều phối đánh giá một event qua các rule
# chưa có code, đây là hợp đồng để các phase sau làm theo
#
# chiều phụ thuộc: engine -> repository, matcher, generator (một chiều);
# engine không import Scapy
#
# input : Event và FlowContext | None (lấy từ tracker.context_of(event) ngay sau tracker.process)
# output: list[DetectionEvent], rỗng nếu không rule nào khớp
#
# việc của engine:
#   - lấy ứng viên từ repository, gọi matcher cho từng rule, rule khớp thì nhờ generator dựng
#     DetectionEvent
#   - một rule lỗi khi đánh giá không làm dừng các rule còn lại
#
# engine KHÔNG được:
#   - in hoặc ghi cảnh báo (việc của alerting/logging ở bài 4)
#   - tự so khớp (việc của matcher) hay tự dựng DetectionEvent (việc của generator)
#   - đọc packet thô hay sửa Event, FlowContext

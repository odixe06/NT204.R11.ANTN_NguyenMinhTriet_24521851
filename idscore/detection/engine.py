# file này là Rule Evaluation Engine: điều phối đánh giá một event qua các rule
# hợp đồng của module; hiện có khung EvaluationEngine.evaluate (bỏ event drop, chặn lỗi), các bước sau điền phần đánh giá
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

import logging

from idscore.detection.repository import RuleRepository
from idscore.models.detection import DetectionEvent
from idscore.models.event import ACTION_DROP, Event
from idscore.models.flow import FlowContext

logger = logging.getLogger(__name__)


class EvaluationEngine:
    # nhận repository thay vì tự nạp rule hay đọc config, để testcase truyền được bộ rule riêng
    def __init__(self, repository: RuleRepository) -> None:
        self._repository = repository

    # đánh giá một event, trả list mới (rỗng nếu không rule nào khớp); một event có thể khớp nhiều rule
    # không bao giờ raise: một packet lỗi không được làm dừng chương trình
    def evaluate(self, event: Event, ctx: FlowContext | None) -> list[DetectionEvent]:
        try:
            # cli không ghi event bị drop vào events.jsonl, sinh cảnh báo thì packet_id không tra ngược được
            if event.processing_action == ACTION_DROP:
                return []
            # thân hàm tạm thời, các bước sau điền: candidates -> match -> generate
            return []
        except Exception as exc:
            logger.error("Packet %s could not be evaluated: %r", event.packet_id, exc)
            logger.info("Traceback of packet %s", event.packet_id, exc_info=True)
            return []

# file này là Rule Evaluation Engine: điều phối đánh giá một event qua các rule
# hợp đồng của module; EvaluationEngine.evaluate (bỏ event drop, candidates -> match -> generate, chặn lỗi) và stats()
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

from idscore.detection.generator import generate
from idscore.detection.matcher import match
from idscore.detection.repository import RuleRepository
from idscore.models.detection import DetectionEvent
from idscore.models.event import ACTION_DROP, Event
from idscore.models.flow import FlowContext
from idscore.models.rule import Rule

logger = logging.getLogger(__name__)


class EvaluationEngine:
    # nhận repository thay vì tự nạp rule hay đọc config, để testcase truyền được bộ rule riêng
    def __init__(self, repository: RuleRepository) -> None:
        self._repository = repository
        # thống kê theo mục 4.5; engine chỉ cung cấp stats(), tổng kết cuối lượt chạy là việc của cli
        self.events_received = 0 # mọi lần gọi evaluate
        self.events_skipped = 0 # event bị drop
        self.events_evaluated = 0 # event đã lấy được candidate
        self.events_failed = 0 # event rơi vào lưới chặn ngoài cùng
        self.candidates_total = 0
        self.matches_total = 0 # chỉ tính Detection Event dựng thành công
        self.rule_errors = 0 # số lần một rule lỗi khi match/generate
        self.matches_by_sid: dict[int, int] = {}
        # rule đã báo lỗi ở mức error; rule lỗi cố định sẽ lỗi ở mọi packet nên các lần sau chỉ ghi debug
        self._reported: set[tuple[str, int]] = set()

    # đánh giá một event, trả list mới (rỗng nếu không rule nào khớp); một event có thể khớp nhiều rule
    # không bao giờ raise: một packet lỗi không được làm dừng chương trình
    def evaluate(self, event: Event, ctx: FlowContext | None) -> list[DetectionEvent]:
        self.events_received += 1
        try:
            # cli không ghi event bị drop vào events.jsonl, sinh cảnh báo thì packet_id không tra ngược được
            if event.processing_action == ACTION_DROP:
                self.events_skipped += 1
                return []

            candidates = self._repository.candidates(event)
            self.events_evaluated += 1
            self.candidates_total += len(candidates)

            # duyệt hết candidate theo thứ tự nạp (nhiều rule có thể cùng khớp một event),
            # mỗi rule một try riêng để một rule lỗi không làm dừng các rule còn lại
            results: list[DetectionEvent] = []
            for rule in candidates:
                try:
                    matches = match(rule, event, ctx)
                    if matches is None:
                        continue
                    detection = generate(rule, event, ctx, matches)
                except Exception as exc:
                    self._record_rule_error(rule, event, exc)
                    continue
                # đếm sau khi generate thành công, nếu không sẽ lệch với số Detection Event thực
                self.matches_total += 1
                self.matches_by_sid[rule.sid] = self.matches_by_sid.get(rule.sid, 0) + 1
                results.append(detection)
            return results
        except Exception as exc:
            self.events_failed += 1
            logger.error("Packet %s could not be evaluated: %r", event.packet_id, exc)
            logger.info("Traceback of packet %s", event.packet_id, exc_info=True)
            return []

    def _record_rule_error(self, rule: Rule, event: Event, exc: Exception) -> None:
        self.rule_errors += 1
        key = (rule.source_file, rule.line_no)
        level = logging.DEBUG if key in self._reported else logging.ERROR
        self._reported.add(key)
        logger.log(
            level, "Packet %s: rule sid %s (%s:%d) failed: %r",
            event.packet_id, rule.sid, rule.source_file, rule.line_no, exc,
        )
        logger.info("Traceback of rule %s:%d", rule.source_file, rule.line_no, exc_info=True)

    # thống kê tĩnh theo thời điểm gọi, trả dict mới; avg_candidates so với rules_indexed cho thấy
    # indexer có loại bớt rule hay không (mục 4.3)
    def stats(self) -> dict:
        evaluated = self.events_evaluated
        return {
            "events_received": self.events_received,
            "events_skipped": self.events_skipped,
            "events_evaluated": evaluated,
            "events_failed": self.events_failed,
            "candidates_total": self.candidates_total,
            "matches_total": self.matches_total,
            "rule_errors": self.rule_errors,
            "matches_by_sid": dict(self.matches_by_sid),
            "rules_indexed": len(self._repository),
            "avg_candidates": round(self.candidates_total / evaluated, 2) if evaluated else 0,
        }

# đây là file điều hướng cơ bản của module preprocessor

import logging
from typing import Any

from idscore.models.event import (
    ACTION_PASS,
    PREPROCESS_INVALID,
    PREPROCESS_PARTIAL,
    PREPROCESS_VALID,
    Event,
)
from idscore.preprocessor.normalize import (
    normalize_dns_names,
    normalize_headers,
    normalize_ip,
    normalize_protocol,
    normalize_timestamp,
    normalize_uri_path,
)

# khởi tạo log
logger = logging.getLogger(__name__)

SEVERITY = {PREPROCESS_VALID: 0, PREPROCESS_PARTIAL: 1, PREPROCESS_INVALID: 2}


class Preprocessor:
    def __init__(self, config: dict[str, Any]) -> None:
        # load các config liên quan đến preprocessor
        settings = config["preprocess"]
        self.invalid_policy = settings["invalid_policy"]
        self.unsupported_policy = settings["unsupported_policy"]

    # định nghĩa quy trình xử lý 1 event
    def process(self, event: Event) -> None:
        # 2 giá trị preprocessor điền vào event
        event.preprocess_status = PREPROCESS_VALID
        event.processing_action = ACTION_PASS

        try: # quy trình thực hiện
            # chuẩn hóa
            self._normalize(event)

            # kiểm tra các tính hợp lệ của các field
            self._validate(event)

            # áp policy từ config để gán action cho gói tin
            self._apply_policy(event)
        except Exception as exc:
            # nếu lỗi thì ghi log tùy trường hợp
            logger.error(
                "Packet %d could not be preprocessed: %r", event.packet_id, exc
            )
            logger.info("Traceback of packet %d", event.packet_id, exc_info=True)
            event.errors.append(f"preprocessor: process raised {exc!r}")
            self._downgrade(
                event, PREPROCESS_PARTIAL, f"preprocessor raised {exc!r}"
            )

    # lần lượt gọi các hàm để chuẩn hóa các giá trị trong event
    def _normalize(self, event: Event) -> None:
        event.transport_protocol = normalize_protocol(event.transport_protocol)
        event.app_protocol = normalize_protocol(event.app_protocol)
        event.src_ip = normalize_ip(event.src_ip)
        event.dst_ip = normalize_ip(event.dst_ip)
        event.timestamp = normalize_timestamp(event.timestamp)

        if not isinstance(event.app, dict):
            return

        if "headers" in event.app:
            event.app["headers"] = normalize_headers(event.app["headers"])
        normalize_dns_names(event.app)

        uri = event.uri_decoded or event.app.get("uri")
        if isinstance(uri, str) and uri:
            event.uri_normalized = normalize_uri_path(uri)

    def _validate(self, event: Event) -> None:
        pass

    def _apply_policy(self, event: Event) -> None:
        pass

    @staticmethod
    # hạ status của preprocessor
    def _downgrade(event: Event, status: str, reason: str) -> None:
        current = event.preprocess_status or PREPROCESS_VALID
        if SEVERITY[status] > SEVERITY[current]:
            event.preprocess_status = status
        event.reason.append(reason)

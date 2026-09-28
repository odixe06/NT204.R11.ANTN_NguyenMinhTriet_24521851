#pipeline tổng thể cho quá trình parser ghi thông tin các gói tin vào event

from collections.abc import Sequence
from typing import Any

from idscore.models.event import Event
from idscore.parsers.base import BaseParser


class Pipeline:
    """Run one parser per layer over a packet and return the filled ``Event``."""

    # nhận parser cho từng layer
    def __init__(
        self,
        link_parsers: Sequence[BaseParser],
        network_parsers: Sequence[BaseParser],
        transport_parsers: Sequence[BaseParser],
    ) -> None:
        # chuyển về dạng list các parser trong một tầng
        self.link_parsers = list(link_parsers)
        self.network_parsers = list(network_parsers)
        self.transport_parsers = list(transport_parsers)

    # tạo event trước với các field trong metadata
    def process(
        self,
        packet: Any,
        timestamp: float,
        packet_id: int,
        source: str,
        source_type: str,
    ) -> Event:
        """Parse ``packet`` layer by layer into a new ``Event``."""
        event = Event(
            packet_id=packet_id,
            timestamp=timestamp,
            source=source,
            source_type=source_type,
        )

        # chạy parser tầng data link trước 
        self._run_layer(self.link_parsers, packet, event)

        # chạy parser tầng network -> không xử lý được thì hạ xuống unknown
        if not self._run_layer(self.network_parsers, packet, event):
            self._unknown(event)
            return event

        # chạy parser tầng transport -> không xử lý được thì hạ xuống unknown
        if not self._run_layer(self.transport_parsers, packet, event):
            self._unknown(event)

        return event

    def _run_layer(
        self, parsers: Sequence[BaseParser], packet: Any, event: Event
    ) -> bool:
        for parser in parsers:
            try:
                handled = parser.can_parse(packet)
            except Exception as exc:
                self._parser_raised(event, parser, "can_parse", exc)
                continue

            if not handled:
                continue

            try:
                parser.parse(packet, event)
            except Exception as exc:
                self._parser_raised(event, parser, "parse", exc)
            return True

        return False

    # định dạng lỗi: tên parser, tên hàm, nội dung exception, hạ xuống MALFORMED
    def _parser_raised(
        self, event: Event, parser: BaseParser, method: str, exc: Exception
    ) -> None:
        event.errors.append(f"pipeline: {parser.name}.{method} raised {exc!r}")
        event.parse_status = "MALFORMED"

    # hàm hạ xuống unknown (chỉ hạ từ trạng thái OK)
    def _unknown(self, event: Event) -> None:
        if event.parse_status == "OK":
            event.parse_status = "UNKNOWN"

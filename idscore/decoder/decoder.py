# file điều phối thành phần decoder, đứng sau parser
# tất cả những phần được đến decoder đều từ field app của event

import logging

from idscore.models.event import (
    DECODE_FAILED,
    DECODE_OK,
    DECODE_PARTIAL,
    Event,
)

logger = logging.getLogger(__name__)

SEVERITY = {DECODE_OK: 0, DECODE_PARTIAL: 1, DECODE_FAILED: 2}


class Decoder:
    def decode(self, event: Event) -> None:
        if not isinstance(event.app, dict):
            return

        try:
            if event.app_protocol == "HTTP":
                self._decode_http(event)
            elif event.app_protocol == "SMTP":
                self._decode_smtp(event)
        except Exception as exc:
            logger.error("Packet %d could not be decoded: %r", event.packet_id, exc)
            logger.info("Traceback of packet %d", event.packet_id, exc_info=True)
            event.errors.append(f"decoder: decode raised {exc!r}")
            event.decode_status = self._merge_status(event.decode_status, DECODE_FAILED)

    # decode cho body của http
    def _decode_http(self, event: Event) -> None:
        self._merge_text_status(
            event, event.app.get("body"), event.app.get("body_text_status")
        )

    # decode cho body của smtp
    def _decode_smtp(self, event: Event) -> None:
        self._merge_text_status(
            event, event.app.get("payload_text"), event.app.get("payload_text_status")
        )

    # hàm gộp status
    # event k có phần nào được decode -> None
    # có 1 thành phần k decode được -> partial 
    def _merge_text_status(
        self, event: Event, text: str | None, status: str | None
    ) -> None:
        if text and status is not None:
            event.decode_status = self._merge_status(event.decode_status, status)

    @staticmethod
    def _merge_status(current: str | None, new: str) -> str:
        if current is None:
            return new
        return max(current, new, key=SEVERITY.__getitem__)

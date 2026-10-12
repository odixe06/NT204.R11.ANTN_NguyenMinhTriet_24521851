# file điều phối thành phần decoder, đứng sau parser
# tất cả những phần được đến decoder đều từ field app của event

import logging

from idscore.decoder.http import (
    decode_form,
    decode_html,
    decode_uri,
    is_form_urlencoded,
    is_html,
)
from idscore.decoder.status import merge_status
from idscore.models.event import DECODE_FAILED, Event

logger = logging.getLogger(__name__)


class Decoder:

    # gọi các thành phần decode cụ thể: input là 1 event
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
            event.decode_status = merge_status(event.decode_status, DECODE_FAILED)

    # decode cho body của http
    def _decode_http(self, event: Event) -> None:
        uri = event.app.get("uri")
        if uri:
            event.uri_decoded, status = decode_uri(uri)
            event.decode_status = merge_status(event.decode_status, status)
        self._merge_text_status(
            event, event.app.get("body"), event.app.get("body_text_status")
        )

        body = event.app.get("body")
        headers = event.app.get("headers") or {}
        content_type = headers.get("content-type")
        # nếu body rỗng 
        if not body:
            return

        # chia làm 3 TH:
        # decode_form, decode html, còn lại thì return 
        if is_form_urlencoded(content_type):
            event.body_decoded, status = decode_form(body)
        elif is_html(content_type):
            event.body_decoded, status = decode_html(body)
        else:
            return
        event.decode_status = merge_status(event.decode_status, status)

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
            event.decode_status = merge_status(event.decode_status, status)

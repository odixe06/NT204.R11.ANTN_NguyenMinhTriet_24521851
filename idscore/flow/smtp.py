import logging
import re

from idscore.decoder.mime import decode_mime_body, parse_headers, transfer_encoding
from idscore.decoder.status import merge_status
from idscore.models.event import DECODE_FAILED, Event
from idscore.models.flow import (
    SMTP_STATE_COMMAND,
    SMTP_STATE_DATA,
    SMTP_STATE_DATA_PENDING,
    Flow,
)

logger = logging.getLogger(__name__)

SMTP_PROTOCOL = "SMTP"

DATA_MESSAGE_TYPE = "data"
DATA_VERB = "DATA"
READY_FOR_DATA_CODE = 354
END_OF_DATA_ONLY = ".\r\n"
END_OF_DATA_SUFFIX = "\r\n.\r\n"
HEADER_BODY_SEPARATOR = "\r\n\r\n"
BLANK_LINE_START = "\r\n"
COMMAND_RESPONSE_KEYS = ("commands", "code", "messages", "final")
END_OF_DATA_TAIL_LEN = 3
DOT_STUFFED_LINE = re.compile(r"(^|\r\n)\.\.")


def update_smtp_session(flow: Flow, event: Event, direction: str) -> None:
    app = event.app
    if not isinstance(app, dict):
        return
    text = app.get("payload_text")
    if not isinstance(text, str) or not text:
        return

    in_data = (
        flow._smtp_state == SMTP_STATE_DATA and direction == flow._smtp_client_dir
    )
    if in_data:
        _reclassify_as_data(app, event)
        headers_done_before = flow._smtp_headers_done
        _read_encoding(flow, text)
        _decode_body_safely(flow, event, text, headers_done_before)

    _transition(flow, app, text, direction)


def _transition(flow: Flow, app: dict, text: str, direction: str) -> None:
    state = flow._smtp_state
    if state == SMTP_STATE_COMMAND:
        if app.get("message_type") == "command" and _has_data_verb(app):
            flow._smtp_state = SMTP_STATE_DATA_PENDING
            flow._smtp_client_dir = direction
    elif state == SMTP_STATE_DATA_PENDING:
        if app.get("message_type") == "response" and direction != flow._smtp_client_dir:
            if app.get("code") == READY_FOR_DATA_CODE:
                flow._smtp_state = SMTP_STATE_DATA
                flow._smtp_encoding = None
                flow._smtp_headers_done = False
            else:
                flow._smtp_state = SMTP_STATE_COMMAND
    elif state == SMTP_STATE_DATA:
        if direction == flow._smtp_client_dir and _ends_data(text):
            flow._smtp_state = SMTP_STATE_COMMAND


def _reclassify_as_data(app: dict, event: Event) -> None:
    message_type = app.get("message_type")
    if message_type == DATA_MESSAGE_TYPE:
        return

    if message_type is not None:
        app["reclassified_from"] = message_type
    app["message_type"] = DATA_MESSAGE_TYPE
    for key in COMMAND_RESPONSE_KEYS:
        app.pop(key, None)
    payload_len = event.payload_len
    if isinstance(payload_len, int) and not isinstance(payload_len, bool):
        app["data_len"] = payload_len


def _read_encoding(flow: Flow, text: str) -> None:
    if flow._smtp_headers_done:
        return

    encoding = transfer_encoding(parse_headers(text))
    if encoding is not None:
        flow._smtp_encoding = encoding
    if HEADER_BODY_SEPARATOR in text or text.startswith(BLANK_LINE_START):
        flow._smtp_headers_done = True


def _decode_body_safely(
    flow: Flow, event: Event, text: str, headers_done_before: bool
) -> None:
    try:
        _decode_body(flow, event, text, headers_done_before)
    except Exception as exc:
        logger.error("Packet %d SMTP body could not be decoded: %r", event.packet_id, exc)
        logger.info("Traceback of packet %d", event.packet_id, exc_info=True)
        event.errors.append(f"flow: smtp decode raised {exc!r}")
        event.decode_status = merge_status(event.decode_status, DECODE_FAILED)


def _decode_body(
    flow: Flow, event: Event, text: str, headers_done_before: bool
) -> None:
    body = _body_of(text, headers_done_before, flow._smtp_headers_done)
    if body is None:
        return

    body = _strip_end_of_data(body)
    body = DOT_STUFFED_LINE.sub(lambda match: match.group(1) + ".", body)
    if not body.strip():
        return

    decoded, status = decode_mime_body(body, flow._smtp_encoding)
    if status is None:
        return
    event.body_decoded = decoded
    event.decode_status = merge_status(event.decode_status, status)


def _body_of(text: str, headers_done_before: bool, headers_done_now: bool) -> str | None:
    if not headers_done_now:
        return None
    if headers_done_before:
        return text
    if text.startswith(BLANK_LINE_START):
        return text[len(BLANK_LINE_START):]
    return text.split(HEADER_BODY_SEPARATOR, 1)[1]


def _strip_end_of_data(body: str) -> str:
    if body == END_OF_DATA_ONLY:
        return ""
    if body.endswith(END_OF_DATA_SUFFIX):
        return body[:-END_OF_DATA_TAIL_LEN]
    return body


def _has_data_verb(app: dict) -> bool:
    commands = app.get("commands")
    if not isinstance(commands, list):
        return False
    return any(
        isinstance(command, dict) and command.get("verb") == DATA_VERB
        for command in commands
    )


def _ends_data(text: str) -> bool:
    return text == END_OF_DATA_ONLY or text.endswith(END_OF_DATA_SUFFIX)

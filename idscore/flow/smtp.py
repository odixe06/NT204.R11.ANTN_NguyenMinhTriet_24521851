# tracker dành cho flow smtp
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from idscore.models.event import Event
    from idscore.models.flow import Flow

# các trạng thái state của smtp
SMTP_PROTOCOL = "SMTP"
SMTP_STATE_COMMAND = "command"
SMTP_STATE_DATA_PENDING = "data_pending"
SMTP_STATE_DATA = "data"

DATA_VERB = "DATA"
READY_FOR_DATA_CODE = 354
END_OF_DATA_ONLY = ".\r\n"
END_OF_DATA_SUFFIX = "\r\n.\r\n"

# hàm cập nhật trạng thái flow smtp
def update_smtp_session(flow: "Flow", event: "Event", direction: str) -> None:
    app = event.app
    if not isinstance(app, dict):
        return
    text = app.get("payload_text")
    if not isinstance(text, str) or not text:
        return

    state = flow._smtp_state
    if state == SMTP_STATE_COMMAND:
        if app.get("message_type") == "command" and _has_data_verb(app):
            flow._smtp_state = SMTP_STATE_DATA_PENDING
            flow._smtp_client_dir = direction
    elif state == SMTP_STATE_DATA_PENDING:
        if app.get("message_type") == "response" and direction != flow._smtp_client_dir:
            if app.get("code") == READY_FOR_DATA_CODE:
                flow._smtp_state = SMTP_STATE_DATA
            else:
                flow._smtp_state = SMTP_STATE_COMMAND
    elif state == SMTP_STATE_DATA:
        if direction == flow._smtp_client_dir and _ends_data(text):
            flow._smtp_state = SMTP_STATE_COMMAND


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

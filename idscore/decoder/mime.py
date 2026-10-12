# file này dùng để decode cho những payload smtp

import base64
import binascii
import quopri
import re

from idscore.decoder.status import merge_status
from idscore.models.event import DECODE_FAILED, DECODE_OK, DECODE_PARTIAL
from idscore.utils.text import decode_text

TRANSFER_ENCODING_HEADER = "content-transfer-encoding"
BASE64_BLOCK_LEN = 4
NO_ENCODING_VALUES = frozenset({"7bit", "8bit", "binary"})
WHITESPACE = re.compile(r"\s+")

# ghi các header
def parse_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    name: str | None = None
    for line in text.splitlines():
        if line[:1] in (" ", "\t"):
            if name is not None:
                headers[name] = f"{headers[name]} {line.strip()}".strip()
            continue

        key, separator, value = line.partition(":")
        if not separator:
            name = None
            continue

        name = key.strip().lower()
        if name in headers:
            name = None
            continue
        headers[name] = value.strip()
    return headers


def transfer_encoding(headers: dict[str, str]) -> str | None:
    value = headers.get(TRANSFER_ENCODING_HEADER)
    if value is None:
        return None
    return value.strip().lower()

# có 2 dạng mã hóa của MIME là base64 và quoted-printable
# xử lý với 2 hàm khác nhau dựa vào giá trị transfer encoding

def decode_base64(text: str) -> tuple[str | None, str]:
    compact = WHITESPACE.sub("", text)
    usable_len = len(compact) - len(compact) % BASE64_BLOCK_LEN
    status = DECODE_OK if usable_len == len(compact) else DECODE_PARTIAL

    try:
        data = base64.b64decode(compact[:usable_len], validate=True)
    except (binascii.Error, ValueError):
        return None, DECODE_FAILED

    decoded, text_status = decode_text(data)
    return decoded, merge_status(status, text_status)


def decode_quoted_printable(text: str) -> tuple[str, str]:
    return decode_text(quopri.decodestring(text.encode("utf-8")))


def decode_mime_body(
    body: str, encoding: str | None
) -> tuple[str | None, str | None]:
    if encoding is None or encoding in NO_ENCODING_VALUES:
        return None, None
    if encoding == "base64":
        return decode_base64(body)
    if encoding == "quoted-printable":
        return decode_quoted_printable(body)
    return None, DECODE_FAILED

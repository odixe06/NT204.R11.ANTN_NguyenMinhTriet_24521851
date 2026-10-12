# định nghĩa cách decode các thành phần trong dict của field app với http

from urllib.parse import unquote_to_bytes

from idscore.decoder.status import merge_status
from idscore.utils.text import decode_text

QUERY_SEPARATOR = "?"
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

# decode uri: input là str uri chưa decode
# output -> uri đã decode - decode status
def decode_uri(uri: str) -> tuple[str, str]:
    path, separator, query = uri.partition(QUERY_SEPARATOR)
    path_text, path_status = _percent_decode(path)
    if not separator:
        return path_text, path_status

    query_text, query_status = _decode_form_urlencoded(query)
    status = merge_status(path_status, query_status)
    return f"{path_text}{separator}{query_text}", status


def decode_form(body: str) -> tuple[str, str]:
    return _decode_form_urlencoded(body)

# kiểm tra có nên decode body không
def is_form_urlencoded(content_type: str | None) -> bool:
    # None hoặc chuỗi rỗng thì trả False
    if not content_type:
        return False

    # Lấy phần trước ;, bỏ khoảng trắng, chuyển chữ thường
    # so sánh với FORM_CONTENT_TYPE 
    media_type = content_type.partition(";")[0].strip().lower()
    return media_type == FORM_CONTENT_TYPE


def _decode_form_urlencoded(text: str) -> tuple[str, str]:
    return _percent_decode(text.replace("+", " "))


def _percent_decode(text: str) -> tuple[str, str]:
    return decode_text(unquote_to_bytes(text))

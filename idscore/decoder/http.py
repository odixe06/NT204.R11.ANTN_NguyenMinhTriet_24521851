# định nghĩa cách decode các thành phần trong dict của field app với http

from urllib.parse import unquote_to_bytes

from idscore.models.event import DECODE_STATUSES
from idscore.utils.text import decode_text

QUERY_SEPARATOR = "?"
_SEVERITY = {status: rank for rank, status in enumerate(DECODE_STATUSES)}

# decode uri: input là str uri chưa decode
# output -> uri đã decode - decode status
def decode_uri(uri: str) -> tuple[str, str]:
    path, separator, query = uri.partition(QUERY_SEPARATOR)
    path_text, path_status = _percent_decode(path)
    if not separator:
        return path_text, path_status

    query_text, query_status = _percent_decode(query.replace("+", " "))
    status = max(path_status, query_status, key=_SEVERITY.__getitem__)
    return f"{path_text}{separator}{query_text}", status


def _percent_decode(text: str) -> tuple[str, str]:
    return decode_text(unquote_to_bytes(text))

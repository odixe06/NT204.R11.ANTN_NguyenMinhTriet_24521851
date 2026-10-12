# hàm merge status decode
# gộp các trạng thái text khi có text rỗng
from idscore.models.event import DECODE_FAILED, DECODE_OK, DECODE_PARTIAL

SEVERITY = {DECODE_OK: 0, DECODE_PARTIAL: 1, DECODE_FAILED: 2}


def merge_status(current: str | None, new: str) -> str:
    if current is None:
        return new
    return max(current, new, key=SEVERITY.__getitem__)

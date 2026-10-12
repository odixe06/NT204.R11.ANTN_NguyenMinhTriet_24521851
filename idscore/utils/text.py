# file này định nghĩa hàm helper dùng để decode phần body tại tầng application 

from idscore.models.event import DECODE_STATUSES

# 2 trạng thái: ok, partial
DECODE_OK, DECODE_PARTIAL, _ = DECODE_STATUSES

# input là bytes -> trả về tuple[str đã decode, decode status]
def decode_text(data: bytes) -> tuple[str, str]:
    try:
        # decode utf 8 thành công -> ok
        return data.decode("utf-8"), DECODE_OK
    # nếu không decode được UTF 8 -> errors replace để decode lại 
    # hạ decodes status xuống partial
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), DECODE_PARTIAL

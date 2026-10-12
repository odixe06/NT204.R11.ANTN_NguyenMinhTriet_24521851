# helper dùng để decode

import codecs

from idscore.models.event import DECODE_OK, DECODE_PARTIAL

# nhận data là bytes, trả về dạng [nội dung đã decode , status]
def decode_text(data: bytes, final: bool = True) -> tuple[str, str]:
    try:
        # nếu decode utf 8 -> trả về ok
        if final:
            return data.decode("utf-8"), DECODE_OK
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        return decoder.decode(data, final=False), DECODE_OK
        # nếu decode utf 8 thất bại -> error = "replace" và hạ status xuống partial
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), DECODE_PARTIAL

# hàm cắt bớt body và decode dùng chung của các app parser
def body_fields(
    # input
    data: bytes, # bytes của body
    limit: int, # max_byte của body
    text_key: str = "body", 
    truncated_key: str = "body_truncated", # body có bị cắt k -> true/false
    status_key: str = "body_text_status", 
) -> dict:
    truncated = len(data) > limit
    text, status = decode_text(data[:limit], final=not truncated)
    return {text_key: text, truncated_key: truncated, status_key: status}

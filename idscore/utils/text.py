# helper dùng để chuyển từ byte -> string với UTF 8 
# helper này dùng cho parser để ghi vào các dict trong field app của event

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
        if final:
            return data.decode("utf-8", errors="replace"), DECODE_PARTIAL
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        return decoder.decode(data, final=False), DECODE_PARTIAL

# hàm cắt bớt body và decode dùng chung của các app parser
def body_fields(
    # input
    data: bytes, # bytes của body
    limit: int, # max_byte của body
    text_key: str = "body", # key lưu body (mặc định "body")
    truncated_key: str = "body_truncated", # key body có bị cắt k 
    status_key: str = "body_text_status", # key lưu trạng thái decode
) -> dict:
    truncated = len(data) > limit # nếu lớn hơn limit -> cắt
    text, status = decode_text(data[:limit], final=not truncated) 
    # trả về dict: text là body đã được decode, truncated = true/false, decode_status: ok/partial
    return {text_key: text, truncated_key: truncated, status_key: status} 

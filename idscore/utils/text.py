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

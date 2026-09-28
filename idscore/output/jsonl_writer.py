# file này xây dựng class Jsonl writer, kế thừa BaseWriter 
# ghi các đối tượng event vào file định dạng json lines (mỗi sự kiện 1 dòng)

import json
from pathlib import Path

from idscore.models.event import Event
from idscore.output.base import BaseWriter

SEPARATORS = (",", ":")


class JsonlWriter(BaseWriter):
    """Append events to a JSON Lines file, one line per event, flushed in batches."""

    # khởi tạo và ghi các chuỗi json vào buffer trước khi lưu vào ổ cứng
    def __init__(self, path: str, batch_size: int = 100) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open(mode="a", encoding="utf-8")
        self._batch_size = batch_size
        self._buffer: list[str] = []

    # chuyển event thành json rồi đưa vào buffer
    def write(self, event: Event) -> None:
        """Serialise ``event`` now and flush once the batch is full."""
        line = json.dumps(
            event.to_dict(), separators=SEPARATORS, default=self._default
        )
        self._buffer.append(f"{line}\n")

        # khi số dòng >= batch_size -> flush
        if len(self._buffer) >= self._batch_size:
            self.flush()

    # hàm đẩy từ buffer xuống ổ cứng, rồi làm rỗng buffer
    def flush(self) -> None:
        if not self._buffer:
            return

        self._file.writelines(self._buffer)
        self._buffer.clear()
        self._file.flush()

    # ghi những dữ liệu cuối trong buffer và đóng file
    def close(self) -> None:
        if self._file.closed:
            return

        self.flush()
        self._file.close()

    @staticmethod
    # hàm để chuyển định dạng lạ của event sang dạng có thể ghi vào json (hex, str)
    def _default(obj: object) -> str:
        if isinstance(obj, (bytes, bytearray)):
            return obj.hex()
        return str(obj)

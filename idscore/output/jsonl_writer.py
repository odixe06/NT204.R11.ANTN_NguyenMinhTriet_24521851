import json
from pathlib import Path

from idscore.models.event import Event
from idscore.output.base import BaseWriter

SEPARATORS = (",", ":")


class JsonlWriter(BaseWriter):
    """Append events to a JSON Lines file, one line per event, flushed in batches."""

    def __init__(self, path: str, batch_size: int = 100) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open(mode="a", encoding="utf-8")
        self._batch_size = batch_size
        self._buffer: list[str] = []

    def write(self, event: Event) -> None:
        """Serialise ``event`` now and flush once the batch is full."""
        line = json.dumps(
            event.to_dict(), separators=SEPARATORS, default=self._default
        )
        self._buffer.append(f"{line}\n")

        if len(self._buffer) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return

        self._file.writelines(self._buffer)
        self._buffer.clear()
        self._file.flush()

    def close(self) -> None:
        if self._file.closed:
            return

        self.flush()
        self._file.close()

    @staticmethod
    def _default(obj: object) -> str:
        if isinstance(obj, (bytes, bytearray)):
            return obj.hex()
        return str(obj)

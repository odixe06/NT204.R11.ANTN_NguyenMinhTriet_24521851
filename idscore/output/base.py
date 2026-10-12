# file này định nghĩa interface chung cho mọi writer
# định nghĩa class trừu tượng BaseWriter
# code xử lý nằm ở các file cụ thể khác, class con của class này

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Protocol, Self


class Record(Protocol):
    def to_dict(self) -> dict: ...


class BaseWriter(ABC):
    """Destination a ``Record`` is written to, used by the CLI as a context manager."""

    # hàm nhận record (event, flow, ... bất kỳ object nào có to_dict) và xử lý
    @abstractmethod
    def write(self, record: Record) -> None:
        """Write one record; turning it into the output format is the writer's job."""
        ...

    # hàm để đẩy dữ liệu trong buffer xuống đích hết -> đóng file an toàn
    @abstractmethod
    def close(self) -> None:
        """Flush whatever is still buffered and release the destination."""
        ...

    # hàm để gọi self
    def __enter__(self) -> Self:
        return self

    # hàm đóng kết nối 
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

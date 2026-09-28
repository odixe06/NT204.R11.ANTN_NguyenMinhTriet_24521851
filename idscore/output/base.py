from abc import ABC, abstractmethod
from types import TracebackType

from idscore.models.event import Event


class BaseWriter(ABC):
    """Destination an ``Event`` is written to, used by the CLI as a context manager."""

    @abstractmethod
    def write(self, event: Event) -> None:
        """Write one event; turning it into the output format is the writer's job."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Flush whatever is still buffered and release the destination."""
        ...

    def __enter__(self) -> "BaseWriter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

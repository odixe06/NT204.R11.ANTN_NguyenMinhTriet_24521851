# file này định nghĩa cách bắt gói tin từ file pcap  
# sử dụng class con PcapCapture  

import logging
from pathlib import Path
from collections.abc import Iterator
from typing import Literal

from scapy.packet import Packet, Raw
from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from idscore.capture.base import BaseCapture, CaptureError

logger = logging.getLogger(__name__)

PCAP_RECORD_HEADER_LEN = 16


class PcapCapture(BaseCapture):
# kế thừa -> dùng để đọc những packet từ file pcap
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def source(self) -> str:
        return str(self._path)

    @property
    def source_type(self) -> Literal["pcap"]: 
        return "pcap"

    def packets(self) -> Iterator[tuple[Packet, float]]:
        try:
            # kiểm tra giao thức ở tầng datalinj
            with PcapReader(str(self._path)) as reader:
                link_layer = getattr(reader, "LLcls", None)

                # nếu loại giao thức k hỗ trợ thì k đưa vào pipeline
                if link_layer is Raw:
                    raise CaptureError(
                        f"unsupported link type {reader.linktype} "
                        f"in PCAP '{self._path}'"
                    )

                expected_end = reader.f.tell()

                for packet in reader:
                    expected_end += PCAP_RECORD_HEADER_LEN + len(packet.original)
                    yield packet, float(packet.time)
                    # yield là generator, mỗi lần lặp sẽ trả về một tuple gồm packet và timestamp của packet đó

                if link_layer is not None:
                    leftover = reader.f.tell() - expected_end
                    if leftover > 0:
                        logger.warning(
                            "PCAP '%s' ends with %d bytes that do not form a "
                            "complete record",
                            self._path,
                            leftover,
                        )
        except (OSError, Scapy_Exception) as error:
            raise CaptureError(
                f"Unable to read PCAP '{self._path}': {error}"
            ) from error
                
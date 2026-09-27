# file này định nghĩa cách bắt gói tin từ file pcap  
# sử dụng class con PcapCapture  

from pathlib import Path
from typing import Literal

from scapy.packet import Packet
from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from idscore.capture.base import BaseCapture, CaptureError


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

    def packets(self):
        try:
            with PcapReader(str(self._path)) as reader:
                for packet in reader:
                    yield packet, float(packet.time) 
                    # yield là generator, mỗi lần lặp sẽ trả về một tuple gồm packet và timestamp của packet đó
        except (OSError, Scapy_Exception) as error:
            raise CaptureError(
                f"Unable to read PCAP '{self._path}': {error}"
            ) from error
                
# file này định nghĩa cách bắt một gói tin dữ liệu từ một nguồn (pcap - file hoặc live - card mạng) 
# định nghĩa một lớp trừu tượng BaseCapture, từ đó sinh ra các lớp con PcapCapture và LiveCapture

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Literal

from scapy.packet import Packet
import scapy.layers.inet  # noqa: F401  nạp Ether, IP, TCP, UDP cho dissector


class CaptureError(Exception):
    """A packet-source error exposed by the capture layer."""


class BaseCapture(ABC):
# dùng module abc là lớp trừu tượng, từ đó để sinh ra các lớp con 
    @property
    @abstractmethod # nhãn nãy đánh dấu những thuộc tính/hàm bắt buộc có ở class con của BaseCapture
    def source(self) -> str:
        """Capture identifier: a PCAP path or a live interface name."""
        ...
    # source sẽ là một đường dẫn tới file pcap hoặc một card mạng bắt trực tiếp

    @property
    @abstractmethod
    def source_type(self) -> Literal["pcap", "live"]: # literal để dễ đọc  
        """Capture kind; the only valid values are ``pcap`` and ``live``."""
        ...
    # nguồn là file pcap hoặc live

    @abstractmethod
    def packets(self) -> Iterator[tuple[Packet, float]]: 
        ...
    # khi chạy ở class con, method packets sẽ trả về một iterator, mỗi lần lặp sẽ trả về một tuple gồm packet và timestamp của packet đó

# 2 class con của BaseCapture là PcapCapture và LiveCapture
# mỗi class sẽ implement các method abstract của BaseCapture


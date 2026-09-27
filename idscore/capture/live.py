# file này định nghĩa cách bắt gói tin từ card mạng   
# sử dụng class con LiveCapture

from collections.abc import Iterator
from queue import Empty, Queue
from typing import Literal

from scapy.packet import Packet
from scapy.error import Scapy_Exception
from scapy.sendrecv import AsyncSniffer

from idscore.capture.base import BaseCapture, CaptureError


class LiveCapture(BaseCapture):
    def __init__(self, interface: str) -> None:
        self._interface = interface

    @property
    def source(self) -> str:
        return self._interface

    @property
    def source_type(self) -> Literal["live"]:
        return "live"

    def packets(self) -> Iterator[tuple[Packet, float]]:
        packet_queue: Queue[Packet] = Queue() 
        #tạo hàng đợi ngầm
        sniffer = AsyncSniffer( 
            iface=self._interface,
            prn=packet_queue.put, 
            store=False,
        )
        # đẩy trực tiếp gói tin bắt được vào hàng đợi chứ k lưu -> tránh tràn RAM

        sniffer.start()

        try:
            while True:
                try:
                    packet = packet_queue.get(timeout=0.5)
                except Empty:
                    if sniffer.exception is not None:
                        raise sniffer.exception
                    if not sniffer.running:
                        break
                    continue
                yield packet, float(packet.time)
        except (OSError, ValueError, Scapy_Exception) as error:
            raise CaptureError(
                f"Unable to capture from interface '{self._interface}': {error}"
            ) from error
        finally:
            if sniffer.running:
                try:
                    sniffer.stop()
                except Exception:
                    if sniffer.exception is None:
                        raise
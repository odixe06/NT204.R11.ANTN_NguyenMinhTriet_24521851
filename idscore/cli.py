# file này điều phối giữa cli và các class con của BaseCapture 

import argparse
import sys
from collections.abc import Sequence

from idscore.capture.base import BaseCapture, CaptureError
from idscore.capture.live import LiveCapture
from idscore.capture.pcap import PcapCapture


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the IDS packet capture.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--interface", help="Capture packets from an interface.")
    source_group.add_argument("--pcap", help="Read packets from a PCAP file.")
    return parser.parse_args(argv)
# kiểm tra tham số từ cli, từ đó chọn bắt gói tin từ đâu  


def build_capture(args: argparse.Namespace) -> BaseCapture:
    if args.interface is not None:
        return LiveCapture(args.interface)
    return PcapCapture(args.pcap)
# chọn class con của BaseCapture để bắt gói tin từ card mạng hoặc file pcap


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    capture = build_capture(args)
    packet_count = 0

    try:
        for packet_count, _ in enumerate(capture.packets(), start=1):
            pass
    except KeyboardInterrupt:
        print(f"Total packets: {packet_count}")
        return 0
    except CaptureError as error:
        print(f"Capture error: {error}", file=sys.stderr)
        return 1

    print(f"Total packets: {packet_count}")
    return 0
# thực hiện vòng lặp bắt gói tin, đếm số lượng gói tin bắt được, nếu có lỗi thì in ra thông báo lỗi
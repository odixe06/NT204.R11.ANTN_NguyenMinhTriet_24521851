# file này điều phối giữa cli và các module khác trong ids 

import argparse # thư viện xử lý tham số cli
import json
import sys
from collections.abc import Sequence

from idscore.capture.base import BaseCapture, CaptureError
from idscore.capture.live import LiveCapture
from idscore.capture.pcap import PcapCapture
from idscore.parsers.application.detector import AppProtocolDetector
from idscore.parsers.link.ethernet import EthernetParser
from idscore.parsers.network.ipv4 import IPv4Parser
from idscore.parsers.transport.tcp import TCPParser
from idscore.parsers.transport.udp import UDPParser
from idscore.pipeline import Pipeline

# kiểm tra tham số từ cli, từ đó chọn bắt gói tin từ đâu  
def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the IDS packet capture.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--interface", help="Capture packets from an interface.")
    source_group.add_argument("--pcap", help="Read packets from a PCAP file.")
    return parser.parse_args(argv)

# chọn class con của BaseCapture để bắt gói tin từ card mạng hoặc file pcap
def build_capture(args: argparse.Namespace) -> BaseCapture:
    if args.interface is not None:
        return LiveCapture(args.interface)
    return PcapCapture(args.pcap)


# chọn parser cho từng tầng, Pipeline không cần biết đang có những parser nào
def build_pipeline() -> Pipeline:
    return Pipeline(
        [EthernetParser()],
        [IPv4Parser()],
        [TCPParser(), UDPParser()],

        # sau đó chạy đến detector
        [AppProtocolDetector()],
    )


# thực hiện vòng lặp bắt gói tin, đếm số lượng gói tin bắt được
# nếu có lỗi thì in ra thông báo lỗi
def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    capture = build_capture(args)
    pipeline = build_pipeline()
    packet_count = 0

    try:
        for packet_id, (packet, timestamp) in enumerate(capture.packets(), start=1):
            packet_count = packet_id
            event = pipeline.process(
                packet,
                timestamp,
                packet_id,
                capture.source,
                capture.source_type,
            )
            print(json.dumps(event.to_dict()))
    except KeyboardInterrupt:
        print(f"Total packets: {packet_count}", file=sys.stderr)
        return 0
    except CaptureError as error:
        print(f"Capture error: {error}", file=sys.stderr)
        return 1

    print(f"Total packets: {packet_count}", file=sys.stderr)
    return 0

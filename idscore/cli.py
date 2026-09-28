# file này điều phối giữa cli và các module khác trong ids 

import argparse # thư viện xử lý tham số cli
import logging
import sys
from collections.abc import Sequence

from idscore.capture.base import BaseCapture, CaptureError
from idscore.capture.live import LiveCapture
from idscore.capture.pcap import PcapCapture
from idscore.output.jsonl_writer import JsonlWriter
from idscore.parsers.application.detector import AppProtocolDetector
from idscore.parsers.application.registry import build_app_parsers
from idscore.parsers.link.ethernet import EthernetParser
from idscore.parsers.network.ipv4 import IPv4Parser
from idscore.parsers.transport.tcp import TCPParser
from idscore.parsers.transport.udp import UDPParser
from idscore.pipeline import Pipeline
from idscore.utils.logger import setup_logging

logger = logging.getLogger(__name__)


# kiểm tra tham số từ cli, từ đó chọn bắt gói tin từ đâu  
def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the IDS packet capture.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--interface", help="Capture packets from an interface.")
    source_group.add_argument("--pcap", help="Read packets from a PCAP file.")

    # nếu người dùng không truyền gì thì ghi vào event.jsonl và ids.log
    # nếu không thì truyền tham số để đổi vị trí
    parser.add_argument(
        "--output",
        default="logs/events.jsonl",
        help="JSON Lines file the events are appended to.",
    )
    parser.add_argument(
        "--log-file",
        default="logs/ids.log",
        help="File the runtime log is appended to.",
    )
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
        build_app_parsers(),
    )


# thực hiện vòng lặp bắt gói tin, đếm số lượng gói tin bắt được
# nếu có lỗi thì in ra thông báo lỗi
def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    # khởi tạo log ngay từ đầu để module có thể ghi vào 
    setup_logging(args.log_file) 

    # khởi tạo nguồn capture và gọi pipeline xử lý
    capture = build_capture(args)
    pipeline = build_pipeline()
    packet_count = 0 # bộ đếm

    # thông tin log lúc bắt đầu
    # Reading from pcap 'data/pcap/sample.pcap'
    # writing events to 'logs/events.jsonl'
    logger.info(
        "Reading from %s '%s', writing events to '%s'",
        capture.source_type,
        capture.source,
        args.output,
    )
    
    # mở jsonl writer để ghi các event
    try:
        with JsonlWriter(args.output) as writer:
            try:
                # đọc packet
                for packet_id, (packet, timestamp) in enumerate(
                    capture.packets(), start=1
                ):
                    packet_count = packet_id
                    writer.write(
                        pipeline.process(
                            packet,
                            timestamp,
                            packet_id,
                            capture.source,
                            capture.source_type,
                        )
                    )
            except KeyboardInterrupt:
                logger.info("Capture stopped by the user")
    except CaptureError as error:
        logger.error("Capture error: %s", error)
        return 1
    except OSError as error:
        logger.error("Output error: %s", error)
        return 1

    logger.info("Total packets: %d", packet_count)
    print(f"Total packets: {packet_count}", file=sys.stderr)
    return 0

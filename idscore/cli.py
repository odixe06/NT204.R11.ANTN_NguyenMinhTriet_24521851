# file này điều phối giữa cli và các module khác trong ids 

import argparse # thư viện xử lý tham số cli
import logging
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from idscore.capture.base import BaseCapture, CaptureError
from idscore.capture.live import LiveCapture
from idscore.capture.pcap import PcapCapture
from idscore.config import ConfigError, load_config
from idscore.decoder.decoder import Decoder
from idscore.flow.tracker import FlowTracker
from idscore.models.event import (
    ACTION_DROP,
    ACTION_MARK,
    ACTION_PASS,
    PARSE_STATUSES,
    PREPROCESS_PARTIAL,
    PREPROCESS_VALID,
    Event,
)
from idscore.models.flow import Flow
from idscore.output.jsonl_writer import JsonlWriter
from idscore.parsers.application.detector import AppProtocolDetector
from idscore.parsers.application.registry import build_app_parsers
from idscore.parsers.link.ethernet import EthernetParser
from idscore.parsers.link.undecoded import UndecodedFrameParser
from idscore.parsers.network.ipv4 import IPv4Parser
from idscore.parsers.transport.tcp import TCPParser
from idscore.parsers.transport.udp import UDPParser
from idscore.pipeline import Pipeline
from idscore.preprocessor.preprocessor import Preprocessor
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
    # tham số output -> file jsonl ghi các event
        "--output",
        default="logs/events.jsonl",
        help="JSON Lines file the events are appended to.",
    )
    # tham số flow-output -> file jsonl ghi các flow 
    parser.add_argument(
        "--flow-output",
        default="logs/flows.jsonl",
        help="JSON Lines file the flows are appended to.",
    )
    # tham số log-file -> file .log ghi nội dung log
    parser.add_argument(
        "--log-file",
        default="logs/ids.log",
        help="File the runtime log is appended to.",
    )
    # file config -> truyền config đầu vào
    parser.add_argument(
        "--config",
        default="config/default.yaml",
        help="YAML file overriding the default configuration.",
    )
    return parser.parse_args(argv)

# chọn class con của BaseCapture để bắt gói tin từ card mạng hoặc file pcap
def build_capture(args: argparse.Namespace) -> BaseCapture:
    if args.interface is not None:
        return LiveCapture(args.interface)
    return PcapCapture(args.pcap)


# chọn parser cho từng tầng
# Pipeline không cần biết đang có những parser nào
def build_pipeline(config: dict[str, Any]) -> Pipeline:
    return Pipeline(
        [EthernetParser(), UndecodedFrameParser()],
        [IPv4Parser()],
        [TCPParser(), UDPParser()],

        # sau đó chạy đến detector
        [AppProtocolDetector()],
        # pipeline nhận config và truyền xuống app parser 
        build_app_parsers(config),
    )

# nếu xử lý một packet thất bại -> vẫn ghi message trong json L và gán MALFORMED
def _fallback_event(
    packet_id: int, timestamp: float, capture: BaseCapture, message: str
) -> Event:
    return Event(
        packet_id=packet_id,
        timestamp=timestamp,
        source=capture.source,
        source_type=capture.source_type,
        parse_status="MALFORMED",
        errors=[message],
    )

# xử lý khi pipeline gặp lỗi
def _process_safely(
    pipeline: Pipeline,
    packet: object,
    timestamp: float,
    packet_id: int,
    capture: BaseCapture,
) -> Event:
    try:
        # chạy bình thường
        return pipeline.process(
            packet, timestamp, packet_id, capture.source, capture.source_type
        )
        # nếu parser hoặc pipeline phát sinh lỗi ghi log để debug, trả về event fallback
    except Exception as exc:
        logger.error("Packet %d could not be processed: %r", packet_id, exc)
        logger.info("Traceback of packet %d", packet_id, exc_info=True)
        return _fallback_event(
            packet_id, timestamp, capture, f"cli: pipeline.process raised {exc!r}"
        )


def _log_step_error(event: Event, step: str, exc: Exception) -> None:
    logger.error("Packet %d failed in %s: %r", event.packet_id, step, exc)
    logger.info("Traceback of packet %d", event.packet_id, exc_info=True)
    event.errors.append(f"cli: {step} raised {exc!r}")


def _decode_safely(decoder: Decoder, event: Event) -> None:
    try:
        decoder.decode(event)
    except Exception as exc:
        _log_step_error(event, "decoder.decode", exc)


def _preprocess_safely(preprocessor: Preprocessor, event: Event) -> None:
    try:
        preprocessor.process(event)
    except Exception as exc:
        _log_step_error(event, "preprocessor.process", exc)
        if event.preprocess_status in (None, PREPROCESS_VALID):
            event.preprocess_status = PREPROCESS_PARTIAL
            event.reason.append(f"cli: preprocessor.process raised {exc!r}")
        if event.processing_action in (None, ACTION_PASS):
            event.processing_action = ACTION_MARK


def _track_safely(tracker: FlowTracker, event: Event) -> list[Flow]:
    try:
        return tracker.process(event)
    except Exception as exc:
        _log_step_error(event, "tracker.process", exc)
        return []

# xử lý khi quá trình ghi file jsonl bị lỗi
def _write_safely(
    writer: JsonlWriter, event: Event, packet_id: int, capture: BaseCapture
) -> Event:
    try:
        writer.write(event)
    # gặp OSError thì cho qua hàm main xử lý
    except OSError:
        raise
    # nếu event k thể ghi được mà kp OS Error thì ghi log, traceback và event fallback
    except Exception as exc:
        logger.error("Packet %d could not be serialised: %r", packet_id, exc)
        logger.info("Traceback of packet %d", packet_id, exc_info=True)
        fallback = _fallback_event(
            packet_id,
            event.timestamp,
            capture,
            f"cli: cannot serialise the event: {exc!r}",
        )
        writer.write(fallback)
        return fallback

    return event


def _write_flow_safely(flow_writer: JsonlWriter, flow: Flow) -> None:
    try:
        flow_writer.write(flow)
    except OSError:
        raise
    except Exception as exc:
        logger.error("Flow %s could not be serialised: %r", flow.flow_id, exc)
        logger.info("Traceback of flow %s", flow.flow_id, exc_info=True)


# dòng tổng kết cho cả lượt chạy, luôn in đủ 4 status theo thứ tự cố định
def _report_summary(
    total: int,
    counts: Counter,
    dropped: int,
    flows_created: int,
    flows_timed_out: int,
) -> None:
    breakdown = ", ".join(f"{status} {counts[status]}" for status in PARSE_STATUSES)
    summary = f"Total packets: {total} ({breakdown})"
    flow_summary = (
        f"Dropped events: {dropped}, flows created: {flows_created}, "
        f"flows timed out: {flows_timed_out}"
    )
    for line in (summary, flow_summary):
        logger.info(line)
        print(line, file=sys.stderr)


# thực hiện vòng lặp bắt gói tin, đếm số lượng gói tin bắt được
# nếu có lỗi thì in ra thông báo lỗi
def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    # khởi tạo log ngay từ đầu để module có thể ghi vào 
    setup_logging(args.log_file) 

    if Path(args.flow_output).resolve() == Path(args.output).resolve():
        logger.error(
            "--flow-output and --output must be different files, both are '%s'",
            args.output,
        )
        return 1

    try:
        config = load_config(args.config)
    except ConfigError as error:
        logger.error("%s", error)
        return 1

    # khởi tạo nguồn capture và gọi pipeline xử lý
    capture = build_capture(args)
    pipeline = build_pipeline(config)

    # khởi tạo các thành phần sau parser
    decoder = Decoder()
    preprocessor = Preprocessor(config)
    tracker = FlowTracker(config)

    packet_count = 0 # bộ đếm
    counts: Counter = Counter()
    dropped_count = 0
    exit_code = 0

    # thông tin log lúc bắt đầu
    # ex: Reading from pcap 'data/pcap/sample.pcap'
    # writing events to 'logs/events.jsonl'
    logger.info(
        "Reading from %s '%s', writing events to '%s' and flows to '%s'",
        capture.source_type,
        capture.source,
        args.output,
        args.flow_output,
    )
    
    # mở jsonl writer để ghi các event
    try:
        with (
            JsonlWriter(args.output) as writer,
            JsonlWriter(args.flow_output) as flow_writer,
        ):
            try:
                # đọc packet
                for packet_id, (packet, timestamp) in enumerate(
                    capture.packets(), start=1
                ):
                    packet_count = packet_id
                    # thêm guard, mỗi hàm có try/except riêng
                    event = _process_safely(
                        pipeline, packet, timestamp, packet_id, capture
                    )
                    _decode_safely(decoder, event)
                    _preprocess_safely(preprocessor, event)
                    finished_flows = _track_safely(tracker, event)
                    for flow in finished_flows:
                        _write_flow_safely(flow_writer, flow)

                    # event bị drop thì chỉ đếm, không ghi ra file
                    # action drop thì k cần write
                    if event.processing_action == ACTION_DROP:
                        dropped_count += 1
                        counts[event.parse_status] += 1
                    else:
                        written = _write_safely(writer, event, packet_id, capture)
                        counts[written.parse_status] += 1
            except KeyboardInterrupt:
                logger.info("Capture stopped by the user")
            finally:
                for flow in tracker.flush():
                    _write_flow_safely(flow_writer, flow)
    except CaptureError as error:
        if packet_count > 0:
            logger.error(
                "Capture stopped after %d packets: %s", packet_count, error
            )
        else:
            logger.error("Capture error: %s", error)
        exit_code = 1
    except OSError as error:
        logger.error("Output error: %s", error)
        exit_code = 1

    _report_summary(
        packet_count,
        counts,
        dropped_count,
        tracker.flows_created,
        tracker.flows_timed_out,
    )
    return exit_code

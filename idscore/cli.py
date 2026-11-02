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
from idscore.detection.engine import EvaluationEngine
from idscore.detection.loader import load_rules
from idscore.detection.repository import RuleRepository
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
from idscore.models.detection import DetectionEvent
from idscore.models.flow import Flow, FlowContext
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
    # tham số detection-output -> file jsonl ghi các Detection Event (đầu vào của Alert/Logging ở bài 4)
    parser.add_argument(
        "--detection-output",
        default="logs/detections.jsonl",
        help="JSON Lines file the detection events are appended to.",
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

# dựng Core Engine một lần lúc khởi động (giai đoạn nạp, parse, index rule), trước vòng lặp packet
def build_engine(config: dict[str, Any]) -> EvaluationEngine:
    repository = RuleRepository(load_rules(config["detection"]))
    if len(repository) == 0:
        # phân biệt "không có rule" với "có rule nhưng không khớp"
        logger.warning("No valid rule is indexed, detection will not report anything")
    return EvaluationEngine(repository)


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


def _evaluate_safely(
    engine: EvaluationEngine, event: Event, ctx: FlowContext | None
) -> list[DetectionEvent]:
    try:
        return engine.evaluate(event, ctx)
    except Exception as exc:
        _log_step_error(event, "engine.evaluate", exc)
        return []


def _write_flow_safely(flow_writer: JsonlWriter, flow: Flow) -> None:
    try:
        flow_writer.write(flow)
    except OSError:
        raise
    except Exception as exc:
        logger.error("Flow %s could not be serialised: %r", flow.flow_id, exc)
        logger.info("Traceback of flow %s", flow.flow_id, exc_info=True)


# khác _write_safely, không ghi bản fallback: một Detection Event giả với sid/msg không thật sẽ làm
# bài 4 sinh cảnh báo sai. Trả True nếu ghi được, để đếm và đối chiếu với matches_total của engine
def _write_detection_safely(
    detection_writer: JsonlWriter, detection: DetectionEvent
) -> bool:
    try:
        detection_writer.write(detection)
    except OSError:
        raise
    except Exception as exc:
        logger.error(
            "Detection event of sid %s (packet %s) could not be serialised: %r",
            detection.sid,
            detection.packet_id,
            exc,
        )
        logger.info("Traceback of packet %s", detection.packet_id, exc_info=True)
        return False
    return True


# dòng tổng kết cho cả lượt chạy, luôn in đủ 4 status theo thứ tự cố định
def _report_summary(
    total: int,
    counts: Counter,
    dropped: int,
    flows_created: int,
    flows_timed_out: int,
    detection_stats: dict,
    detections_written: int,
) -> None:
    breakdown = ", ".join(f"{status} {counts[status]}" for status in PARSE_STATUSES)
    summary = f"Total packets: {total} ({breakdown})"
    flow_summary = (
        f"Dropped events: {dropped}, flows created: {flows_created}, "
        f"flows timed out: {flows_timed_out}"
    )
    # avg_candidates cạnh rules_indexed cho thấy indexer có loại bớt rule hay không (mục 4.3)
    detection_summary = (
        f"Detection: events_evaluated={detection_stats['events_evaluated']} "
        f"events_skipped={detection_stats['events_skipped']} "
        f"events_failed={detection_stats['events_failed']} "
        f"candidates_total={detection_stats['candidates_total']} "
        f"avg_candidates={detection_stats['avg_candidates']} "
        f"rules_indexed={detection_stats['rules_indexed']} "
        f"matches_total={detection_stats['matches_total']} "
        f"detections_written={detections_written} "
        f"rule_errors={detection_stats['rule_errors']}"
    )
    for line in (summary, flow_summary, detection_summary):
        logger.info(line)
        print(line, file=sys.stderr)

    # theo sid chỉ ghi vào log file: bộ rule lớn thì dòng này rất dài, làm rối màn hình
    by_sid = detection_stats["matches_by_sid"]
    logger.info(
        "Matches by sid: %s",
        " ".join(f"{sid}={by_sid[sid]}" for sid in sorted(by_sid)) or "none",
    )
    # lệch nghĩa là có Detection Event ghi thất bại (lỗi từng dòng đã log ở _write_detection_safely)
    if detections_written != detection_stats["matches_total"]:
        logger.warning(
            "Detection events written (%d) differ from matches (%d)",
            detections_written,
            detection_stats["matches_total"],
        )


# thực hiện vòng lặp bắt gói tin, đếm số lượng gói tin bắt được
# nếu có lỗi thì in ra thông báo lỗi
def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    # khởi tạo log ngay từ đầu để module có thể ghi vào 
    setup_logging(args.log_file) 

    # JsonlWriter mở file ở chế độ a: hai writer cùng một file sẽ trộn các schema khác nhau vào một chỗ
    outputs = (
        ("--output", args.output),
        ("--flow-output", args.flow_output),
        ("--detection-output", args.detection_output),
    )
    for i, (first_name, first_path) in enumerate(outputs):
        for second_name, second_path in outputs[i + 1 :]:
            if Path(first_path).resolve() == Path(second_path).resolve():
                logger.error(
                    "%s and %s must be different files, both are '%s'",
                    first_name,
                    second_name,
                    first_path,
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

    # lỗi khởi động xảy ra trước khi mở file nên không để lại file output rỗng
    # lỗi từng rule đã được loader chặn, exception lọt ra đây là lỗi lập trình: dừng hẳn thay vì
    # chạy tiếp không có detection để người dùng tưởng không có cảnh báo nào
    try:
        engine = build_engine(config)
    except Exception as exc:
        logger.error("Cannot build the detection engine: %r", exc)
        logger.info("Traceback of the detection engine", exc_info=True)
        return 1

    packet_count = 0 # bộ đếm
    counts: Counter = Counter()
    dropped_count = 0
    detections_written = 0
    exit_code = 0

    # thông tin log lúc bắt đầu
    # ex: Reading from pcap 'data/pcap/sample.pcap'
    # writing events to 'logs/events.jsonl'
    logger.info(
        "Reading from %s '%s', writing events to '%s', flows to '%s' and detections to '%s'",
        capture.source_type,
        capture.source,
        args.output,
        args.flow_output,
        args.detection_output,
    )
    
    # mở jsonl writer để ghi các event
    try:
        with (
            JsonlWriter(args.output) as writer,
            JsonlWriter(args.flow_output) as flow_writer,
            JsonlWriter(args.detection_output) as detection_writer,
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
                    # context_of phải gọi ngay sau process, trước mọi việc khác của packet này:
                    # ảnh chụp trạng thái flow tại đúng packet (ACK cuối handshake thấy ESTABLISHED)
                    ctx = tracker.context_of(event)
                    # gọi với mọi event kể cả bị drop: engine tự bỏ và đếm events_skipped, cli tự lọc thì
                    # events_received lệch tổng packet; truyền event gốc, không phải bản fallback khi ghi
                    detections = _evaluate_safely(engine, event, ctx)
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

                    # một event có thể khớp nhiều rule, mỗi rule khớp là một dòng riêng
                    for detection in detections:
                        if _write_detection_safely(detection_writer, detection):
                            detections_written += 1
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
        engine.stats(),
        detections_written,
    )
    return exit_code

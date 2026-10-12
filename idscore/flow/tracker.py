# dùng để định nghĩa flow tracker
# tạo active flow table để theo dõi các flow đang hoạt động
import logging
from typing import Any

from idscore.flow.key import FlowKey, make_flow_id, make_flow_key
from idscore.models.event import (
    ACTION_DROP,
    DIRECTION_BACKWARD,
    DIRECTION_FORWARD,
    PREPROCESS_INVALID,
    Event,
)
from idscore.models.flow import STATE_NEW, Flow
from idscore.preprocessor.validate import UNKNOWN_APP_PROTOCOL

# khởi tạo log
logger = logging.getLogger(__name__)

TCP_PROTOCOL = "TCP"
TCP_FLAG_SEPARATOR = "-"

# định nghĩa flow tracker
class FlowTracker:
    def __init__(self, config: dict[str, Any]) -> None:

        # đọc các config timeout của TCP/UDP
        settings = config["flow"]
        self.tcp_idle_timeout = settings["tcp_idle_timeout"]
        self.udp_idle_timeout = settings["udp_idle_timeout"]
        self.flows: dict[FlowKey, Flow] = {}

    # process theo dõi các flow
    def process(self, event: Event) -> list[Flow]:
        try:
            self._track(event)
        except Exception as exc:
            logger.error("Packet %d could not be tracked: %r", event.packet_id, exc)
            logger.info("Traceback of packet %d", event.packet_id, exc_info=True)
            event.errors.append(f"flow: process raised {exc!r}")
        return []

    def _track(self, event: Event) -> None:
        # không tạo flow trong 2 TH
        if event.processing_action == ACTION_DROP:
            return
        if event.preprocess_status == PREPROCESS_INVALID:
            return

        key = make_flow_key(event)
        # make flow key là none thì cũng k tạo
        if key is None:
            return

        # k tạo mới với những flow key đã có trong bảng
        flow = self.flows.get(key)
        if flow is None:
            flow = self._new_flow(key, event)
            self.flows[key] = flow

        is_forward = (event.src_ip, event.src_port) == (flow.a_ip, flow.a_port)
        direction = DIRECTION_FORWARD if is_forward else DIRECTION_BACKWARD
        self._update_stats(flow, event, direction)
        event.flow_id = flow.flow_id
        event.direction = direction

    # hàm dùng để check các event trong 1 flow
    # đếm các thông tin để điền vào các field của flow 
    def _update_stats(self, flow: Flow, event: Event, direction: str) -> None:
        ip_len = event.ip_len
        size = ip_len if isinstance(ip_len, int) and not isinstance(ip_len, bool) else 0
        last_seen = max(flow.last_seen, event.timestamp)
        flags = self._tcp_flags(event) if flow.protocol == TCP_PROTOCOL else ()
        app_protocol = event.app_protocol

        flow.packet_count += 1
        flow.byte_count += size
        if direction == DIRECTION_FORWARD:
            flow.fwd_packet_count += 1
            flow.fwd_byte_count += size
        else:
            flow.bwd_packet_count += 1
            flow.bwd_byte_count += size

        flow.last_seen = last_seen

        if flow.protocol == TCP_PROTOCOL:
            flow.syn_count += "SYN" in flags
            flow.ack_count += "ACK" in flags
            flow.fin_count += "FIN" in flags
            flow.rst_count += "RST" in flags

        if isinstance(app_protocol, str) and flow.application_protocol in (
            None,
            UNKNOWN_APP_PROTOCOL,
        ):
            flow.application_protocol = app_protocol

    @staticmethod
    def _tcp_flags(event: Event) -> tuple[str, ...]:
        flags = event.tcp_flags
        if not isinstance(flags, str) or not flags:
            return ()
        return tuple(flags.split(TCP_FLAG_SEPARATOR))

    # nếu có flow key mới thì định nghĩa flow
    def _new_flow(self, key: FlowKey, event: Event) -> Flow:
        flow = Flow(
            flow_id=make_flow_id(key, event.timestamp),
            protocol=key[0],
            application_protocol=None,
            a_ip=event.src_ip,
            a_port=event.src_port,
            b_ip=event.dst_ip,
            b_port=event.dst_port,
            start_time=event.timestamp,
            last_seen=event.timestamp,
        )
        if flow.protocol == TCP_PROTOCOL:
            flow.syn_count = 0
            flow.ack_count = 0
            flow.fin_count = 0
            flow.rst_count = 0
            flow.state = STATE_NEW
        return flow

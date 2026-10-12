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

# khởi tạo log
logger = logging.getLogger(__name__)

TCP_PROTOCOL = "TCP"

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
        event.flow_id = flow.flow_id
        event.direction = DIRECTION_FORWARD if is_forward else DIRECTION_BACKWARD

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

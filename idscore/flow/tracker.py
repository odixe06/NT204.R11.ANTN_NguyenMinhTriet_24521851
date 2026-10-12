# dùng để định nghĩa flow tracker
# tạo active flow table để theo dõi các flow đang hoạt động
import logging
import math
from typing import Any

from idscore.flow.key import FlowKey, make_flow_id, make_flow_key
from idscore.flow.smtp import SMTP_PROTOCOL, update_smtp_session
from idscore.models.event import (
    ACTION_DROP,
    DIRECTION_BACKWARD,
    DIRECTION_FORWARD,
    PREPROCESS_INVALID,
    UNKNOWN_APP_PROTOCOL,
    Event,
)
from idscore.models.flow import (
    END_REASON_END_OF_CAPTURE,
    END_REASON_NEW_CONNECTION,
    END_REASON_TIMEOUT,
    STATE_CLOSED,
    STATE_CLOSING,
    STATE_ESTABLISHED,
    STATE_HANDSHAKE,
    STATE_NEW,
    STATE_RESET,
    Flow,
)

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
        self._clock: float | None = None
        self.flows_created = 0
        self.flows_timed_out = 0

    # process theo dõi các flow
    def process(self, event: Event) -> list[Flow]:
        finished: list[Flow] = []
        try:
            if self._advance_clock(event):
                self._expire(finished)
        except Exception as exc:
            self._record_error(event, exc)

        try:
            self._track(event, finished)
        except Exception as exc:
            self._record_error(event, exc)
        return finished

    # kết thúc thì xóa toàn bộ flow trong bảng với reason là ngừng capture
    def flush(self) -> list[Flow]:
        remaining = list(self.flows.values())
        for flow in remaining:
            flow.end_reason = END_REASON_END_OF_CAPTURE
        self.flows.clear()
        return remaining

    # định nghĩa giá trị clock bằng timestamp lớn nhất
    def _advance_clock(self, event: Event) -> bool:
        timestamp = event.timestamp
        if event.preprocess_status == PREPROCESS_INVALID:
            return False
        if not isinstance(timestamp, float) or not math.isfinite(timestamp):
            return False
        if self._clock is None or timestamp > self._clock:
            self._clock = timestamp
        return True

    # nếu clock - lastseen > timeout -> ngừng tracker
    def _expire(self, finished: list[Flow]) -> None:
        expired = [
            key
            for key, flow in self.flows.items()
            if self._clock - flow.last_seen > self._timeout_of(flow)
        ]
        for key in expired:
            flow = self.flows.pop(key)
            flow.end_reason = END_REASON_TIMEOUT
            self.flows_timed_out += 1
            finished.append(flow)

    def _timeout_of(self, flow: Flow) -> float:
        if flow.protocol == TCP_PROTOCOL:
            return self.tcp_idle_timeout
        return self.udp_idle_timeout

    @staticmethod
    def _record_error(event: Event, exc: Exception) -> None:
        logger.error("Packet %d could not be tracked: %r", event.packet_id, exc)
        logger.info("Traceback of packet %d", event.packet_id, exc_info=True)
        event.errors.append(f"flow: process raised {exc!r}")

    def _track(self, event: Event, finished: list[Flow]) -> None:
        # không tạo flow trong 2 TH
        if event.processing_action == ACTION_DROP:
            return
        if event.preprocess_status == PREPROCESS_INVALID:
            return

        key = make_flow_key(event)
        # make flow key là none thì cũng k tạo
        if key is None:
            return

        is_tcp = key[0] == TCP_PROTOCOL
        flags = self._tcp_flags(event) if is_tcp else frozenset()

        # k tạo mới với những flow key đã có trong bảng
        flow = self.flows.get(key)
        if flow is not None and self._starts_new_connection(flow, flags):
            del self.flows[key]
            flow.end_reason = END_REASON_NEW_CONNECTION
            finished.append(flow)
            flow = None
        if flow is None:
            flow = self._new_flow(key, event)
            self.flows[key] = flow
            self.flows_created += 1

        is_forward = (event.src_ip, event.src_port) == (flow.a_ip, flow.a_port)
        direction = DIRECTION_FORWARD if is_forward else DIRECTION_BACKWARD
        self._update_stats(flow, event, direction, flags)
        if is_tcp:
            self._update_tcp_state(flow, flags, direction)
            if flow.application_protocol == SMTP_PROTOCOL:
                update_smtp_session(flow, event, direction)
        event.flow_id = flow.flow_id
        event.direction = direction

    @staticmethod
    def _starts_new_connection(flow: Flow, flags: frozenset[str]) -> bool:
        return (
            flow.state in (STATE_CLOSED, STATE_RESET)
            and "SYN" in flags
            and "ACK" not in flags
        )

    # hàm dùng để check các event trong 1 flow
    # đếm các thông tin để điền vào các field của flow 
    def _update_stats(
        self, flow: Flow, event: Event, direction: str, flags: frozenset[str]
    ) -> None:
        ip_len = event.ip_len
        size = ip_len if isinstance(ip_len, int) and not isinstance(ip_len, bool) else 0
        last_seen = max(flow.last_seen, event.timestamp)
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

    # dựa vào các cờ TCP để xác định state của flow
    # lưu ý: nếu reset thì end flow cũ để bắt đầu flow mới
    def _update_tcp_state(
        self, flow: Flow, flags: frozenset[str], direction: str
    ) -> None:
        state = flow.state
        if state in (STATE_CLOSED, STATE_RESET):
            return

        if "RST" in flags:
            flow.state = STATE_RESET
        elif state in (STATE_NEW, STATE_HANDSHAKE) and {"SYN", "ACK"} <= flags:
            flow.state = STATE_HANDSHAKE
            flow._syn_ack_seen = True
        elif state == STATE_NEW and "SYN" in flags:
            flow.state = STATE_HANDSHAKE
        elif "FIN" in flags and state in (
            STATE_NEW,
            STATE_HANDSHAKE,
            STATE_ESTABLISHED,
            STATE_CLOSING,
        ):
            self._mark_fin(flow, direction)
            both_closed = flow._fin_fwd and flow._fin_bwd
            flow.state = STATE_CLOSED if both_closed else STATE_CLOSING
        elif (
            state == STATE_HANDSHAKE
            and flow._syn_ack_seen
            and "ACK" in flags
            and "SYN" not in flags
        ):
            flow.state = STATE_ESTABLISHED

    @staticmethod
    def _mark_fin(flow: Flow, direction: str) -> None:
        if direction == DIRECTION_FORWARD:
            flow._fin_fwd = True
        else:
            flow._fin_bwd = True

    # với những hàm packet tcp có nhiều cờ 
    # -> tách cờ để đếm chính xác
    @staticmethod
    def _tcp_flags(event: Event) -> frozenset[str]:
        flags = event.tcp_flags
        if not isinstance(flags, str) or not flags:
            return frozenset()
        return frozenset(flags.split(TCP_FLAG_SEPARATOR))

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

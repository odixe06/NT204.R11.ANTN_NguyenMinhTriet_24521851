# file này định nghĩa model flow gồm các field gì

from dataclasses import asdict, dataclass

# các trạng thái của flow
STATE_NEW = "NEW"
STATE_HANDSHAKE = "HANDSHAKE"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_CLOSING = "CLOSING"
STATE_CLOSED = "CLOSED"
STATE_RESET = "RESET"
FLOW_STATES = (
    STATE_NEW,
    STATE_HANDSHAKE,
    STATE_ESTABLISHED,
    STATE_CLOSING,
    STATE_CLOSED,
    STATE_RESET,
)

SMTP_STATE_COMMAND = "command"
SMTP_STATE_DATA_PENDING = "data_pending"
SMTP_STATE_DATA = "data"

# các lí do kết thúc flow
END_REASON_TIMEOUT = "timeout"
END_REASON_END_OF_CAPTURE = "end_of_capture"
END_REASON_NEW_CONNECTION = "new_connection"
END_REASONS = (
    END_REASON_TIMEOUT,
    END_REASON_END_OF_CAPTURE,
    END_REASON_NEW_CONNECTION,
)

DURATION_DIGITS = 6


@dataclass
# nhóm field định danh
class Flow:
    flow_id: str
    protocol: str
    application_protocol: str | None
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int


    # nhóm field thời gian
    start_time: float
    last_seen: float

    # nhóm field đếm số lượng
    packet_count: int = 0
    byte_count: int = 0

    # đếm số lượng cụ thể từng chiều
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0

    # đếm các cờ trạng thái
    syn_count: int | None = None
    ack_count: int | None = None
    fin_count: int | None = None
    rst_count: int | None = None
    state: str | None = None

    # field lí do kết thúc
    end_reason: str | None = None

    # nhóm field trạng thái nội bộ 
    _syn_ack_seen: bool = False # flow đã từng thấy SYN-ACK chưa
    # thấy cờ fin chưa
    _fin_fwd: bool = False
    _fin_bwd: bool = False
    _smtp_state: str = SMTP_STATE_COMMAND
    _smtp_client_dir: str | None = None
    _smtp_encoding: str | None = None
    _smtp_headers_done: bool = False

    # chuyển 1 object flow thành dict để ghi ra file jsonl
    # tương tự event
    def to_dict(self) -> dict:
        result = {}
        for key, value in asdict(self).items():
            if value is None or key.startswith("_"):
                continue
            result[key] = value
            if key == "last_seen":
                result["duration"] = round(
                    self.last_seen - self.start_time, DURATION_DIGITS
                )
        return result

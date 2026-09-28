# schema cho event, ghi dữ liệu parser phân tích từ một packet

from dataclasses import asdict, dataclass, field

PARSE_STATUSES = ("OK", "PARTIAL", "UNKNOWN", "MALFORMED")


@dataclass # decorator tự động tạo method cho các class lưu dữ liệu
class Event:
    # metadata
    packet_id: int # bắt buộc có
    timestamp: float
    source: str
    source_type: str # "pcap" hoặc "live"

    # layer 2
    src_mac: str | None = None 
    # nếu không có giá trị -> gán bằng None
    dst_mac: str | None = None

    # network
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    ttl: int | None = None
    ip_len: int | None = None
    ip_id: int | None = None
    ip_proto: int | None = None
    ip_flags: str | None = None
    frag_offset: int | None = None

    # transport
    src_port: int | None = None
    dst_port: int | None = None
    transport_protocol: str | None = None
    seq: int | None = None
    ack: int | None = None
    tcp_flags: str | None = None
    window: int | None = None
    payload_len: int | None = None

    # application
    app_protocol: str | None = None
    detection_method: str | None = None
    app: dict | None = None

    # trạng thái
    parse_status: str = "OK" # mặc định là OK
    # nếu không OK, check từng trường hợp -> gán giá trị tương ứng
    # lưu ý: mọi nhánh xử lý fail đều hạ trạng thái
    
    errors: list[str] = field(default_factory=list)
    # errors là danh sách thông báo lỗi chi tiết trong một Event
    # khai báo default_factory=list để tạo ra một danh sách rỗng mặc định cho errors (mỗi event có list riêng)


    def to_dict(self) -> dict:
        return {
            key: value
            for key, value in asdict(self).items() 
            # asdict tạo bản sao của event mà không đụng object
            if value is not None 
            # so sánh value với None, nếu khác None -> giữ lại (không xóa các trường rỗng hoặc số 0)
        }
    # application parser k được ghi giá trị None vào dict app
# file này định nghĩa class AppProtocolDetector 
# dùng để detect giao thức ứng dụng từ payload

from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from idscore.models.event import Event
from idscore.parsers.base import BaseParser

# các phương thức của http
HTTP_METHODS = (
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"TRACE",
    b"CONNECT",
)
HTTP_VERSION = b"HTTP/1." # phiên bản http

# các lệnh SMTP
SMTP_VERBS = (
    b"HELO",
    b"EHLO",
    b"MAIL",
    b"RCPT",
    b"DATA",
    b"QUIT",
    b"RSET",
    b"NOOP",
    b"VRFY",
    b"AUTH",
    b"STARTTLS",
)

# các mã response của SMTP bắt đầu bằng mã 3 chữ số từ 200 đến 599
SMTP_CODE_LEN = 3
SMTP_MIN_CODE = ord("2") 
SMTP_MAX_CODE = ord("5")
CRLF = b"\r\n"


class AppProtocolDetector(BaseParser):
    """Name the application protocol of a payload without looking at ports."""
    # thêm port fallback nếu không được được bằng payload thô
    @property
    def name(self) -> str:
        return "app_detector"

    # kiểm tra điều kiện xử lý
    def can_parse(self, packet: Packet) -> bool:
        """Return True only when the TCP or UDP payload carries bytes."""
        try:
            layer = self._transport_layer(packet) 
            # trả về true khi: có TCP/UDP và payload k rỗng
            # tránh mấy gói SYN/ACK dùng để bắt tay
            return layer is not None and bool(self._payload_bytes(layer))
        except Exception:
            return False

    def parse(self, packet: Packet, event: Event) -> None:
        """Set ``app_protocol`` and ``detection_method``; nothing else changes."""
        try:
            layer = self._transport_layer(packet) # tìm TCP/UDP
            if layer is None:
                return
            payload = self._payload_bytes(layer) # lấy byte thô của payload
            protocol = self._detect(payload) # gọi hàm detect

        # nếu xảy ra exception -> hạ xuống malformed
        except Exception as exc:
            self._malformed(event, f"cannot inspect the payload: {exc!r}")
            return

        # phát hiện protocol -> ghi vào event
        if protocol is not None:
            event.app_protocol = protocol
            event.detection_method = "payload"

    # hàm kiểm tra nếu có packet TCP/UDP thì trả về layer tương ứng
    # không có thì none
    def _transport_layer(self, packet: Packet) -> Packet | None:
        for layer_type in (TCP, UDP):
            if packet.haslayer(layer_type):
                return packet[layer_type]
        return None

    # hàm detect nhận diện theo thứ tự 
    def _detect(self, payload: bytes) -> str | None:
        if self._is_http(payload):
            return "HTTP"
        if self._is_smtp(payload):
            return "SMTP"
        return None

    # kiểm tra http 
    def _is_http(self, payload: bytes) -> bool:

        # nếu là gói response -> bắt đầu với version 
        if payload.startswith(HTTP_VERSION): 
            return True

        # nếu là gói request -> kiểm tra danh sách phương thức 
        first_line = payload.split(b"\n", 1)[0]
        return any(
            first_line.startswith(method + b" ") for method in HTTP_METHODS
        ) and HTTP_VERSION in first_line

    def _is_smtp(self, payload: bytes) -> bool:
        line, separator, _ = payload.partition(CRLF)
        if not separator or b"\n" in line:
            return False
        return self._is_smtp_command(line) or self._is_smtp_response(line)

    def _is_smtp_command(self, line: bytes) -> bool:
        upper = line.upper()
        for verb in SMTP_VERBS:
            if not upper.startswith(verb):
                continue
            rest = upper[len(verb):]
            if rest and not rest.startswith(b" "):
                continue
            argument = rest.lstrip(b" ")
            if verb == b"MAIL":
                return argument.startswith(b"FROM:")
            if verb == b"RCPT":
                return argument.startswith(b"TO:")
            return True
        return False

    def _is_smtp_response(self, line: bytes) -> bool:
        code = line[:SMTP_CODE_LEN]
        if len(code) < SMTP_CODE_LEN or not code.isdigit():
            return False
        if not SMTP_MIN_CODE <= code[0] <= SMTP_MAX_CODE:
            return False
        rest = line[SMTP_CODE_LEN:]
        return rest.startswith(b" ") or rest.startswith(b"-")

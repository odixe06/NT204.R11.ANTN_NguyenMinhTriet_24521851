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

DNS_HEADER_LEN = 12
DNS_FLAGS_OFFSET = 2
DNS_QDCOUNT_OFFSET = 4
DNS_QUESTION_TAIL_LEN = 4
DNS_LABEL_MAX = 63
DNS_OPCODES = frozenset({0, 1, 2, 4, 5})
DNS_QDCOUNT = 1

TCP_PORTS = {
    80: "HTTP",
    8080: "HTTP",
    25: "SMTP",
    587: "SMTP",
}
UDP_PORTS = {
    53: "DNS",
}


class AppProtocolDetector(BaseParser):
    """Name the application protocol from the payload, falling back to the port."""
    # payload là tín hiệu chính, port fallback
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
            transport = self._transport_name(layer)
            protocol = self._detect(payload, transport) # gọi hàm detect
            method = "payload"

            if protocol is None:
                protocol = self._detect_by_port(layer, transport)
                method = "port"

            if protocol is None:
                protocol = "UNKNOWN"
                method = None

        # nếu xảy ra exception -> hạ xuống malformed
        except Exception as exc:
            self._malformed(event, f"cannot inspect the payload: {exc!r}")
            return

        # phát hiện protocol -> ghi vào event
        event.app_protocol = protocol
        if method is not None:
            event.detection_method = method

    # hàm kiểm tra nếu có packet TCP/UDP thì trả về layer tương ứng
    # không có thì none
    def _transport_layer(self, packet: Packet) -> Packet | None:
        for layer_type in (TCP, UDP):
            if packet.haslayer(layer_type):
                return packet[layer_type]
        return None

    def _transport_name(self, layer: Packet) -> str:
        return "TCP" if isinstance(layer, TCP) else "UDP"

    def _detect_by_port(self, layer: Packet, transport: str) -> str | None:
        ports = TCP_PORTS if transport == "TCP" else UDP_PORTS
        for port in (int(layer.sport), int(layer.dport)):
            protocol = ports.get(port)
            if protocol is not None:
                return protocol
        return None

    # hàm detect nhận diện theo thứ tự 
    def _detect(self, payload: bytes, transport: str) -> str | None:
        if transport == "TCP":
            if self._is_http(payload):
                return "HTTP"
            if self._is_smtp(payload):
                return "SMTP"
        elif transport == "UDP":
            if self._is_dns(payload):
                return "DNS"
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

    # tách và kiểm tra định dạng dòng đầu tiên
    # đảm bảo dòng đầu tiên phải kết thúc bằng CRLF
    def _is_smtp(self, payload: bytes) -> bool:
        line, separator, _ = payload.partition(CRLF) # tách thành line và separator
        if not separator or b"\n" in line: # nếu separator rỗng hoặc có ký tự xuống dòng trước CRLF
            return False
        return self._is_smtp_command(line) or self._is_smtp_response(line) # xác định là SMTP nếu thỏa mãn 1 trong 2 hàm

    # kiểm tra lệnh gửi đi
    def _is_smtp_command(self, line: bytes) -> bool:
        upper = line.upper()

        # kiểm tra các từ khóa trong verb
        for verb in SMTP_VERBS:
            if not upper.startswith(verb):
                continue
            rest = upper[len(verb):]
            if rest and not rest.startswith(b" "):
                continue
            # kiểm tra đặc biết với các câu lệnh MAIL FROM và RCPT TO
            argument = rest.lstrip(b" ")
            if verb == b"MAIL":
                return argument.startswith(b"FROM:")
            if verb == b"RCPT":
                return argument.startswith(b"TO:")
            return True
        return False

    # kiểm tra mã phản hồi
    def _is_smtp_response(self, line: bytes) -> bool:
        # lấy 3 byte đầu của dòng
        code = line[:SMTP_CODE_LEN] 

        # kiểm tra 3 byte đều là chữ số
        if len(code) < SMTP_CODE_LEN or not code.isdigit():
            return False

        # kiểm tra mã có nằm trong 200 - 599
        if not SMTP_MIN_CODE <= code[0] <= SMTP_MAX_CODE:
            return False

        # kiểm tra phần phản hồi sau mã lệnh (là " " hoặc "-" cho trường hợp nhiều dòng)
        rest = line[SMTP_CODE_LEN:]
        return rest.startswith(b" ") or rest.startswith(b"-")

    # kiểm tra phần header cố định của dns
    def _is_dns(self, payload: bytes) -> bool:
        if len(payload) < DNS_HEADER_LEN:
            return False

        qdcount = int.from_bytes(
            payload[DNS_QDCOUNT_OFFSET:DNS_QDCOUNT_OFFSET + 2], "big"
        )
        if qdcount != DNS_QDCOUNT:
            return False

        opcode = (payload[DNS_FLAGS_OFFSET] >> 3) & 0x0F
        if opcode not in DNS_OPCODES:
            return False

        return self._has_dns_question(payload)

    def _has_dns_question(self, payload: bytes) -> bool:
        """Walk the first QNAME, then check qtype and qclass still fit.

        A length byte above ``DNS_LABEL_MAX`` is either a compression pointer
        (top bits ``11``) or a reserved value; neither can open the first
        question, so both end the walk with False.
        """
        offset = DNS_HEADER_LEN
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                return offset + 1 + DNS_QUESTION_TAIL_LEN <= len(payload)
            if length > DNS_LABEL_MAX:
                return False
            offset += 1 + length
        return False

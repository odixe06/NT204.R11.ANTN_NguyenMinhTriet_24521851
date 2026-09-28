# NT204.R11.ANTN_NguyenMinhTriet_24521851

**Bài tập lớn của sinh viên Nguyễn Minh Triết - môn IDPS - lớp NT204.R11.ANTN.**

## Module Packet Capture & Parser

Module đọc gói tin từ file pcap hoặc trực tiếp từ card mạng, bóc tách theo từng tầng,
nhận diện giao thức ứng dụng dựa trên payload, rồi ghi kết quả ra file JSON Lines.
Mỗi packet đọc được sinh ra đúng một dòng JSON, kể cả packet hỏng hay không nhận diện được.

Phạm vi hỗ trợ:

| tầng | xử lý |
| --- | --- |
| data link | Ethernet (`src_mac`, `dst_mac`); frame không dissect được bị đánh dấu `MALFORMED` |
| network | IPv4; giao thức khác (ARP, IPv6) được gán `UNKNOWN` thay vì crash |
| transport | TCP, UDP; các giao thức khác như ICMP được gán `UNKNOWN` |
| application | HTTP, DNS, SMTP |

Nhận diện giao thức ứng dụng đi theo hai bước: so khớp **payload thô** trước, nếu không
khớp thì mới dùng **bảng port** làm phương án dự phòng; `detection_method` ghi lại đã dùng
cách nào. Nhờ vậy HTTP trên port 8081 hay DNS trên port lạ vẫn được nhận ra.

### Pipeline xử lý

```text
[ Packet Capture ]  (PcapCapture | LiveCapture)
       │
       ▼  yield (packet, timestamp)
┌────────────────────────────────────────────────────────┐
│ Processing Pipeline                                    │
│                                                        │
│  1. Event Init        → Tạo Event rỗng + metadata      │
│  2. Ethernet Parser   → src_mac, dst_mac               │
│  3. IPv4 Parser       → src_ip, dst_ip, ttl, ...       │
│  4. TCP/UDP Parser    → src_port, dst_port, flags, ... │
│  5. Protocol Detector → app_protocol, detection_method │
│  6. App Parser        → bóc tách payload thành app dict│
└────────────────────────────────────────────────────────┘
       │
       ▼  event.to_dict()
[ JSON Lines Writer ] (.jsonl)   [ Runtime Logger ] (.log)
```

Mỗi tầng chỉ chạy một parser: pipeline hỏi `can_parse()` rồi gọi `parse()` của parser đầu
tiên nhận packet. Parser tầng ứng dụng được chọn theo `app_protocol` mà detector vừa gán.

## Cài đặt

Môi trường phát triển là conda env tên `btids`, Python 3.12.

```bash
conda create -n btids python=3.12
conda activate btids
pip install -r requirements.txt
```

`requirements.txt`:

```text
scapy==2.7.0
PyYAML==6.0.3
pytest==9.1.1
```

## Cách chạy

Đọc từ file pcap:

```bash
python main.py --pcap data/pcap/sample.pcap
```

Bắt trực tiếp từ card mạng. Live capture cần quyền root, mà `sudo` không giữ conda env,
nên phải gọi bằng **đường dẫn tuyệt đối tới python của env**:

```bash
sudo ~/miniforge3/envs/btids/bin/python main.py --interface eth0
```

Dừng live capture bằng `Ctrl+C`: chương trình ghi nốt batch cuối rồi thoát với exit code 0.

### Tham số

| tham số | bắt buộc | mặc định | ý nghĩa |
| --- | --- | --- | --- |
| `--pcap` | chọn 1 trong 2 | | đường dẫn file pcap hoặc pcap.gz |
| `--interface` | chọn 1 trong 2 | | tên card mạng để bắt trực tiếp |
| `--output` | không | `logs/events.jsonl` | file JSONL chứa event, ghi ở chế độ append |
| `--log-file` | không | `logs/ids.log` | file log runtime, ghi ở chế độ append |

Hai file output đều ghi nối, nên mỗi lần chạy lại cần xóa file cũ hoặc đổi đường dẫn.
Ví dụ chạy cho một testcase:

```bash
python main.py --pcap TEST/tc04_http_get/input.pcap \
  --output TEST/tc04_http_get/events.jsonl \
  --log-file TEST/tc04_http_get/run_log.txt
```

### Kết quả trên terminal và exit code

Mỗi lượt chạy kết thúc bằng một dòng tổng kết trên `stderr`, luôn in đủ 4 trạng thái:

```text
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
```

| exit code | trường hợp |
| --- | --- |
| 0 | chạy hết nguồn, hoặc người dùng bấm `Ctrl+C` |
| 1 | lỗi nguồn capture (`CaptureError`) hoặc lỗi ghi file output (`OSError`) |

`stdout` không có gì, nên output JSONL không bao giờ lẫn với thông báo của chương trình.
Chi tiết lỗi và traceback nằm trong file log; terminal chỉ hiện mức `WARNING` trở lên.

## Ví dụ output JSONL

Mỗi dòng là một event. Field nào không có giá trị thì bị lược khỏi JSON.

Gói TCP SYN, không có payload:

```json
{"packet_id":1,"timestamp":1790602674.895464,"source":"TEST/tc01_tcp_handshake/input.pcap","source_type":"pcap","src_mac":"00:15:5d:4b:41:59","dst_mac":"00:15:5d:0d:d0:c2","src_ip":"172.18.124.92","dst_ip":"104.20.23.154","ip_version":4,"ttl":64,"ip_len":60,"ip_id":48777,"ip_proto":6,"ip_flags":"DF","frag_offset":0,"src_port":55996,"dst_port":80,"transport_protocol":"TCP","seq":1291727709,"ack":0,"tcp_flags":"SYN","window":64240,"payload_len":0,"parse_status":"OK","errors":[]}
```

Gói HTTP request, nhận diện bằng payload:

```json
{"packet_id":4,"timestamp":1790604355.63667,"source":"TEST/tc04_http_get/input.pcap","source_type":"pcap","src_ip":"172.18.124.92","dst_ip":"104.20.23.154","ip_proto":6,"src_port":38454,"dst_port":80,"transport_protocol":"TCP","tcp_flags":"PSH-ACK","payload_len":74,"app_protocol":"HTTP","detection_method":"payload","app":{"message_type":"request","method":"GET","uri":"/","version":"HTTP/1.1","headers":{"host":"example.com","user-agent":"curl/8.5.0","accept":"*/*"},"body_len":0},"parse_status":"OK","errors":[]}
```

Gói DNS query:

```json
{"packet_id":1,"timestamp":1790606126.708668,"source":"TEST/tc07_dns_query/input.pcap","source_type":"pcap","src_ip":"172.18.124.92","dst_ip":"8.8.8.8","ip_proto":17,"src_port":58549,"dst_port":53,"transport_protocol":"UDP","payload_len":52,"app_protocol":"DNS","detection_method":"payload","app":{"transaction_id":59234,"message_type":"query","opcode":0,"rcode":0,"flags":"RD","qdcount":1,"ancount":0,"nscount":0,"arcount":1,"questions":[{"name":"example.com","qtype":1,"qclass":1,"qtype_name":"A"}],"answers":[]},"parse_status":"OK","errors":[]}
```

Gói IPv4 bị hỏng header:

```json
{"packet_id":4,"timestamp":1790608151.556664,"source":"TEST/tc12_malformed_packet/input.pcap","source_type":"pcap","src_mac":"02:00:00:00:00:01","dst_mac":"02:00:00:00:00:02","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","ip_version":4,"ttl":64,"ip_len":1000,"ip_id":1,"ip_proto":6,"ip_flags":"","frag_offset":0,"src_port":40000,"dst_port":80,"transport_protocol":"TCP","seq":0,"ack":0,"tcp_flags":"PSH-ACK","window":8192,"payload_len":0,"parse_status":"MALFORMED","errors":["ipv4: ip_len 1000 exceeds the 40 bytes captured"]}
```

Hai ví dụ HTTP và DNS ở trên đã lược bớt phần metadata và các field tầng dưới cho dễ đọc;
ví dụ TCP SYN và IPv4 hỏng là nguyên văn một dòng trong `events.jsonl`.

Đọc file bằng `jq`:

```bash
jq -c 'select(.parse_status != "OK") | {packet_id, parse_status, errors}' logs/events.jsonl
jq -r .parse_status logs/events.jsonl | sort | uniq -c
```

## Schema của event

Định nghĩa trong `idscore/models/event.py`. Field có giá trị `None` bị `to_dict()` lược bỏ,
nên một dòng JSONL chỉ chứa những gì thực sự đọc được từ packet.

| nhóm | field | kiểu | mô tả |
| --- | --- | --- | --- |
| metadata | `packet_id` | int | số thứ tự packet trong lượt chạy, bắt đầu từ 1, khớp số thứ tự trong Wireshark |
| | `timestamp` | float | thời điểm bắt packet, epoch giây |
| | `source` | str | đường dẫn pcap hoặc tên interface |
| | `source_type` | str | `pcap` hoặc `live` |
| data link | `src_mac`, `dst_mac` | str | địa chỉ MAC nguồn và đích |
| network | `src_ip`, `dst_ip` | str | địa chỉ IP nguồn và đích |
| | `ip_version` | int | phiên bản IP, phải là 4 |
| | `ttl` | int | time to live |
| | `ip_len` | int | tổng độ dài IP do header khai báo |
| | `ip_id` | int | identification, dùng để ghép mảnh |
| | `ip_proto` | int | số hiệu giao thức tầng trên, 6 là TCP, 17 là UDP |
| | `ip_flags` | str | cờ IP, ví dụ `DF`, `MF`, `MF+DF`, rỗng nếu không bật cờ nào |
| | `frag_offset` | int | offset của mảnh, đơn vị 8 byte |
| transport | `src_port`, `dst_port` | int | port nguồn và đích |
| | `transport_protocol` | str | `TCP` hoặc `UDP` |
| | `seq`, `ack` | int | sequence và acknowledgement number, chỉ có ở TCP |
| | `tcp_flags` | str | tên các cờ nối bằng `-` theo thứ tự bit `FIN, SYN, RST, PSH, ACK, URG, ECE, CWR`, ví dụ `SYN-ACK`; rỗng nếu không bật cờ nào (NULL scan) |
| | `window` | int | window size, chỉ có ở TCP |
| | `payload_len` | int | số byte payload trong segment này, đã trừ phần padding của Ethernet |
| application | `app_protocol` | str | `HTTP`, `DNS`, `SMTP`, hoặc `UNKNOWN` khi có payload mà không nhận diện được |
| | `detection_method` | str | `payload` hoặc `port`; không có field này nghĩa là không nhận diện được |
| | `app` | dict | dữ liệu do parser tầng ứng dụng bóc tách, không chứa giá trị `None` |
| trạng thái | `parse_status` | str | `OK`, `PARTIAL`, `UNKNOWN`, `MALFORMED` |
| | `errors` | list[str] | danh sách message lỗi, mỗi message có tiền tố là tên tầng phát sinh |

### Ý nghĩa `parse_status`

Thứ tự ưu tiên giảm dần, một parser chỉ được hạ trạng thái xuống, không bao giờ nâng lên.

| status | khi nào |
| --- | --- |
| `MALFORMED` | lỗi cấu trúc ở tầng link, network hoặc transport: số byte ít hơn độ dài header tối thiểu, `ip_len` hoặc `dataofs` khai báo lớn hơn số byte thực có, hoặc đọc byte ném exception |
| `PARTIAL` | các tầng dưới parse xong, nhưng parser tầng ứng dụng gặp lỗi cấu trúc, ví dụ HTTP header bị cắt giữa chừng |
| `UNKNOWN` | packet hợp lệ nhưng mang giao thức không hỗ trợ: ARP, IPv6, ICMP, hoặc mảnh IP phía sau |
| `OK` | mọi tầng có mặt đều được bóc tách trọn vẹn. Gói handshake `payload_len` bằng 0 và mảnh IP có `frag_offset` lớn hơn 0 cũng là `OK` |

Tiền tố trong `errors` cho biết lỗi đến từ đâu: `frame:`, `ipv4:`, `tcp:`, `udp:`, `http:`,
`dns:`, `smtp:`, `app_detector:` là lỗi của parser; `pipeline:` là parser ném exception ra
ngoài; `cli:` là lỗi của chính chương trình khi xử lý hoặc ghi packet đó.

### Dict trong field `app` theo từng giao thức

- HTTP
  - request: `message_type`, `method`, `uri`, `version`, `headers`, `body_len`
  - response: `message_type`, `version`, `status_code`, `reason`, `headers`, `body_len`
  - segment tiếp nối không có start line: `message_type` là `continuation` kèm `body_len`
- DNS: `transaction_id`, `message_type`, `opcode`, `rcode`, `flags`, bốn count, `questions`
  (gồm `name`, `qtype`, `qclass`, `qtype_name`) và `answers` (gồm `name`, `type`, `class`,
  `ttl`, `type_name`, `rdata`)
- SMTP
  - command: `message_type`, `commands` gồm `verb`, `argument`, thêm `address` với `MAIL` và `RCPT`
  - response: `message_type`, `code`, `messages`, `final`
  - xử lý được nhiều dòng trong một segment, ví dụ chuỗi `250-...`
  - nội dung thư sau lệnh `DATA`: `message_type` là `data` kèm `data_len`

## Testcase

12 testcase cùng input, output và log nằm trong [TEST/](TEST/), bảng mapping ở
[TEST/README.md](TEST/README.md).

## Lưu ý khi làm

- Output live có packet ARP. Đây là packet không phải IPv4, pipeline phải gán UNKNOWN cho loại này chứ không được crash khi tìm lớp IP.
- TCP header là 1 cờ có 8 bit, tương ứng với thứ tự `["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]`, lưu ý để detect chính xác.
- Bài tập yêu cầu không được chỉ sử dụng port để xác định protocol => phải kiểm tra payload thô để xem nội dung payload thay vì dùng layer dựng sẵn của scapy.
- Event không phụ thuộc Scapy vì Detector chỉ làm việc với event, còn parser sẽ tiếp xúc với scapy.
- Với file pcapng có linktype không hỗ trợ, các frame vẫn bị gán `MALFORMED`.
- Lỗi của chính chương trình cũng mang `parse_status` là `MALFORMED`, chỉ phân biệt được với packet hỏng thật qua tiền tố `cli:` trong `errors`. Đây là trade-off để giữ schema đúng 4 trạng thái đã chốt.

## Mục đích khi sử dụng các công cụ AI

#### Mục đích:

- Thiết kế cấu trúc thư mục dự án
- Kiểm tra syntax và logic của các đoạn code, cải thiện hoặc chỉnh sửa style code để tối ưu.

#### Công cụ: GitHub Copilot + Claude Code

File có hỗ trợ AI: `idscore/capture/base.py`, `idscore/capture/pcap.py`, `idscore/capture/live.py`, `idscore/cli.py`, `main.py`, `idscore/parsers/application/dns.py`, `TEST/tc12_malformed_packet/gen_malformed.py`, `idscore/pipeline.py`, `idscore/utils/logger.py`

## Tài liệu liên quan sử dụng trong quá trình làm

https://minhtriet0502-note.notion.site/PLAN-3e5730cee68d80f785edfd92cd5a1f54

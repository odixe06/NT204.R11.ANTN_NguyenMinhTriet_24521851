# NT204.R11.ANTN_NguyenMinhTriet_24521851

**Bài tập lớn của sinh viên Nguyễn Minh Triết - môn IDPS - lớp NT204.R11.ANTN.**

Hệ thống IDS viết bằng Python, hiện gồm hai phần đã hoàn thành:

| phần | module | output |
| --- | --- | --- |
| Bài tập 1 | Packet Capture & Parser | `events.jsonl`: mỗi packet một event |
| Bài tập 2 | Decoder, Preprocessor, Flow/Connection Tracker | `events.jsonl` được bổ sung field decode, preprocess, flow; `flows.jsonl`: mỗi flow một dòng |

## Module Packet Capture & Parser

Module đọc gói tin từ file pcap hoặc trực tiếp từ card mạng, bóc tách theo từng tầng,
nhận diện giao thức ứng dụng dựa trên payload, rồi ghi kết quả ra file JSON Lines.
Mỗi packet đọc được sinh ra đúng một event, kể cả packet hỏng hay không nhận diện được.

Phạm vi hỗ trợ:

| tầng | xử lý |
| --- | --- |
| data link | Ethernet: `src_mac`, `dst_mac`. Frame không dissect được bị đánh dấu `MALFORMED` |
| network | IPv4. Giao thức khác như ARP, IPv6 được gán `UNKNOWN` thay vì crash |
| transport | TCP, UDP. Các giao thức khác như ICMP được gán `UNKNOWN` |
| application | HTTP, DNS, SMTP |

Nhận diện giao thức ứng dụng đi theo hai bước: so khớp **payload thô** trước, nếu không
khớp thì mới dùng **bảng port** làm phương án dự phòng. `detection_method` ghi lại đã dùng
cách nào. Nhờ vậy HTTP trên port 8081 hay DNS trên port lạ vẫn được nhận ra.

## Module Decoder

Chuyển dữ liệu đang ở dạng mã hóa sang dạng phân tích được, **không ghi đè dữ liệu gốc**:
bản decode nằm ở field mới, field gốc trong `app` giữ nguyên.

| giao thức | dữ liệu | cách decode | field kết quả |
| --- | --- | --- | --- |
| HTTP | URI | percent-decoding cho path, `application/x-www-form-urlencoded` cho query, tức thêm `+` thành dấu cách | `uri_decoded` |
| HTTP | body có `Content-Type: application/x-www-form-urlencoded` | form decoding | `body_decoded` |
| HTTP | body có `Content-Type: text/html` hoặc `application/xhtml+xml` | HTML entity decoding, gồm entity tên và entity số | `body_decoded` |
| SMTP | body MIME có `Content-Transfer-Encoding: base64` | Base64 | `body_decoded` |
| SMTP | body MIME có `Content-Transfer-Encoding: quoted-printable` | Quoted-Printable, gồm soft line break | `body_decoded` |
| mọi text | byte payload | UTF-8, byte không hợp lệ thay bằng `�` | `body`, `payload_text` trong `app` |

`Content-Type` được so khớp không phân biệt hoa thường và bỏ qua tham số, ví dụ
`text/html; charset=utf-8` vẫn được nhận là HTML. Encoding `7bit`, `8bit`, `binary` được bỏ
qua vì không cần decode.

Body SMTP được decode nhờ **SMTP session tracking** gắn trên flow: khi client gửi `DATA` và
server trả `354`, flow chuyển sang pha data. Mọi packet của client trong pha này được phân
loại lại thành `message_type` là `data`, kể cả khi nội dung trông giống command. Encoding đọc
từ header MIME được lưu vào trạng thái của flow nên các packet data tiếp theo của cùng thư
vẫn biết cách decode. Dòng `.` kết thúc thư đưa flow về pha command, encoding được đặt lại cho
thư kế tiếp.

### Giá trị `decode_status`

Trạng thái chỉ được hạ xuống theo thứ tự `ok` → `partial` → `failed`, không bao giờ nâng lên.

| giá trị | khi nào |
| --- | --- |
| không có field | event không có dữ liệu nào cần decode |
| `ok` | mọi phần được decode trọn vẹn |
| `partial` | decode được một phần: có byte không phải UTF-8 hợp lệ, hoặc khối Base64 bị cắt lẻ |
| `failed` | không decode được: Base64 chứa ký tự lạ, encoding MIME không hỗ trợ, hoặc decoder ném exception |

## Module Preprocessor

Chuẩn hóa và kiểm tra event để các module phía sau nhận một biểu diễn nhất quán.

### Normalization

| dữ liệu | quy tắc | ví dụ |
| --- | --- | --- |
| `transport_protocol`, `app_protocol` | bỏ khoảng trắng hai đầu, viết hoa | `" tcp "` → `TCP` |
| `src_ip`, `dst_ip` | bỏ khoảng trắng, đưa về dạng chuẩn của `ipaddress` | `" 10.0.0.1 "` → `10.0.0.1` |
| `timestamp` | chuỗi hoặc số nguyên số đổi thành float | `"1790604355.5"` → `1790604355.5` |
| HTTP header name | viết thường; header trùng tên khác kiểu chữ được gộp bằng `, ` | `X-Test: one` và `x-TEST: two` → `x-test: one, two` |
| HTTP `Host` | domain viết thường, bỏ dấu `.` cuối, giữ port | `WWW.Example.COM.:80` → `www.example.com:80` |
| URI path | xử lý `.`, `..`, `//`; giữ kiểu chữ của path và giữ nguyên query | `/A/./b/../c//d/?q=1` → `/A/c/d/?q=1` |
| DNS name trong question và answer | viết thường, bỏ dấu `.` cuối | `WWW.ExAmPlE.CoM.` → `www.example.com` |

URI chuẩn hóa được ghi vào `uri_normalized`, lấy từ `uri_decoded` nếu có, nếu không thì từ
`app.uri`. Path giữ kiểu chữ vì theo RFC 3986 path phân biệt hoa thường.

### Missing data

| dữ liệu thiếu hoặc là `None` | giá trị điền |
| --- | --- |
| `errors`, `reason` | `[]` |
| `headers` của HTTP request và response | `{}` |
| `questions`, `answers` của DNS | `[]` |
| `commands` của SMTP command, `messages` của SMTP response | `[]` |
| key có giá trị `None` trong `app` | bị xóa khỏi `app` |
| event không có `app` | giữ `app` là `null`, không tạo dict rỗng |

### Validation và giá trị `preprocess_status`

Trạng thái chỉ được hạ xuống theo thứ tự `valid` → `partial` → `invalid`. Mỗi lần hạ đều
thêm một dòng vào `reason`.

| giá trị | khi nào |
| --- | --- |
| `valid` | mọi kiểm tra đều đạt |
| `partial` | 5-tuple vẫn đúng nhưng nội dung chưa trọn vẹn: `parse_status` là `PARTIAL`, `decode_status` là `partial` hoặc `failed`, `app_protocol` không thuộc `HTTP`, `DNS`, `SMTP`, `UNKNOWN`, `app_protocol` không khớp transport như HTTP trên UDP, hoặc TCP event thiếu `tcp_flags` |
| `invalid` | sai hoặc thiếu field Flow Tracker cần: `packet_id` không phải số dương, `timestamp` không phải float hữu hạn không âm, `source_type` khác `pcap`/`live`, IP thiếu hoặc sai, `transport_protocol` thiếu hoặc khác `TCP`/`UDP`, port thiếu hoặc ngoài khoảng 0 đến 65535, `ip_proto` không khớp transport, hoặc `parse_status` là `MALFORMED` |

Event có `parse_status` là `UNKNOWN`, `ip_version` khác 4 hoặc địa chỉ IPv6 được xem là
**unsupported**, `reason` có dòng bắt đầu bằng `unsupported:`.

### Policy và giá trị `processing_action`

| giá trị | khi nào |
| --- | --- |
| `pass` | event `valid` và được hỗ trợ |
| `mark` | event `partial`, `invalid` hoặc unsupported, policy tương ứng là `keep` |
| `drop` | event `invalid` với `invalid_policy: drop`, hoặc unsupported với `unsupported_policy: drop` |

Event `drop` không được ghi vào `events.jsonl` và không vào flow, nhưng vẫn được đếm trong
dòng tổng kết.

## Module Flow/Connection Tracker

Gom các packet cùng phiên giao tiếp thành một flow hai chiều, duy trì trạng thái và thống kê.

### Nhận diện flow và direction

- **Flow key** gồm `protocol` và hai endpoint `ip:port` đã được sắp xếp theo thứ tự cố định,
  nên packet A→B và B→A cho ra cùng một key.
- **`flow_id`** là 16 ký tự hex đầu của SHA-1 tính trên flow key và `start_time`. Vì
  `start_time` lấy từ timestamp của packet, chạy lại trên cùng pcap luôn ra cùng `flow_id`,
  còn hai lần kết nối cùng 5-tuple ở hai thời điểm khác nhau có `flow_id` khác nhau.
- **Endpoint A** là bên gửi packet đầu tiên của flow. Packet đi từ A là `forward`, packet đi
  từ B là `backward`.
- Event **không được đưa vào flow** khi có `processing_action` là `drop`, `preprocess_status`
  là `invalid`, hoặc thiếu thông tin để dựng 5-tuple như ARP, IPv6, ICMP.

### TCP state machine

| trạng thái hiện tại | packet nhận | trạng thái mới |
| --- | --- | --- |
| mọi trạng thái chưa đóng | có `RST` | `RESET` |
| `NEW` | `SYN` | `HANDSHAKE` |
| `NEW`, `HANDSHAKE` | `SYN-ACK` | `HANDSHAKE`, ghi nhận đã thấy SYN-ACK |
| `HANDSHAKE` đã thấy SYN-ACK | `ACK` không có `SYN` | `ESTABLISHED` |
| `NEW`, `HANDSHAKE`, `ESTABLISHED`, `CLOSING` | `FIN` chỉ từ một phía | `CLOSING` |
| `NEW`, `HANDSHAKE`, `ESTABLISHED`, `CLOSING` | đã có `FIN` từ cả hai phía | `CLOSED` |
| `CLOSED`, `RESET` | packet khác | giữ nguyên, packet vẫn được tính vào thống kê |
| `CLOSED`, `RESET` | `SYN` không có `ACK` | flow cũ kết thúc với `end_reason` là `new_connection`, tạo flow mới |

Flow bắt đầu giữa chừng, tức packet đầu không phải `SYN`, giữ trạng thái `NEW`.

### UDP flow và idle timeout

- UDP không có trạng thái kết nối: các packet cùng 5-tuple hai chiều trong thời gian chưa
  vượt timeout thuộc cùng một flow.
- Mỗi flow hết hạn khi `clock - last_seen > timeout`, dùng `tcp_idle_timeout` cho TCP và
  `udp_idle_timeout` cho UDP.
- `clock` là timestamp lớn nhất đã thấy trong các packet, **không phải đồng hồ hệ thống**,
  nên kết quả với cùng một pcap luôn tái hiện được.
- Việc kiểm tra hết hạn chạy mỗi khi có packet hợp lệ mới. Flow hết hạn được ghi ra
  `flows.jsonl` ngay và xóa khỏi active table; packet sau đó cùng 5-tuple tạo flow mới.
- Khi kết thúc capture, mọi flow còn lại được ghi ra với `end_reason` là `end_of_capture`.

### Giá trị `end_reason`

| giá trị | khi nào |
| --- | --- |
| `timeout` | flow im lặng quá idle timeout |
| `end_of_capture` | flow còn mở khi hết pcap hoặc dừng live capture |
| `new_connection` | flow TCP đã `CLOSED` hoặc `RESET` mà gặp `SYN` mới cùng 5-tuple |

## Pipeline xử lý

```text
[ Packet Capture ]  (PcapCapture | LiveCapture)
       │
       ▼  yield (packet, timestamp)
┌──────────────────────────────────────────────────────────────┐
│ Bài 1: Processing Pipeline                                   │
│                                                              │
│  1. Event Init        → tạo Event rỗng + metadata            │
│  2. Ethernet Parser   → src_mac, dst_mac                     │
│  3. IPv4 Parser       → src_ip, dst_ip, ttl, ...             │
│  4. TCP/UDP Parser    → src_port, dst_port, flags, ...       │
│  5. Protocol Detector → app_protocol, detection_method       │
│  6. App Parser        → app dict, parse_status, errors       │
└──────────────────────────────────────────────────────────────┘
       │  Event
       ▼
┌──────────────────────────────────────────────────────────────┐
│ Bài 2                                                        │
│                                                              │
│  7. Decoder           → uri_decoded, body_decoded,           │
│                         decode_status                        │
│  8. Preprocessor      → normalize, fill missing, validate,   │
│                         policy: uri_normalized,              │
│                         preprocess_status, processing_action,│
│                         reason                               │
│  9. Flow Tracker      → flow_id, direction                   │
│                         + kiểm tra timeout, cập nhật         │
│                           thống kê, TCP state, SMTP session  │
└──────────────────────────────────────────────────────────────┘
       │                                   │
       │ event.to_dict()                   │ flow hết hạn, flow còn lại
       │ trừ event drop                    │ khi kết thúc capture
       ▼                                   ▼
[ Event Writer ] events.jsonl       [ Flow Writer ] flows.jsonl

                 [ Runtime Logger ] ids.log
```

- Mỗi tầng của bài 1 chỉ chạy một parser: pipeline hỏi `can_parse()` rồi gọi `parse()` của
  parser đầu tiên nhận packet. Parser tầng ứng dụng được chọn theo `app_protocol` mà detector
  vừa gán.
- Mỗi bước 7, 8, 9 có guard riêng trong `cli.py`: exception của một bước được ghi vào `errors`
  với tiền tố `cli:` và log, các bước sau và packet sau vẫn chạy tiếp.
- Detection Engine ở các bài sau chỉ làm việc với `events.jsonl` và `flows.jsonl`, không truy
  cập trực tiếp packet của Scapy.

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

Dừng live capture bằng `Ctrl+C`: chương trình ghi nốt event cuối, ghi toàn bộ flow còn mở
rồi thoát với exit code 0.

### Tham số

| tham số | bắt buộc | mặc định | ý nghĩa |
| --- | --- | --- | --- |
| `--pcap` | chọn 1 trong 2 | | đường dẫn file pcap hoặc pcap.gz |
| `--interface` | chọn 1 trong 2 | | tên card mạng để bắt trực tiếp |
| `--output` | không | `logs/events.jsonl` | file JSONL chứa event, ghi ở chế độ append |
| `--flow-output` | không | `logs/flows.jsonl` | file JSONL chứa flow, ghi ở chế độ append, phải khác `--output` |
| `--log-file` | không | `logs/ids.log` | file log runtime, ghi ở chế độ append |
| `--config` | không | `config/default.yaml` | file YAML cấu hình |

Các file output đều ghi nối, nên mỗi lần chạy lại cần xóa file cũ hoặc đổi đường dẫn.
Ví dụ chạy cho một testcase:

```bash
D=TEST/requirements2/t08_bidirectional_flow
python main.py --pcap $D/input.pcap \
  --output $D/events.jsonl \
  --flow-output $D/flows.jsonl \
  --log-file $D/run_log.txt
```

### Cấu hình

`config/default.yaml`:

```yaml
# giới hạn nội dung phần body parser lưu lại vào event
parser:
  max_body_bytes: 65536

# thời gian timeout khi k nhận packet mới đối với flow
flow:
  tcp_idle_timeout: 120
  udp_idle_timeout: 30

# keep/drop gói tin khi preprocessed xử lý
preprocess:
  invalid_policy: keep
  unsupported_policy: keep
```

| key | giá trị hợp lệ | ý nghĩa |
| --- | --- | --- |
| `parser.max_body_bytes` | số nguyên lớn hơn 0 | số byte body HTTP và payload SMTP tối đa lưu vào `app` |
| `flow.tcp_idle_timeout` | số lớn hơn 0, đơn vị giây | idle timeout của flow TCP |
| `flow.udp_idle_timeout` | số lớn hơn 0, đơn vị giây | idle timeout của flow UDP |
| `preprocess.invalid_policy` | `keep` hoặc `drop` | xử lý event `invalid` |
| `preprocess.unsupported_policy` | `keep` hoặc `drop` | xử lý event unsupported |

File config chỉ cần ghi các key muốn đổi, key còn lại lấy giá trị mặc định. Key không biết
được cảnh báo trong log rồi bỏ qua. File không tồn tại thì dùng toàn bộ giá trị mặc định.

### Kết quả trên terminal và exit code

Mỗi lượt chạy kết thúc bằng hai dòng tổng kết trên `stderr`:

```text
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
```

| exit code | trường hợp |
| --- | --- |
| 0 | chạy hết nguồn, hoặc người dùng bấm `Ctrl+C` |
| 1 | lỗi nguồn capture `CaptureError`, lỗi ghi file output `OSError`, config không hợp lệ, hoặc `--output` và `--flow-output` trỏ cùng một file |

`stdout` không có gì, nên output JSONL không bao giờ lẫn với thông báo của chương trình.
Chi tiết lỗi và traceback nằm trong file log; terminal chỉ hiện mức `WARNING` trở lên.

## Ví dụ output

Mỗi dòng là một record. Field nào không có giá trị thì bị lược khỏi JSON.

### `events.jsonl`

HTTP request có URI percent-encoding, nguyên văn một dòng của testcase T01:

```json
{"packet_id":4,"timestamp":1791813414.171048,"source":"TEST/requirements2/t01_http_url_decode/input.pcap","source_type":"pcap","src_mac":"00:00:00:00:00:00","dst_mac":"00:00:00:00:00:00","src_ip":"127.0.0.1","dst_ip":"127.0.0.1","ip_version":4,"ttl":64,"ip_len":190,"ip_id":21178,"ip_proto":6,"ip_flags":"DF","frag_offset":0,"src_port":45892,"dst_port":8000,"transport_protocol":"TCP","seq":3829960998,"ack":362091946,"tcp_flags":"PSH-ACK","window":64,"payload_len":138,"app_protocol":"HTTP","detection_method":"payload","app":{"message_type":"request","method":"GET","uri":"/admin%2Fpanel/login.php?user=admin%27%20OR%201%3D1--&pass=a+b","version":"HTTP/1.1","headers":{"host":"127.0.0.1:8000","user-agent":"curl/8.5.0","accept":"*/*"},"body_len":0,"body":"","body_truncated":false,"body_text_status":"ok"},"parse_status":"OK","errors":[],"uri_decoded":"/admin/panel/login.php?user=admin' OR 1=1--&pass=a b","decode_status":"ok","uri_normalized":"/admin/panel/login.php?user=admin' OR 1=1--&pass=a b","preprocess_status":"valid","processing_action":"pass","reason":[],"flow_id":"4d1b59e292561f35","direction":"forward"}
```

SMTP data có body Base64, testcase T03, đã lược phần metadata và các field tầng dưới:

```json
{"packet_id":18,"src_port":36212,"dst_port":25,"transport_protocol":"TCP","app_protocol":"SMTP","detection_method":"port","app":{"message_type":"data","data_len":239,"payload_text":"From: alice@test.local\r\n...\r\nContent-Transfer-Encoding: base64\r\n\r\nWGluIGNow6BvLCDEkcOieSBsw6AgdGjGsCB0aOG7rSBuZ2hp4buHbSBUMDMgQmFzZTY0Lg==\r\n.\r\n","payload_truncated":false,"payload_text_status":"ok"},"parse_status":"OK","errors":[],"body_decoded":"Xin chào, đây là thư thử nghiệm T03 Base64.","decode_status":"ok","preprocess_status":"valid","processing_action":"pass","reason":[],"flow_id":"e034813dce5c4ba9","direction":"forward"}
```

Packet IPv4 hỏng header, nguyên văn một dòng của testcase T14:

```json
{"packet_id":1,"timestamp":1791818207.098691,"source":"TEST/requirements2/t14_malformed_event/input.pcap","source_type":"pcap","src_mac":"02:00:00:00:00:01","dst_mac":"02:00:00:00:00:02","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","ip_version":4,"ttl":64,"ip_len":40,"ip_id":1,"ip_proto":6,"ip_flags":"","frag_offset":0,"parse_status":"MALFORMED","errors":["ipv4: invalid ihl: header is 12 bytes, captured 40","tcp: ip_proto is TCP but the TCP header is missing or shorter than 20 bytes"],"preprocess_status":"invalid","processing_action":"mark","reason":["transport_protocol: missing","src_port: missing","dst_port: missing","parse_status: MALFORMED"]}
```

Packet ARP không hỗ trợ, nguyên văn một dòng của testcase T14:

```json
{"packet_id":3,"timestamp":1791818207.09872,"source":"TEST/requirements2/t14_malformed_event/input.pcap","source_type":"pcap","src_mac":"02:00:00:00:00:01","dst_mac":"02:00:00:00:00:02","parse_status":"UNKNOWN","errors":[],"preprocess_status":"valid","processing_action":"mark","reason":["unsupported: parse_status UNKNOWN"]}
```

### `flows.jsonl`

Flow TCP HTTP đóng bằng FIN, nguyên văn của testcase T08:

```json
{"flow_id":"2f28d9706145c21e","protocol":"TCP","application_protocol":"HTTP","a_ip":"127.0.0.1","a_port":44238,"b_ip":"127.0.0.1","b_port":8000,"start_time":1791816511.760223,"last_seen":1791816511.761306,"duration":0.001083,"packet_count":12,"byte_count":1603,"fwd_packet_count":6,"fwd_byte_count":397,"bwd_packet_count":6,"bwd_byte_count":1206,"syn_count":2,"ack_count":11,"fin_count":2,"rst_count":0,"state":"CLOSED","end_reason":"end_of_capture"}
```

Flow UDP DNS, nguyên văn của testcase T10. Flow UDP không có các field riêng của TCP:

```json
{"flow_id":"87a6782bbc9f2fcb","protocol":"UDP","application_protocol":"DNS","a_ip":"172.18.124.92","a_port":43387,"b_ip":"8.8.8.8","b_port":53,"start_time":1791816986.157162,"last_seen":1791816986.200029,"duration":0.042867,"packet_count":2,"byte_count":180,"fwd_packet_count":1,"fwd_byte_count":80,"bwd_packet_count":1,"bwd_byte_count":100,"end_reason":"end_of_capture"}
```

Đọc file bằng `jq`:

```bash
jq -c 'select(.parse_status != "OK") | {packet_id, parse_status, errors}' logs/events.jsonl
jq -r .preprocess_status logs/events.jsonl | sort | uniq -c
jq -c '{flow_id, protocol, state, packet_count, end_reason}' logs/flows.jsonl
```

## Schema của event

Định nghĩa trong `idscore/models/event.py`. Field có giá trị `None` bị `to_dict()` lược bỏ,
nên một dòng JSONL chỉ chứa những gì thực sự có giá trị.

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
| | `tcp_flags` | str | tên các cờ nối bằng `-` theo thứ tự bit `FIN, SYN, RST, PSH, ACK, URG, ECE, CWR`, ví dụ `SYN-ACK`; rỗng nếu không bật cờ nào |
| | `window` | int | window size, chỉ có ở TCP |
| | `payload_len` | int | số byte payload trong segment này, đã trừ phần padding của Ethernet |
| application | `app_protocol` | str | `HTTP`, `DNS`, `SMTP`, hoặc `UNKNOWN` khi có payload mà không nhận diện được |
| | `detection_method` | str | `payload` hoặc `port`; không có field này nghĩa là không nhận diện được |
| | `app` | dict | dữ liệu do parser tầng ứng dụng bóc tách, không chứa giá trị `None` |
| trạng thái parse | `parse_status` | str | `OK`, `PARTIAL`, `UNKNOWN`, `MALFORMED` |
| | `errors` | list[str] | danh sách message lỗi, mỗi message có tiền tố là tầng hoặc module phát sinh |
| decode | `uri_decoded` | str | URI HTTP sau khi decode |
| | `body_decoded` | str | body HTTP hoặc body MIME của SMTP sau khi decode |
| | `decode_status` | str | `ok`, `partial`, `failed`; không có nếu không có gì để decode |
| preprocess | `uri_normalized` | str | URI sau khi chuẩn hóa path |
| | `preprocess_status` | str | `valid`, `partial`, `invalid` |
| | `processing_action` | str | `pass`, `mark`, `drop` |
| | `reason` | list[str] | lý do hạ `preprocess_status`, lý do unsupported và lý do drop |
| flow | `flow_id` | str | id của flow chứa event; không có nếu event không vào flow |
| | `direction` | str | `forward` hoặc `backward` |

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
ngoài; `decoder:` là lỗi của Decoder; `preprocessor:` là lỗi của Preprocessor; `flow:` là
lỗi của Flow Tracker; `cli:` là lỗi bị guard trong `cli.py` bắt được khi xử lý hoặc ghi
packet đó.

### Dict trong field `app` theo từng giao thức

- HTTP
  - request: `message_type`, `method`, `uri`, `version`, `headers`, `body_len`, `body`,
    `body_truncated`, `body_text_status`
  - response: `message_type`, `version`, `status_code`, `reason`, `headers`, `body_len`,
    `body`, `body_truncated`, `body_text_status`
  - segment tiếp nối không có start line: `message_type` là `continuation` kèm `body_len`
    và các field body
- DNS: `transaction_id`, `message_type` là `query` hoặc `response`, `opcode`, `rcode`,
  `flags`, bốn count, `questions` gồm `name`, `qtype`, `qclass`, `qtype_name` và `answers`
  gồm `name`, `type`, `class`, `ttl`, `type_name`, `rdata`
- SMTP
  - command: `message_type`, `commands` gồm `verb`, `argument`, thêm `address` với `MAIL` và `RCPT`
  - response: `message_type`, `code`, `messages`, `final`
  - xử lý được nhiều dòng trong một segment, ví dụ chuỗi `250-...`
  - nội dung thư sau lệnh `DATA`: `message_type` là `data` kèm `data_len`
  - mọi message SMTP có thêm `payload_text`, `payload_truncated`, `payload_text_status`
  - packet bị session tracking phân loại lại thành data có thêm `reclassified_from` ghi loại cũ

`body_text_status` và `payload_text_status` là kết quả decode UTF-8 của riêng phần text đó:
`ok` hoặc `partial`. Giá trị này được gộp vào `decode_status` của event.

## Schema của flow

Định nghĩa trong `idscore/models/flow.py`. Field có giá trị `None` và field nội bộ bắt đầu
bằng `_` bị `to_dict()` lược bỏ.

| nhóm | field | kiểu | mô tả |
| --- | --- | --- | --- |
| định danh | `flow_id` | str | 16 ký tự hex, ổn định với cùng một pcap |
| | `protocol` | str | `TCP` hoặc `UDP` |
| | `application_protocol` | str | giao thức ứng dụng đầu tiên nhận diện được trong flow, `UNKNOWN` được thay khi gặp giao thức cụ thể; không có nếu flow không mang payload |
| | `a_ip`, `a_port` | str, int | endpoint A, bên gửi packet đầu tiên |
| | `b_ip`, `b_port` | str, int | endpoint B |
| thời gian | `start_time` | float | timestamp packet đầu tiên |
| | `last_seen` | float | timestamp lớn nhất trong flow |
| | `duration` | float | `last_seen - start_time`, làm tròn 6 chữ số |
| tổng thể | `packet_count` | int | số packet của flow |
| | `byte_count` | int | tổng `ip_len` của các packet |
| hai chiều | `fwd_packet_count`, `fwd_byte_count` | int | packet và byte theo chiều A→B |
| | `bwd_packet_count`, `bwd_byte_count` | int | packet và byte theo chiều B→A |
| TCP | `syn_count`, `ack_count`, `fin_count`, `rst_count` | int | số packet có cờ tương ứng; chỉ có ở flow TCP |
| | `state` | str | `NEW`, `HANDSHAKE`, `ESTABLISHED`, `CLOSING`, `CLOSED`, `RESET`; chỉ có ở flow TCP |
| kết thúc | `end_reason` | str | `timeout`, `end_of_capture`, `new_connection` |

Một packet có nhiều cờ được tính vào mọi bộ đếm tương ứng, ví dụ `SYN-ACK` tăng cả
`syn_count` và `ack_count`.

## Testcase

Testcase cùng input, output và log nằm trong [TEST/](TEST/):

| bài | số testcase | bảng mapping và báo cáo |
| --- | --- | --- |
| Bài tập 1 | 12, `tc01` đến `tc12` | [TEST/requirements1/README.md](TEST/requirements1/README.md) |
| Bài tập 2 | 14, `t01` đến `t14` | [TEST/requirements2/README.md](TEST/requirements2/README.md) |

Mỗi testcase bài 2 là một thư mục gồm `input.pcap`, `events.jsonl`, `flows.jsonl`,
`run_log.txt` và script tạo input khi cần. Riêng t05, t06, t14 dùng thêm event giả đưa thẳng
vào chuỗi `Decoder`, `Preprocessor`, `FlowTracker`, vì parser không bao giờ sinh ra event
thiếu field hoặc sai kiểu; các script này chạy với `PYTHONPATH=.` từ thư mục gốc dự án.

## Lưu ý khi làm

### Bài tập 1: Packet Capture & Parser

- Output live có packet ARP. Đây là packet không phải IPv4, pipeline phải gán UNKNOWN cho loại này chứ không được crash khi tìm lớp IP.
- TCP header là 1 cờ có 8 bit, tương ứng với thứ tự `["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]`, lưu ý để detect chính xác.
- Bài tập yêu cầu không được chỉ sử dụng port để xác định protocol => phải kiểm tra payload thô để xem nội dung payload thay vì dùng layer dựng sẵn của scapy.
- Event không phụ thuộc Scapy vì Detector chỉ làm việc với event, còn parser sẽ tiếp xúc với scapy.
- Với file pcapng có linktype không hỗ trợ, các frame vẫn bị gán `MALFORMED`.
- Lỗi của chính chương trình cũng mang `parse_status` là `MALFORMED`, chỉ phân biệt được với packet hỏng thật qua tiền tố `cli:` trong `errors`. Đây là trade-off để giữ schema đúng 4 trạng thái đã chốt.

### Bài tập 2: Decoder, Preprocessor & Flow/Connection Tracker

- Chưa có TCP stream reassembly: Decoder chỉ làm việc trên từng packet. Body HTTP nằm ở segment khác với header sẽ không biết `Content-Type` nên không được decode; khối Base64 bị cắt giữa hai segment SMTP sẽ decode lỗi phần bị cắt và đánh dấu `partial`. Khi tạo input cho testcase decode phải đảm bảo header và body nằm chung một segment.
- SMTP session tracking giúp nhận đúng packet DATA và nhớ encoding qua nhiều packet của cùng thư, nhưng chỉ hoạt động khi flow bắt được cả lệnh `DATA` và mã `354`. Pcap bắt đầu giữa pha data sẽ không nhận ra packet data.
- Decoder không ghi đè dữ liệu gốc: `app.uri`, `app.body`, `app.payload_text` giữ nguyên, bản decode nằm ở field riêng để Detection Engine so khớp được cả hai dạng.
- `parse_status` và `decode_status` tách riêng: packet parse đúng cấu trúc nhưng chứa byte không phải UTF-8 vẫn là `OK` ở `parse_status` và `partial` ở `decode_status`.
- Parser của bài 1 đã viết thường header name, nên normalization header ở Preprocessor chủ yếu đảm bảo nhất quán khi event đến từ nguồn khác. Path URI giữ nguyên kiểu chữ vì phân biệt hoa thường.
- Preprocessor chưa kiểm tra kiểu của `app`: event có `app` không phải dict vẫn được đánh `valid`. Parser không bao giờ sinh ra trường hợp này.
- `invalid` dành cho lỗi ở field Flow Tracker cần để dựng 5-tuple nên event bị loại khỏi flow; `partial` dành cho lỗi ở nội dung nên event vẫn được tính vào flow.
- Event bị `drop` vẫn được đếm trong dòng `Total packets`, số lượng hiện ở `Dropped events`, nên `Total packets` có thể lớn hơn số dòng của `events.jsonl`.
- Timeout tính theo timestamp của packet chứ không theo đồng hồ hệ thống, để chạy lại cùng pcap luôn ra cùng kết quả. Hệ quả là flow chỉ được kiểm tra hết hạn khi có packet mới đẩy clock lên; flow cuối cùng của pcap luôn kết thúc với `end_of_capture`.
- `flow_id` băm cả `start_time`, nên cùng 5-tuple nhưng kết nối lại sau timeout hoặc sau khi đóng sẽ là flow khác với `flow_id` khác.
- `--output` và `--flow-output` phải là hai file khác nhau: hai writer cùng append một file sẽ làm lẫn hai schema.

## Mục đích khi sử dụng các công cụ AI

#### Mục đích:

- Thiết kế cấu trúc thư mục dự án
- Kiểm tra syntax và logic của các đoạn code, cải thiện hoặc chỉnh sửa style code để tối ưu.

#### Công cụ: GitHub Copilot + Claude Code

File có hỗ trợ AI: 
- `idscore/capture/base.py`, `idscore/capture/pcap.py`, `idscore/capture/live.py`, `idscore/cli.py`, `main.py`, `idscore/parsers/application/dns.py`, `TEST/tc12_malformed_packet/gen_malformed.py`, `idscore/pipeline.py`, `idscore/utils/logger.py`
- Các script tạo test cho các testcase trong TEST/requirements2.
- Các file trong thư mục idscore/flow


## Tài liệu liên quan sử dụng trong quá trình làm

https://minhtriet0502-note.notion.site/PLAN-3e5730cee68d80f785edfd92cd5a1f54
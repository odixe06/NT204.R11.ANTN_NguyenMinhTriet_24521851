# NT204.R11.ANTN_NguyenMinhTriet_24521851

**Bài tập lớn của sinh viên Nguyễn Minh Triết - môn IDPS - lớp  NT204.R11.ANTN.**

## Môi trường:

File requirements.txt là các thư viện cần cài vào môi trường để sử dụng, trong máy local xây dựng dự án là env btids.

```bash
conda activate btids
```

## Pipeline xử lý: 

```text
[ Packet Capture ]
       │
       ▼  yield (packet, timestamp)
┌────────────────────────────────────────────────────────┐
│ Processing Pipeline                                    │
│                                                        │
│  1. Event Init        → Tạo Event rỗng + metadata      │
│  2. IPv4 Parser       → src_ip, dst_ip, ttl, ...       │
│  3. TCP/UDP Parser    → src_port, dst_port, flags, ... │
│  4. Protocol Detector → app_protocol, detection_method │
│  5. App Parser        → bóc tách payload thành app dict│
└────────────────────────────────────────────────────────┘
       │
       ▼  event.to_dict()
[ JSON Lines Logger ] (.jsonl)
```           

## Mục đích khi sử dụng các công cụ AI:

- Thiết kế cấu trúc thư mục dự án
- Kiểm tra syntax và logic của các đoạn code, cải thiện hoặc chỉnh sửa style code để tối ưu.
- Công cụ: GitHub Copilot + Claude Code
- File có hỗ trợ AI: `idscore/capture/base.py`, `idscore/capture/pcap.py`, `idscore/capture/live.py`, `idscore/cli.py`, `main.py`, `idscore/parsers/application/dns.py`


## Lưu ý khi làm:

- Output live có packet ARP. Đây là packet không phải IPv4, pipeline ở phase 3 phải gán UNKNOWN cho loại này chứ không được crash khi tìm lớp IP.
- TCP header là 1 cờ có 8 bit, tương ứng với thứ tự ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"], lưu ý để detect chính xác. 
- Bài tập yêu cầu không được chỉ sử dụng port để xác định protocol => phải kiểm tra payload thô để xem nội dung payload thay vì dùng layer dựng sẵn của scapy.
- Event không phụ thuộc Scapy vì Detector chỉ làm việc với event, còn parser sẽ tiếp xúc với scapy.

#### Dict trong field app ghi những thông tin gì với các giao thức được hỗ trợ: 

Mỗi parser cần lấy các field sau:

- HTTP:
       
       - request: method, uri, version, headers, body length
       - response: version, status code, reason, headers
- DNS: transaction id, qr, opcode, rcode, question gồm qname, qtype, qclass, và answer gồm name, type, ttl, rdata
- SMTP:

       - command: verb, argument
       - response: status code, message
       - xử lý được nhiều dòng trong một segment, ví dụ chuỗi 250-...
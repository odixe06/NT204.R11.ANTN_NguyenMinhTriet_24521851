# TEST

## Bảng mapping testcase và file bằng chứng

Mỗi testcase là một thư mục gồm `input.pcap` (input đã bắt), `events.jsonl` (output của IDS)
và `run_log.txt` (log runtime, chứa dòng tổng kết). Lệnh chạy chung:

```bash
python main.py --pcap TEST/<tcXX>/input.pcap \
  --output TEST/<tcXX>/events.jsonl \
  --log-file TEST/<tcXX>/run_log.txt
```

| # | testcase | báo cáo | input | output | log | dòng tổng kết |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | TCP Handshake | [báo cáo](#testcase-01-tcp-handshake) | [input.pcap](tc01_tcp_handshake/input.pcap) | [events.jsonl](tc01_tcp_handshake/events.jsonl) | [run_log.txt](tc01_tcp_handshake/run_log.txt) | `Total packets: 3 (OK 3, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 02 | TCP Data | [báo cáo](#testcase-02-tcp-data) | [input.pcap](tc02_tcp_data/input.pcap) | [events.jsonl](tc02_tcp_data/events.jsonl) | [run_log.txt](tc02_tcp_data/run_log.txt) | `Total packets: 8 (OK 8, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 03 | UDP | [báo cáo](#testcase-03-udp) | [input.pcap](tc03_udp/input.pcap) | [events.jsonl](tc03_udp/events.jsonl) | [run_log.txt](tc03_udp/run_log.txt) | `Total packets: 1 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 04 | HTTP Get | [báo cáo](#testcase-04-http-get) | [input.pcap](tc04_http_get/input.pcap) | [events.jsonl](tc04_http_get/events.jsonl) | [run_log.txt](tc04_http_get/run_log.txt) | `Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 05 | HTTP Post | [báo cáo](#testcase-05-http-post) | [input.pcap](tc05_http_post/input.pcap) | [events.jsonl](tc05_http_post/events.jsonl) | [run_log.txt](tc05_http_post/run_log.txt) | `Total packets: 10 (OK 10, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 06 | HTTP Response | [báo cáo](#testcase-06-http-response) | [input.pcap](tc06_http_response/input.pcap) | [events.jsonl](tc06_http_response/events.jsonl) | [run_log.txt](tc06_http_response/run_log.txt) | `Total packets: 10 (OK 10, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 07 | DNS Query | [báo cáo](#testcase-07-dns-query) | [input.pcap](tc07_dns_query/input.pcap) | [events.jsonl](tc07_dns_query/events.jsonl) | [run_log.txt](tc07_dns_query/run_log.txt) | `Total packets: 1 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 08 | DNS Response | [báo cáo](#testcase-08-dns-response) | [input.pcap](tc08_dns_response/input.pcap) | [events.jsonl](tc08_dns_response/events.jsonl) | [run_log.txt](tc08_dns_response/run_log.txt) | `Total packets: 1 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 09 | SMTP Command | [báo cáo](#testcase-09-smtp-command) | [input.pcap](tc09_smtp_command/input.pcap) | [events.jsonl](tc09_smtp_command/events.jsonl) | [run_log.txt](tc09_smtp_command/run_log.txt) | `Total packets: 11 (OK 11, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 10 | SMTP Response | [báo cáo](#testcase-10-smtp-response) | [input.pcap](tc10_smtp_response/input.pcap) | [events.jsonl](tc10_smtp_response/events.jsonl) | [run_log.txt](tc10_smtp_response/run_log.txt) | `Total packets: 13 (OK 13, PARTIAL 0, UNKNOWN 0, MALFORMED 0)` |
| 11 | Unknown protocol | [báo cáo](#testcase-11-unknown-protocol) | [input.pcap](tc11_unknown_protocol/input.pcap) | [events.jsonl](tc11_unknown_protocol/events.jsonl) | [run_log.txt](tc11_unknown_protocol/run_log.txt) | `Total packets: 30 (OK 24, PARTIAL 0, UNKNOWN 6, MALFORMED 0)` |
| 12 | Malformed packet | [báo cáo](#testcase-12-malformed-packet) | [input.pcap](tc12_malformed_packet/input.pcap) · [gen_malformed.py](tc12_malformed_packet/gen_malformed.py) | [events.jsonl](tc12_malformed_packet/events.jsonl) | [run_log.txt](tc12_malformed_packet/run_log.txt) | `Total packets: 7 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 6)` |

Riêng tc12, input không bắt được từ mạng thật nên được sinh bằng
[gen_malformed.py](tc12_malformed_packet/gen_malformed.py):

```bash
python TEST/tc12_malformed_packet/gen_malformed.py
```

## Testcase 01: TCP Handshake

#### Mục tiêu khi bắt pcap

Bắt một pcap chỉ chứa đúng 3 packet của một lần bắt tay TCP: SYN, SYN/ACK, ACK.

Dùng `curl` tới server ngoài trên `eth0`: 

```bash
  sudo tcpdump -i eth0 -nn -S -c 3 -Z $USER -w TEST/tc01_tcp_handshake/input.pcap 'tcp port 80 and host example.com'

```

```bash
tcpdump -nn -S -r TEST/tc01_tcp_handshake/input.pcap
```

### **Chạy ids và output thu được:**

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc01_tcp_handshake/input.pcap --output TEST/tc01_tcp_handshake/events.jsonl --log-file TEST/tc01_tcp_handshake/run_log.txt
echo $?
Total packets: 3 (OK 3, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

### tc01 **đạt:**

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `run_log.txt` có dòng `Total packets: 3` | đạt |
| 2 | xử lý đủ số packet trong pcap | 3 event, khớp 3 packet trong `tcpdump` | đạt |
| 3 | nhận diện đúng cờ handshake | `tcp_flags` lần lượt là `SYN`, `SYN-ACK`, `ACK` | đạt |
| 4 | seq và ack nối tiếp nhau, cùng một handshake | ack packet 2 `1291727710` bằng seq packet 1 cộng 1; ack packet 3 `3871782749` bằng seq packet 2 cộng 1; seq packet 3 `1291727710` bằng seq packet 1 cộng 1 | đạt |
| 5 | hướng kết nối đúng | packet 1 và 3 đi từ client `172.18.124.92:55996` tới `104.20.23.154:80`, packet 2 đi theo chiều ngược lại; MAC cũng đảo chiều tương ứng | đạt |
| 6 | không có payload, detector bỏ qua | `payload_len` bằng 0, không có `app_protocol` | đạt |
| 7 | parse không lỗi | `parse_status` là `OK`, `errors` rỗng ở cả 3 event | đạt |

Exit code = 0.

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc01_tcp_handshake/input.pcap --output TEST/tc01_tcp_handshake/events.jsonl --log-file TEST/tc01_tcp_handshake/run_log.txt
echo $?
Total packets: 3 (OK 3, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

## Testcase 02: TCP Data

#### Mục tiêu và bắt pcap

Bắt một pcap có ít nhất một TCP packet mang payload.

Terminal 1: 

```bash
sudo tcpdump -i lo -nn -Z $USER -w TEST/tc02_tcp_data/input.pcap 'tcp port 9000'
```

Terminal 2: 

```bash
nc -l 9000 > /dev/null &
echo "hello from tc02" | nc -N 127.0.0.1 9000
```

### **Chạy ids và output thu được:**

Output thu được: 

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc02_tcp_data/input.pcap --output TEST/tc02_tcp_data/events.jsonl --log-file TEST/tc02_tcp_data/run_log.txt
echo $?
Total packets: 8 (OK 8, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,src_port,dst_port,tcp_flags,seq,ack,window,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc02_tcp_data/events.jsonl
{"packet_id":1,"src_port":38788,"dst_port":9000,"tcp_flags":"SYN","seq":2521521838,"ack":0,"window":65495,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":2,"src_port":9000,"dst_port":38788,"tcp_flags":"SYN-ACK","seq":3986459269,"ack":2521521839,"window":65483,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":3,"src_port":38788,"dst_port":9000,"tcp_flags":"ACK","seq":2521521839,"ack":3986459270,"window":64,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":4,"src_port":38788,"dst_port":9000,"tcp_flags":"PSH-ACK","seq":2521521839,"ack":3986459270,"window":64,"payload_len":16,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":5,"src_port":9000,"dst_port":38788,"tcp_flags":"ACK","seq":3986459270,"ack":2521521855,"window":64,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":6,"src_port":38788,"dst_port":9000,"tcp_flags":"FIN-ACK","seq":2521521855,"ack":3986459270,"window":64,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":7,"src_port":9000,"dst_port":38788,"tcp_flags":"FIN-ACK","seq":3986459270,"ack":2521521856,"window":64,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":8,"src_port":38788,"dst_port":9000,"tcp_flags":"ACK","seq":2521521856,"ack":3986459271,"window":64,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
```

### tc02 đạt:

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 8`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | 8 event, khớp 8 packet trong `tcpdump` | đạt |
| 3 | nhận diện packet có payload | packet 4 có `tcp_flags` là `PSH-ACK`, `payload_len` là `16`, khớp `length 16` của `tcpdump` | đạt |
| 4 | seq và ack của packet data đúng | packet 4 có seq `2521521839` và ack `3986459270`, khớp `tcpdump`. Packet 5 ACK lại `2521521855`, bằng seq packet 4 cộng `payload_len` 16 | đạt |
| 5 | các field transport khác đúng | port `38788` đến `9000`, `window` là `64`, khớp giá trị `win 64` của `tcpdump` | đạt |
| 6 | packet không payload không bị gắn nhầm là data | các packet còn lại có `payload_len` là `0` và `app_protocol` là `null` | đạt |
| 7 | payload không thuộc giao thức hỗ trợ thì không bị gán nhầm | packet 4 có `app_protocol` là `UNKNOWN` và `detection_method` là `null`, vì payload là text thường và port 9000 không có trong bảng fallback | đạt |
| 8 | parse không lỗi | cả 8 event đều có `parse_status` là `OK` và `errors` rỗng | đạt |

## Testcase 03: UDP

### Mục tiêu và bắt pcap

Bắt một pcap có ít nhất 1 UDP packet mang payload

Terminal 1:

```bash
sudo tcpdump -i lo -nn -Z $USER -w TEST/tc03_udp/input.pcap 'udp port 9000'
```

Terminal 2: 

```bash
nc -u -l 9000 > /dev/null &
echo "hello from tc03" | nc -u -w1 127.0.0.1 9000
kill %1
```

### Chạy ids và output thu được

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc03_udp/input.pcap --output TEST/tc03_udp/events.jsonl --log-file TEST/tc03_udp/run_log.txt
echo $?
Total packets: 1 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,src_ip,dst_ip,ttl,ip_len,ip_id,ip_proto,ip_flags,src_port,dst_port,transport_protocol,seq,ack,tcp_flags,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc03_udp/events.jsonl
{"packet_id":1,"src_ip":"127.0.0.1","dst_ip":"127.0.0.1","ttl":64,"ip_len":44,"ip_id":12351,"ip_proto":17,"ip_flags":"DF","src_port":49774,"dst_port":9000,"transport_protocol":"UDP","seq":null,"ack":null,"tcp_flags":null,"payload_len":16,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
(btids) odixe@LapcuaTriet:~/ids$ 
```

### tc03 đạt

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 1`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | có 1 event, khớp với 1 packet trong `tcpdump` | đạt |
| 3 | nhận diện đúng giao thức UDP | `transport_protocol` là `UDP`, `ip_proto` là `17` | đạt |
| 4 | port đúng | `49774` đến `9000`, khớp `tcpdump` | đạt |
| 5 | payload đúng | `payload_len` là `16`, khớp `UDP, length 16` | đạt |
| 6 | các field IP đúng | `ttl` 64, `ip_len` 44, `ip_id` 12351, `ip_flags` DF đều khớp output `-v`. Ngoài ra 44 đúng bằng 20 + 8 + 16 | đạt |
| 7 | không điền nhầm field của TCP | `seq`, `ack`, `tcp_flags` đều là `null` | đạt |
| 8 | payload không thuộc giao thức hỗ trợ thì không bị gán nhầm, và parse không lỗi | `app_protocol` là `UNKNOWN`, `detection_method` là `null`; `parse_status` là `OK`, `errors` rỗng | đạt |

## Testcase 04: HTTP Get

### Mục tiêu và bắt pcap

Bắt 1 pcap có ít nhất một HTTP Get request.

Terminal 1:

```bash
sudo tcpdump -i eth0 -nn -Z $USER -w TEST/tc04_http_get/input.pcap 'tcp port 80 and host example.com'
```

Terminal 2: 

```bash
curl http://example.com/
```

### Chạy ids và output thu được:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc04_http_get/input.pcap --output TEST/tc04_http_get/events.jsonl --log-file TEST/tc04_http_get/run_log.txt
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem tổng quan 12 event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,tcp_flags,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc04_http_get/events.jsonl
{"packet_id":1,"tcp_flags":"SYN","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":2,"tcp_flags":"SYN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":3,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":4,"tcp_flags":"PSH-ACK","payload_len":74,"app_protocol":"HTTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":5,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":6,"tcp_flags":"PSH-ACK","payload_len":868,"app_protocol":"HTTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":7,"tcp_flags":"PSH-ACK","payload_len":5,"app_protocol":"HTTP","detection_method":"port","parse_status":"OK","errors":[]}
{"packet_id":8,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":9,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":10,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":11,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":12,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
```

Xem chi tiết packet GET:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq '{packet_id,src_ip,dst_ip,src_port,dst_port,payload_len,app_protocol,detection_method,app,parse_status,errors}' <(jq -c 'select(.packet_id==4)' TEST/tc04_http_get/events.jsonl)
{
  "packet_id": 4,
  "src_ip": "172.18.124.92",
  "dst_ip": "104.20.23.154",
  "src_port": 38454,
  "dst_port": 80,
  "payload_len": 74,
  "app_protocol": "HTTP",
  "detection_method": "payload",
  "app": {
    "message_type": "request",
    "method": "GET",
    "uri": "/",
    "version": "HTTP/1.1",
    "headers": {
      "host": "example.com",
      "user-agent": "curl/8.5.0",
      "accept": "*/*"
    },
    "body_len": 0
  },
  "parse_status": "OK",
  "errors": []
}
```

### tc04 đạt

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 12`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | có 12 event, khớp 12 packet của `tcpdump` | đạt |
| 3 | nhận diện HTTP bằng nội dung payload | packet 4 có `app_protocol` là `HTTP` và `detection_method` là `payload` | đạt |
| 4 | parse đúng request line | `method` là `GET`, `uri` là `/`, `version` là `HTTP/1.1`, khớp dòng `GET / HTTP/1.1` | đạt |
| 5 | parse đủ header | có 3 header `host`, `user-agent`, `accept`, giá trị khớp `tcpdump -A` | đạt |
| 6 | GET không có body | `body_len` là `0`, trong khi `payload_len` là `74`, đúng bằng độ dài phần header | đạt |
| 7 | phân biệt request và response | packet 6 được nhận là HTTP qua payload, và không bị gán nhầm là request. Nội dung chi tiết của packet này sẽ kiểm tra ở tc06 | đạt |
| 8 | packet không payload không bị gán app protocol | 9 packet có `payload_len` bằng 0 đều có `app_protocol` là `null` | đạt |
| 9 | parse không lỗi | cả 12 event đều có `parse_status` là `OK` và `errors` rỗng | đạt |

## Testcase 05: HTTP Post

### Mục tiêu và bắt pcap

bắt một pcap có ít nhất một HTTP POST request có body.

Terminal 1: 

```bash
sudo tcpdump -i eth0 -nn -Z $USER -w TEST/tc05_http_post/input.pcap 'tcp port 80 and host httpbin.org'
```

Terminal 2: 

```bash
curl -d 'user=tam&msg=hello' http://httpbin.org/post
```

### Chạy ids và output thu được:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc05_http_post/input.pcap --output TEST/tc05_http_post/events.jsonl --log-file TEST/tc05_http_post/run_log.txt
echo $?
Total packets: 10 (OK 10, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem tổng quan 10 event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,tcp_flags,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc05_http_post/events.jsonl
{"packet_id":1,"tcp_flags":"SYN","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":2,"tcp_flags":"SYN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":3,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":4,"tcp_flags":"PSH-ACK","payload_len":166,"app_protocol":"HTTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":5,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":6,"tcp_flags":"PSH-ACK","payload_len":677,"app_protocol":"HTTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":7,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":8,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":9,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":10,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
```

Xem chi tiết packet post:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq 'select(.packet_id==4) | {packet_id,src_ip,dst_ip,src_port,dst_port,payload_len,app_protocol,detection_method,app,parse_status,errors}' TEST/tc05_http_post/events.jsonl
{
  "packet_id": 4,
  "src_ip": "172.18.124.92",
  "dst_ip": "54.175.207.120",
  "src_port": 51944,
  "dst_port": 80,
  "payload_len": 166,
  "app_protocol": "HTTP",
  "detection_method": "payload",
  "app": {
    "message_type": "request",
    "method": "POST",
    "uri": "/post",
    "version": "HTTP/1.1",
    "headers": {
      "host": "httpbin.org",
      "user-agent": "curl/8.5.0",
      "accept": "*/*",
      "content-length": "18",
      "content-type": "application/x-www-form-urlencoded"
    },
    "body_len": 18
  },
  "parse_status": "OK",
  "errors": []
}
```

### tc05 đạt

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | exit code 0 | đạt |
| 2 | xử lý đủ số packet trong pcap | 10 event, khớp 10 packet của `tcpdump` | đạt |
| 3 | nhận diện HTTP bằng payload | packet 4 có `app_protocol` là `HTTP`, `detection_method` là `payload` | đạt |
| 4 | parse đúng request line | `method` là `POST`, `uri` là `/post`, `version` là `HTTP/1.1` | đạt |
| 5 | parse đủ header | đủ 5 header, gồm cả `content-length` và `content-type` của body | đạt |
| 6 | tách đúng body | `body_len` là `18`, khớp độ dài `user=tam&msg=hello` | đạt |
| 7 | body và header nhất quán | `body_len` 18 bằng header `content-length` 18. Phần header dài 166 − 18 = 148 byte, khớp `payload_len` | đạt |
| 8 | packet không payload không bị gán app protocol | 8 packet có `payload_len` bằng 0 đều có `app_protocol` là `null` | đạt |
| 9 | parse không lỗi | cả 10 event đều có `parse_status` là `OK` và `errors` rỗng | đạt |

## Testcase 06: HTTP Response

### Mục tiêu và bắt pcap

Bắt một pcap có ít nhất một HTTP Response, trong đó có status line và header. 

Terminal 1: 

```bash
sudo tcpdump -i eth0 -nn -Z $USER -w TEST/tc06_http_response/input.pcap 'tcp port 80 and host httpbin.org'
```

Terminal 2: 

```bash
curl -i http://httpbin.org/get
```

### **Chạy ids và output thu được**

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc06_http_response/input.pcap --output TEST/tc06_http_response/events.jsonl --log-file TEST/tc06_http_response/run_log.txt
echo $?
Total packets: 10 (OK 10, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem tổng quan 10 event: 

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,tcp_flags,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc06_http_response/events.jsonl
{"packet_id":1,"tcp_flags":"SYN","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":2,"tcp_flags":"SYN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":3,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":4,"tcp_flags":"PSH-ACK","payload_len":77,"app_protocol":"HTTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":5,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":6,"tcp_flags":"PSH-ACK","payload_len":484,"app_protocol":"HTTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":7,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":8,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":9,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":10,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
```

xem chi tiết packet response:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq 'select(.packet_id==6) | {packet_id,src_ip,dst_ip,src_port,dst_port,payload_len,app_protocol,detection_method,app,parse_status,errors}' TEST/tc06_http_response/events.jsonl
{
  "packet_id": 6,
  "src_ip": "44.219.150.215",
  "dst_ip": "172.18.124.92",
  "src_port": 80,
  "dst_port": 47064,
  "payload_len": 484,
  "app_protocol": "HTTP",
  "detection_method": "payload",
  "app": {
    "message_type": "response",
    "version": "HTTP/1.1",
    "status_code": 200,
    "reason": "OK",
    "headers": {
      "date": "Mon, 28 Sep 2026 14:20:52 GMT",
      "content-type": "application/json",
      "content-length": "254",
      "connection": "keep-alive",
      "server": "gunicorn/19.9.0",
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true"
    },
    "body_len": 254
  },
  "parse_status": "OK",
  "errors": []
}
```

### tc06 đạt:

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 10`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | có 10 event, khớp 10 packet của `tcpdump` | đạt |
| 3 | nhận diện HTTP bằng payload | packet 6 có `app_protocol` là `HTTP`, `detection_method` là `payload` | đạt |
| 4 | phân biệt response với request | packet 6 có `message_type` là `response`, packet 4 được nhận là request | đạt |
| 5 | parse đúng status code | `status_code` là `200`, kiểu số nguyên | đạt |
| 6 | parse đúng status line | `version` là `HTTP/1.1`, `reason` là `OK`, khớp dòng `HTTP/1.1 200 OK` | đạt |
| 7 | parse đủ header | đủ 7 header, giá trị khớp `tcpdump -A` | đạt |
| 8 | body và header nhất quán | `body_len` 254 bằng header `content-length` 254, và 484 − 254 = 230 byte header | đạt |
| 9 | chiều gói tin đúng | nguồn là server, port nguồn `80`, ngược chiều với request | đạt |
| 10 | parse không lỗi | cả 10 event có `parse_status` là `OK`, `errors` rỗng | đạt |

## Testcase 07: DNS Query

### Mục tiêu và bắt pcap

Terminal 1

```bash
sudo tcpdump -i eth0 -nn -c 1 -Z $USER -w TEST/tc07_dns_query/input.pcap 'udp dst port 53 and host 8.8.8.8'
```

Terminal 2

```bash
dig @8.8.8.8 example.com A
```

Xem gói tin: 

```bash
(btids) odixe@LapcuaTriet:~/ids$ tcpdump -nn -v -r TEST/tc07_dns_query/input.pcap
reading from file TEST/tc07_dns_query/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:35:26.708668 IP (tos 0x0, ttl 64, id 52359, offset 0, flags [none], proto UDP (17), length 80)
    172.18.124.92.58549 > 8.8.8.8.53: 59234+ [1au] A? example.com. (52)
```

Pcap đạt yêu cầu. Nó có đúng 1 packet UDP, đi từ `172.18.124.92.58549` tới `8.8.8.8.53`. Dòng giải mã DNS `59234+ [1au] A? example.com. (52)` đọc như sau:

| phần | ý nghĩa | field tương ứng trong IDS |
| --- | --- | --- |
| `59234` | transaction id | `transaction_id` |
| `+` | cờ RD được bật, tức client yêu cầu server truy vấn đệ quy | `flags` |
| `[1au]` | có 1 bản ghi trong additional section. Đây là bản ghi OPT của EDNS mà `dig` tự thêm vào | `arcount` |
| `A?` | loại query là `A`, và dấu `?` cho biết đây là query | `qtype`, `qtype_name`, `message_type` |
| `example.com.` | tên miền được hỏi | `name` |
| `(52)` | payload DNS dài 52 byte | `payload_len` |

### Chạy ids:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc07_dns_query/input.pcap --output TEST/tc07_dns_query/events.jsonl --log-file TEST/tc07_dns_query/run_log.txt
echo $?
Total packets: 1 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem chi tiết event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq '{packet_id,src_ip,dst_ip,ip_len,ip_id,ip_flags,src_port,dst_port,transport_protocol,payload_len,app_protocol,detection_method,app,parse_status,errors}' TEST/tc07_dns_query/events.jsonl
{
  "packet_id": 1,
  "src_ip": "172.18.124.92",
  "dst_ip": "8.8.8.8",
  "ip_len": 80,
  "ip_id": 52359,
  "ip_flags": "",
  "src_port": 58549,
  "dst_port": 53,
  "transport_protocol": "UDP",
  "payload_len": 52,
  "app_protocol": "DNS",
  "detection_method": "payload",
  "app": {
    "transaction_id": 59234,
    "message_type": "query",
    "opcode": 0,
    "rcode": 0,
    "flags": "RD",
    "qdcount": 1,
    "ancount": 0,
    "nscount": 0,
    "arcount": 1,
    "questions": [
      {
        "name": "example.com",
        "qtype": 1,
        "qclass": 1,
        "qtype_name": "A"
      }
    ],
    "answers": []
  },
  "parse_status": "OK",
  "errors": []
}
```

### tc07 đạt:

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 1`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | có 1 event, khớp với 1 packet của `tcpdump` | đạt |
| 3 | nhận diện DNS bằng payload | `app_protocol` là `DNS`, `detection_method` là `payload` | đạt |
| 4 | parse đúng domain | `name` là `example.com`, khớp với `example.com.` của `tcpdump` | đạt |
| 5 | parse đúng query type | `qtype` là `1`, `qtype_name` là `A`, khớp với `A?` | đạt |
| 6 | phân biệt được query | `message_type` là `query`, `ancount` là `0`, `answers` rỗng | đạt |
| 7 | parse đúng DNS header | `transaction_id` 59234, `flags` RD, `arcount` 1 đều khớp với `59234+ [1au]` | đạt |
| 8 | các field IP và UDP đúng | `ip_len` 80, `ip_id` 52359, `ip_flags` rỗng, port 58549 → 53, `payload_len` 52 đều khớp với `tcpdump` | đạt |
| 9 | tầng transport đúng | `transport_protocol` là `UDP` | đạt |
| 10 | parse không lỗi | `parse_status` là `OK`, `errors` rỗng | đạt |

Lưu ý: 

- `name` không có dấu chấm cuối. Trong khi đó `tcpdump` in `example.com.` với dấu chấm của root zone. Hai cách viết trỏ tới cùng một tên miền, parser chọn bỏ dấu chấm cho dễ so sánh chuỗi.
- `arcount` là 1 nhưng event không có danh sách additional. Bản ghi đó là OPT của EDNS do `dig` thêm vào. Parser được thiết kế chỉ đọc question và answer, bỏ qua authority và additional.
- `ip_flags` là chuỗi rỗng, không phải `null`. Chuỗi rỗng nghĩa là header có tồn tại nhưng không bật cờ nào, khớp với `flags [none]` của `tcpdump`. Còn `null` sẽ có nghĩa là IDS không đọc được IP header.

## Testcase 08: DNS Response

### Mục tiêu và bắt pcap

Bắt một pcap chỉ chứa đúng 1 DNS response, trong đó có ít nhất 1 answer, trả lời cho query bản ghi `A` của `example.com`.

Terminal 1:

```bash
sudo tcpdump -i eth0 -nn -c 1 -Z $USER -w TEST/tc08_dns_response/input.pcap 'udp src port 53 and host 8.8.8.8
```

Terminal 2:

```bash
dig @8.8.8.8 example.com A
```

### Chạy ids:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc08_dns_response/input.pcap --output TEST/tc08_dns_response/events.jsonl --log-file TEST/tc08_dns_response/run_log.txt
echo $?
Total packets: 1 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem chi tiết event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq '{packet_id,src_ip,dst_ip,ip_len,src_port,dst_port,transport_protocol,payload_len,app_protocol,detection_method,app,parse_status,errors}' TEST/tc08_dns_response/events.jsonl
{
  "packet_id": 1,
  "src_ip": "8.8.8.8",
  "dst_ip": "172.18.124.92",
  "ip_len": 100,
  "src_port": 53,
  "dst_port": 46957,
  "transport_protocol": "UDP",
  "payload_len": 72,
  "app_protocol": "DNS",
  "detection_method": "payload",
  "app": {
    "transaction_id": 45230,
    "message_type": "response",
    "opcode": 0,
    "rcode": 0,
    "flags": "RD-RA",
    "qdcount": 1,
    "ancount": 2,
    "nscount": 0,
    "arcount": 1,
    "questions": [
      {
        "name": "example.com",
        "qtype": 1,
        "qclass": 1,
        "qtype_name": "A"
      }
    ],
    "answers": [
      {
        "name": "example.com",
        "type": 1,
        "class": 1,
        "ttl": 300,
        "type_name": "A",
        "rdata": "172.66.147.243"
      },
      {
        "name": "example.com",
        "type": 1,
        "class": 1,
        "ttl": 300,
        "type_name": "A",
        "rdata": "104.20.23.154"
      }
    ]
  },
  "parse_status": "OK",
  "errors": []
}
```

### tc08 đạt

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 1`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | 1 event, khớp 1 packet | đạt |
| 3 | nhận diện DNS bằng payload | `app_protocol` là `DNS`, `detection_method` là `payload` | đạt |
| 4 | phân biệt được response | `message_type` là `response`, gói tin đi ra từ port `53` | đạt |
| 5 | parse ít nhất một answer | có 2 answer, khớp `ANSWER: 2` của `dig` | đạt |
| 6 | nội dung answer đúng | cả 2 answer có `name` là `example.com`, `type_name` là `A`, `class` là `1`, tức IN, `ttl` là `300`. `rdata` lần lượt là `172.66.147.243` và `104.20.23.154`. Tất cả khớp `ANSWER SECTION` của `dig` theo đúng thứ tự | đạt |
| 7 | parse đúng DNS header | `transaction_id` 45230 khớp `id: 45230`; `opcode` 0 và `rcode` 0 khớp `QUERY, NOERROR`; các giá trị count 1/2/0/1 khớp `dig` | đạt |
| 8 | question được chép lại đúng | `example.com`, `A`, khớp `QUESTION SECTION` | đạt |
| 9 | kích thước payload đúng | `payload_len` 72 khớp `MSG SIZE rcvd: 72` | đạt |
| 10 | parse không lỗi | `parse_status` là `OK`, `errors` rỗng | đạt |

## Testcase 09: SMTP Command

### Mục tiêu và bắt pcap

**mục tiêu:** bắt một pcap chỉ chứa các packet đi từ client tới SMTP server, trong đó có đủ 3 lệnh `EHLO`, `MAIL FROM`, `RCPT TO`.

Terminal 1:

```bash
sudo $(which python) -m aiosmtpd -n -l 127.0.0.1:25
```

Terminal 2:

```bash
sudo tcpdump -i lo -nn -Z $USER -w TEST/tc09_smtp_command/input.pcap 'tcp dst port 25'
```

Terminal 3: 

```bash
python -c "import smtplib; s=smtplib.SMTP('127.0.0.1',25); s.ehlo(); s.sendmail('alice@test.local',['bob@test.local'],'Subject: tc09\r\n\r\nhello'); s.quit()"
```

### Chạy ids và thu được:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc09_smtp_command/input.pcap --output TEST/tc09_smtp_command/events.jsonl --log-file TEST/tc09_smtp_command/run_log.txt
echo $?
Total packets: 11 (OK 11, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem tổng quan 11 event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc09_smtp_command/input.pcap --output TEST/tc09_smtp_command/events.jsonl --log-file TEST/tc09_smtp_command/run_log.txt
echo $?
Total packets: 11 (OK 11, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,tcp_flags,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc09_smtp_command/events.jsonl
{"packet_id":1,"tcp_flags":"SYN","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":2,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":3,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":4,"tcp_flags":"PSH-ACK","payload_len":30,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":5,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":6,"tcp_flags":"PSH-ACK","payload_len":30,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":7,"tcp_flags":"PSH-ACK","payload_len":26,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":8,"tcp_flags":"PSH-ACK","payload_len":6,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":9,"tcp_flags":"PSH-ACK","payload_len":27,"app_protocol":"SMTP","detection_method":"port","parse_status":"OK","errors":[]}
{"packet_id":10,"tcp_flags":"PSH-ACK","payload_len":6,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":11,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]
```

Xem chi tiết các packet có payload: 

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c 'select(.payload_len > 0) | {packet_id,src_port,dst_port,payload_len,app_protocol,detection_method,app,parse_status,errors}' TEST/tc09_smtp_command/events.jsonl
{"packet_id":4,"src_port":37668,"dst_port":25,"payload_len":30,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"command","commands":[{"verb":"EHLO","argument":"LapcuaTriet.localdomain"}]},"parse_status":"OK","errors":[]}
{"packet_id":6,"src_port":37668,"dst_port":25,"payload_len":30,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"command","commands":[{"verb":"MAIL","argument":"FROM:<alice@test.local>","address":"alice@test.local"}]},"parse_status":"OK","errors":[]}
{"packet_id":7,"src_port":37668,"dst_port":25,"payload_len":26,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"command","commands":[{"verb":"RCPT","argument":"TO:<bob@test.local>","address":"bob@test.local"}]},"parse_status":"OK","errors":[]}
{"packet_id":8,"src_port":37668,"dst_port":25,"payload_len":6,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"command","commands":[{"verb":"DATA","argument":""}]},"parse_status":"OK","errors":[]}
{"packet_id":9,"src_port":37668,"dst_port":25,"payload_len":27,"app_protocol":"SMTP","detection_method":"port","app":{"message_type":"data","data_len":27},"parse_status":"OK","errors":[]}
{"packet_id":10,"src_port":37668,"dst_port":25,"payload_len":6,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"command","commands":[{"verb":"QUIT","argument":""}]},"parse_status":"OK","errors":[]}
```

### tc09 đạt

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 11`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | 11 event, khớp 11 packet của `tcpdump` | đạt |
| 3 | nhận diện SMTP bằng payload | các packet 4, 6, 7, 8, 10 đều có `app_protocol` là `SMTP`, `detection_method` là `payload` | đạt |
| 4 | parse được EHLO | packet 4 có `verb` là `EHLO`, `argument` là `LapcuaTriet.localdomain` | đạt |
| 5 | parse được MAIL FROM | packet 6 có `verb` là `MAIL`, `address` là `alice@test.local` | đạt |
| 6 | parse được RCPT TO | packet 7 có `verb` là `RCPT`, `address` là `bob@test.local` | đạt |
| 7 | nhận diện đúng loại message | các lệnh có `message_type` là `command`. Nội dung thư ở packet 9 có `message_type` là `data`, `data_len` là 27, và không bị parse nhầm thành lệnh | đạt |
| 8 | fallback theo port hoạt động | packet 9 không bắt đầu bằng lệnh SMTP nào, nhưng vẫn được nhận là SMTP với `detection_method` là `port` | đạt |
| 9 | packet không có payload thì không bị gán app protocol | 5 packet có `payload_len` 0 đều có `app_protocol` là `null` | đạt |
| 10 | parse không lỗi | cả 11 event đều có `parse_status` là `OK`, `errors` rỗng | đạt |

## Testcase 10: SMTP Response

### Mục tiêu và bắt pcap

Bắt một pcap chỉ chứa các packet đi từ SMTP server về client, trong đó có các response với nhiều status code khác nhau.

Yêu cầu với pcap:

- chỉ lấy chiều server → client.
- đúng 1 phiên SMTP. Một phiên đầy đủ sẽ sinh ra nhiều loại code khác nhau:

| code | ý nghĩa |
| --- | --- |
| 220 | lời chào |
| 250 | chấp nhận lệnh |
| 354 | chờ nội dung thư |
| 221 | đóng kết nối |

Response của `EHLO` còn có nhiều dòng `250-...`. Điều này giúp kiểm tra cách parser xử lý response nhiều dòng.

Terminal 1 như testcase 09.

Terminal 2: 

```bash
sudo tcpdump -i lo -nn -Z $USER -w TEST/tc10_smtp_response/input.pcap 'tcp src port 25'
```

Terminal 3:

```bash
python -c "import smtplib; s=smtplib.SMTP('127.0.0.1',25); s.ehlo(); s.sendmail('alice@test.local',['bob@test.local'],'Subject: tc10\r\n\r\nhello'); s.quit()"
```

Pcap đạt yêu cầu:

- đúng 1 phiên, đúng chiều: chỉ có port client `57210`, gồm 13 packet, tất cả đều đi ra từ port 25.
- có 9 packet mang response, đủ 4 loại code:

| packet | nội dung | code |
| --- | --- | --- |
| 2 | `220 LapcuaTriet.localdomain Python SMTP 1.4.6` | 220, lời chào |
| 4, 5, 6 | `250-LapcuaTriet.localdomain`, `250-8BITMIME`, `250 HELP` | 250, trả lời `EHLO`, gồm nhiều dòng |
| 7, 8 | `250 OK` | 250, chấp nhận `MAIL` và `RCPT` |
| 9 | `354 End data with <CR><LF>.<CR><LF>` | 354, chờ nội dung |
| 10 | `250 OK` | 250, đã nhận thư |
| 11 | `221 Bye` | 221, đóng kết nối |

### Chạy ids và lấy output

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc10_smtp_response/input.pcap --output TEST/tc10_smtp_response/events.jsonl --log-file TEST/tc10_smtp_response/run_log.txt
echo $?
Total packets: 13 (OK 13, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
0
```

Xem tổng quan 13 event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,tcp_flags,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc10_smtp_response/events.jsonl
{"packet_id":1,"tcp_flags":"SYN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":2,"tcp_flags":"PSH-ACK","payload_len":47,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":3,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":4,"tcp_flags":"PSH-ACK","payload_len":29,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":5,"tcp_flags":"PSH-ACK","payload_len":14,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":6,"tcp_flags":"PSH-ACK","payload_len":10,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":7,"tcp_flags":"PSH-ACK","payload_len":8,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":8,"tcp_flags":"PSH-ACK","payload_len":8,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":9,"tcp_flags":"PSH-ACK","payload_len":37,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":10,"tcp_flags":"PSH-ACK","payload_len":8,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":11,"tcp_flags":"PSH-ACK","payload_len":9,"app_protocol":"SMTP","detection_method":"payload","parse_status":"OK","errors":[]}
{"packet_id":12,"tcp_flags":"FIN-ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":13,"tcp_flags":"ACK","payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
```

Xem chi tiết các packet có payload

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c 'select(.payload_len > 0) | {packet_id,src_port,dst_port,payload_len,app_protocol,detection_method,app,parse_status,errors}' TEST/tc10_smtp_response/events.jsonl
{"packet_id":2,"src_port":25,"dst_port":57210,"payload_len":47,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":220,"messages":["LapcuaTriet.localdomain Python SMTP 1.4.6"],"final":true},"parse_status":"OK","errors":[]}
{"packet_id":4,"src_port":25,"dst_port":57210,"payload_len":29,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":250,"messages":["LapcuaTriet.localdomain"],"final":false},"parse_status":"OK","errors":[]}
{"packet_id":5,"src_port":25,"dst_port":57210,"payload_len":14,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":250,"messages":["8BITMIME"],"final":false},"parse_status":"OK","errors":[]}
{"packet_id":6,"src_port":25,"dst_port":57210,"payload_len":10,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":250,"messages":["HELP"],"final":true},"parse_status":"OK","errors":[]}
{"packet_id":7,"src_port":25,"dst_port":57210,"payload_len":8,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":250,"messages":["OK"],"final":true},"parse_status":"OK","errors":[]}
{"packet_id":8,"src_port":25,"dst_port":57210,"payload_len":8,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":250,"messages":["OK"],"final":true},"parse_status":"OK","errors":[]}
{"packet_id":9,"src_port":25,"dst_port":57210,"payload_len":37,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":354,"messages":["End data with <CR><LF>.<CR><LF>"],"final":true},"parse_status":"OK","errors":[]}
{"packet_id":10,"src_port":25,"dst_port":57210,"payload_len":8,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":250,"messages":["OK"],"final":true},"parse_status":"OK","errors":[]}
{"packet_id":11,"src_port":25,"dst_port":57210,"payload_len":9,"app_protocol":"SMTP","detection_method":"payload","app":{"message_type":"response","code":221,"messages":["Bye"],"final":true},"parse_status":"OK","errors":[]}
```

### tc10

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình chạy hết, không crash | `Total packets: 13`, exit code `0` | đạt |
| 2 | xử lý đủ số packet trong pcap | 13 event, khớp 13 packet của `tcpdump` | đạt |
| 3 | nhận diện SMTP bằng payload | cả 9 packet response đều có `app_protocol` là `SMTP` và `detection_method` là `payload` | đạt |
| 4 | phân biệt response với command | cả 9 packet đều có `message_type` là `response` | đạt |
| 5 | parse đúng status code | `code` lần lượt là 220, 250, 250, 250, 250, 250, 354, 250, 221, khớp thứ tự `tcpdump` | đạt |
| 6 | status code có kiểu số nguyên | `code` là `220`, không phải `"220"` | đạt |
| 7 | parse đúng message | message đã bỏ phần code và dấu phân cách, ví dụ `"Bye"` và `"LapcuaTriet.localdomain Python SMTP 1.4.6"` | đạt |
| 8 | xử lý đúng response nhiều dòng | packet 4 và 5 là dòng `250-` nên có `final` là `false`, packet 6 là dòng `250`  nên có `final` là `true` | đạt |
| 9 | giữ nguyên text đặc biệt trong message | packet 9 vẫn giữ nguyên chuỗi `<CR><LF>.<CR><LF>` dưới dạng chữ | đạt |
| 10 | packet không payload không bị gán app protocol, và không có lỗi | 4 packet có `payload_len` 0 đều có `app_protocol` là `null`. Cả 13 event có `parse_status` là `OK`, `errors` rỗng |  |

## Testcase 11: Unknown protocol

### Mục tiêu và bắt pcap

bắt một pcap chứa các packet thuộc giao thức mà IDS không hỗ trợ, trải trên 3 tầng. Mục đích là chứng minh chương trình không crash, ở tầng nào gặp giao thức lạ thì IDS dừng parse ở đúng tầng đó, rồi xử lý tiếp packet sau.

**yêu cầu với pcap:** cần đủ 3 loại packet, mỗi loại ứng với một tầng:

| tầng không hỗ trợ | giao thức dùng để test | lý do chọn |
| --- | --- | --- |
| network | ARP | không phải IPv4, nên pipeline dừng ngay sau tầng link |
| transport | ICMP | là IPv4 nhưng không phải TCP hay UDP, nên pipeline dừng sau tầng network |
| application | TLS, tức HTTPS port 443 | là TCP bình thường nhưng payload đã mã hóa, không phải HTTP, DNS hay SMTP, và port 443 cũng không có trong bảng fallback |

Terminal 1:

```bash
sudo tcpdump -i eth0 -nn -Z $USER -w TEST/tc11_unknown_protocol/input.pcap 'arp or icmp or (tcp port 443 and host example.com)'
```

Terminal 2:

```bash
sudo ip neigh flush dev eth0
ping -c 2 8.8.8.8
curl -s -o /dev/null https://example.com
```

Pcap đạt yêu cầu. Nó có 30 packet, đủ cả 3 tầng cần test:

| packet | giao thức | số lượng | tầng không hỗ trợ |
| --- | --- | --- | --- |
| 1 đến 2 | ARP request và reply cho gateway `172.18.112.1` | 2 | network |
| 3 đến 6 | ICMP echo request và reply tới `8.8.8.8` | 4 | transport |
| 7 đến 30 | một kết nối TCP tới port 443, có 12 packet mang payload TLS | 24 | application |

### Chạy ids và output thu được

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc11_unknown_protocol/input.pcap --output TEST/tc11_unknown_protocol/events.jsonl --log-file TEST/tc11_unknown_protocol/run_log.txt
echo $?
Total packets: 30 (OK 24, PARTIAL 0, UNKNOWN 6, MALFORMED 0)
0
```

Xem tổng quan 30 event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,src_ip,dst_ip,ip_proto,transport_protocol,dst_port,payload_len,app_protocol,detection_method,parse_status,errors}' TEST/tc11_unknown_protocol/events.jsonl
{"packet_id":1,"src_ip":null,"dst_ip":null,"ip_proto":null,"transport_protocol":null,"dst_port":null,"payload_len":null,"app_protocol":null,"detection_method":null,"parse_status":"UNKNOWN","errors":[]}
{"packet_id":2,"src_ip":null,"dst_ip":null,"ip_proto":null,"transport_protocol":null,"dst_port":null,"payload_len":null,"app_protocol":null,"detection_method":null,"parse_status":"UNKNOWN","errors":[]}
{"packet_id":3,"src_ip":"172.18.124.92","dst_ip":"8.8.8.8","ip_proto":1,"transport_protocol":null,"dst_port":null,"payload_len":null,"app_protocol":null,"detection_method":null,"parse_status":"UNKNOWN","errors":[]}
{"packet_id":4,"src_ip":"8.8.8.8","dst_ip":"172.18.124.92","ip_proto":1,"transport_protocol":null,"dst_port":null,"payload_len":null,"app_protocol":null,"detection_method":null,"parse_status":"UNKNOWN","errors":[]}
{"packet_id":5,"src_ip":"172.18.124.92","dst_ip":"8.8.8.8","ip_proto":1,"transport_protocol":null,"dst_port":null,"payload_len":null,"app_protocol":null,"detection_method":null,"parse_status":"UNKNOWN","errors":[]}
{"packet_id":6,"src_ip":"8.8.8.8","dst_ip":"172.18.124.92","ip_proto":1,"transport_protocol":null,"dst_port":null,"payload_len":null,"app_protocol":null,"detection_method":null,"parse_status":"UNKNOWN","errors":[]}
{"packet_id":7,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":8,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":9,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":10,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":517,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":11,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":12,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":2856,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":13,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":1133,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":14,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":15,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":16,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":80,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":17,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":86,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":18,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":59,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":19,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":20,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":553,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":21,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":31,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":22,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":159,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":23,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":590,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":24,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":31,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":25,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":26,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":24,"app_protocol":"UNKNOWN","detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":27,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":28,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":29,"src_ip":"172.66.147.243","dst_ip":"172.18.124.92","ip_proto":6,"transport_protocol":"TCP","dst_port":33974,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
{"packet_id":30,"src_ip":"172.18.124.92","dst_ip":"172.66.147.243","ip_proto":6,"transport_protocol":"TCP","dst_port":443,"payload_len":0,"app_protocol":null,"detection_method":null,"parse_status":"OK","errors":[]}
```

**xem đầy đủ event ARP đầu tiên,** để biết IDS giữ lại những field nào khi dừng ở tầng link:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq 'select(.packet_id==1)' TEST/tc11_unknown_protocol/events.jsonl
{
  "packet_id": 1,
  "timestamp": 1790607659.175576,
  "source": "TEST/tc11_unknown_protocol/input.pcap",
  "source_type": "pcap",
  "src_mac": "00:15:5d:4b:41:59",
  "dst_mac": "ff:ff:ff:ff:ff:ff",
  "parse_status": "UNKNOWN",
  "errors": []
}
```

### tc11

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình không crash | exit code `0`, có dòng summary ở cuối | đạt |
| 2 | xử lý hết mọi packet, không bỏ sót | `Total packets: 30`, đủ 30 event, khớp 30 packet của `tcpdump` | đạt |
| 3 | thống kê status đúng như dự đoán | `OK 24, UNKNOWN 6` | đạt |
| 4 | ARP dừng ở tầng link | packet 1 và 2 chỉ có field metadata và MAC, không có field IP; `parse_status` là `UNKNOWN` | đạt |
| 5 | ICMP dừng ở tầng network | packet 3 đến 6 có `src_ip`, `dst_ip`, `ip_proto` là `1`, tức ICMP. Không có `transport_protocol`, `parse_status` là `UNKNOWN` | đạt |
| 6 | TLS parse được tầng transport nhưng không nhận ra app | 12 packet có payload đều có `app_protocol` là `UNKNOWN` và `detection_method` là `null`, `parse_status` là `OK` | đạt |
| 7 | không gán nhầm HTTP cho packet TLS | không packet nào tới port 443 bị gán HTTP. Payload TLS không khớp rule nào, và 443 không có trong bảng fallback | đạt |
| 8 | dữ liệu các tầng dưới vẫn được giữ | ARP còn giữ MAC; ICMP còn giữ IP; packet 1 có `dst_mac` là `ff:ff:ff:ff:ff:ff`, khớp với ARP request gửi broadcast | đạt |
| 9 | gặp giao thức lạ không bị tính là lỗi | cả 30 event đều có `errors` rỗng, `MALFORMED 0` | đạt |
| 10 | packet sau không bị ảnh hưởng bởi packet trước | sau 6 packet `UNKNOWN`, các packet TCP từ số 7 trở đi vẫn parse đầy đủ | đạt |

## Testcase 12: Malformed packet

### Mục tiêu và bắt pcap

Tạo một pcap chứa các packet hỏng ở nhiều tầng khác nhau, xen với một packet hợp lệ. Test phải chứng minh 3 điều:

- Chương trình không crash.
- Mỗi packet hỏng được đánh dấu `MALFORMED` và có lỗi ghi rõ trong `errors`.
- Packet hợp lệ phía sau vẫn được parse bình thường.

Loại traffic này không thể bắt từ mạng thật, vì kernel không gửi packet hỏng đi.

Ta sẽ tạo script gen_malformed.py để tạo ra file pcap phù hợp.

| # | lỗi đã định | cảnh báo của `tcpdump` |
| --- | --- | --- |
| 1 | frame ngắn hơn Ethernet header | `[ |
| 2 | IPv4 header bị cắt | `IP [ |
| 3 | `ihl` sai | `bad-hlen 12` |
| 4 | `ip_len` sai | `truncated-ip - 960 bytes missing!`, `length 1000` |
| 5 | TCP header bị cắt | `truncated-ip - 12 bytes missing!` kèm `[ |
| 6 | `dataofs` sai | `bad hdr length 8 - too short, < 20` |
| 7 | packet hợp lệ | parse đầy đủ, `cksum 0x1593 (correct)` |

### Chạy ids và output:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap TEST/tc12_malformed_packet/input.pcap --output TEST/tc12_malformed_packet/events.jsonl --log-file TEST/tc12_malformed_packet/run_log.txt
echo $?
Total packets: 7 (OK 1, PARTIAL 0, UNKNOWN 0, MALFORMED 6)
0
```

Xem các field cần đối chiếu:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id,src_ip,ip_len,transport_protocol,app_protocol,parse_status,errors}' TEST/tc12_malformed_packet/events.jsonl
{"packet_id":1,"src_ip":null,"ip_len":null,"transport_protocol":null,"app_protocol":null,"parse_status":"MALFORMED","errors":["frame: cannot decode the link layer: frame is 10 bytes"]}
{"packet_id":2,"src_ip":null,"ip_len":null,"transport_protocol":null,"app_protocol":null,"parse_status":"MALFORMED","errors":["ipv4: EtherType is IPv4 but the IPv4 header is missing or shorter than 20 bytes"]}
{"packet_id":3,"src_ip":"10.0.0.1","ip_len":40,"transport_protocol":null,"app_protocol":null,"parse_status":"MALFORMED","errors":["ipv4: invalid ihl: header is 12 bytes, captured 40","tcp: ip_proto is TCP but the TCP header is missing or shorter than 20 bytes"]}
{"packet_id":4,"src_ip":"10.0.0.1","ip_len":1000,"transport_protocol":"TCP","app_protocol":null,"parse_status":"MALFORMED","errors":["ipv4: ip_len 1000 exceeds the 40 bytes captured"]}
{"packet_id":5,"src_ip":"10.0.0.1","ip_len":40,"transport_protocol":null,"app_protocol":null,"parse_status":"MALFORMED","errors":["ipv4: ip_len 40 exceeds the 28 bytes captured","tcp: ip_proto is TCP but the TCP header is missing or shorter than 20 bytes"]}
{"packet_id":6,"src_ip":"10.0.0.1","ip_len":40,"transport_protocol":"TCP","app_protocol":null,"parse_status":"MALFORMED","errors":["tcp: invalid dataofs: header is 8 bytes, captured 20"]}
{"packet_id":7,"src_ip":"10.0.0.1","ip_len":70,"transport_protocol":"TCP","app_protocol":"HTTP","parse_status":"OK","errors":[]}
```

### tc12 đạt

| # | tiêu chí | kết quả | đánh giá |
| --- | --- | --- | --- |
| 1 | chương trình không crash | exit code `0`, có dòng summary | đạt |
| 2 | xử lý hết mọi packet | `Total packets: 7`, đủ 7 event | đạt |
| 3 | thống kê status đúng | `OK 1, MALFORMED 6` | đạt |
| 4 | lỗi tầng link được phát hiện | packet 1: `frame is 10 bytes` | đạt |
| 5 | lỗi tầng network được phát hiện | packet 2 báo header thiếu, packet 3 báo `invalid ihl`, packet 4 báo `ip_len 1000 exceeds` | đạt |
| 6 | lỗi tầng transport được phát hiện | packet 5 báo TCP header thiếu, packet 6 báo `invalid dataofs` | đạt |
| 7 | lỗi được ghi cụ thể | mỗi lỗi có tên parser đứng đầu, ví dụ `ipv4:`, `tcp:`, `frame:`, kèm con số thực tế, nên đọc là biết hỏng ở tầng nào và hỏng thế nào | đạt |
| 8 | lỗi dây chuyền được ghi đủ | packet 3 và 5 đều có 2 lỗi, đúng như dự đoán | đạt |
| 9 | giữ lại phần đọc được | packet 3 đến 6 vẫn có `src_ip` và `ip_len`. Packet 4 và 6 vẫn có `transport_protocol` là `TCP` | đạt |
| 10 | packet hợp lệ phía sau không bị ảnh hưởng | packet 7 có `parse_status` là `OK`, `app_protocol` là `HTTP`, `errors` rỗng | đạt |
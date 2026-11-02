# TESTCASE BÀI 3: CORE ENGINE

Mỗi testcase nằm trong một thư mục riêng gồm bộ rule `test.rules`, file `config.yaml` chỉ nạp bộ rule đó, input (pcap hoặc script dựng event) và các file output. Lệnh chạy từ thư mục gốc project.

- `config.yaml` của từng testcase chỉ ghi nhóm `detection.rule_files`, các key còn lại lấy giá trị mặc định.
- `detections.jsonl` là file Detection Event, mỗi dòng một rule khớp một event.
- Dòng `Detection:` cuối lượt chạy là thống kê của Evaluation Engine; `Rules loaded` và `Matches by sid` nằm trong `run_log.txt`.
- Các pcap được bắt trên `lo` với `python -m http.server`. Server trả dòng trạng thái `HTTP/1.0` và đóng kết nối sau mỗi response; request tới path không tồn tại trả `404 File not found`, nên mỗi pcap là đúng 1 kết nối 12 packet.

## T01: Nạp file rule có comment và dòng trống

### Mục tiêu

1. Dòng trống, dòng chỉ có khoảng trắng, comment thụt đầu dòng và rule bị comment không được đưa sang parser.
2. Chỉ 3 rule hợp lệ được nạp, `line_no` đúng số dòng thật trong file.
3. Lượt nạp không có warning hay error, tổng kết `valid=3 invalid=0 unsupported=0`.
4. Rule nạp được dùng được thật: có Detection Event ở packet SYN, GET và response.
5. Chương trình thoát mã 0.

### Bộ rule

`test.rules` xen 3 rule hợp lệ với dòng trống (dòng 3, 9), dòng chỉ có khoảng trắng (dòng 5), comment thụt đầu dòng (dòng 6) và một rule đầy đủ bị comment với sid `1999999` (dòng 8).

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t01_load_rules
cat $D/test.rules
# T01: nạp file có rule hợp lệ xen giữa dòng trống, dòng chỉ có khoảng trắng, comment thụt đầu dòng
# và một rule bị comment; chỉ 3 rule hợp lệ được đưa sang parser

alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:"T01 SYN to port 8000"; flags:S; flow:to_server,not_established; sid:3010001; rev:1;)
    
    # comment thụt đầu dòng, không phải rule
alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:"T01 GET to port 8000"; flow:to_server,established; content:"GET "; offset:0; depth:4; sid:3010002; rev:1;)
# alert tcp any any -> any any (msg:"T01 commented out rule"; sid:1999999; rev:1;)

alert tcp 127.0.0.1 8000 -> 127.0.0.1 any (msg:"T01 response from port 8000"; flow:to_client,established; content:"HTTP/1.0"; offset:0; depth:8; sid:3010003; rev:1;)
```

`cat -A` cho thấy dòng 5 chỉ gồm khoảng trắng, `$` đánh dấu cuối dòng:

```bash
(btids) odixe@LapcuaTriet:~/ids$ sed -n 5p $D/test.rules | cat -A
    $
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t01_load_rules
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/t01
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t01_load_rules
tcpdump -nn -r $D/input.pcap
reading from file TEST/requirements3/t01_load_rules/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
20:01:35.886645 IP 127.0.0.1.51620 > 127.0.0.1.8000: Flags [S], seq 2219367903, win 65495, options [mss 65495,sackOK,TS val 1725291729 ecr 0,nop,wscale 10], length 0
20:01:35.886673 IP 127.0.0.1.8000 > 127.0.0.1.51620: Flags [S.], seq 1985100467, ack 2219367904, win 65483, options [mss 65495,sackOK,TS val 2872061001 ecr 1725291729,nop,wscale 10], length 0
20:01:35.886690 IP 127.0.0.1.51620 > 127.0.0.1.8000: Flags [.], ack 1, win 64, options [nop,nop,TS val 1725291729 ecr 2872061001], length 0
20:01:35.886746 IP 127.0.0.1.51620 > 127.0.0.1.8000: Flags [P.], seq 1:82, ack 1, win 64, options [nop,nop,TS val 1725291729 ecr 2872061001], length 81
20:01:35.886754 IP 127.0.0.1.8000 > 127.0.0.1.51620: Flags [.], ack 82, win 64, options [nop,nop,TS val 2872061001 ecr 1725291729], length 0
20:01:35.891863 IP 127.0.0.1.8000 > 127.0.0.1.51620: Flags [P.], seq 1:186, ack 82, win 64, options [nop,nop,TS val 2872061006 ecr 1725291729], length 185
20:01:35.891871 IP 127.0.0.1.51620 > 127.0.0.1.8000: Flags [.], ack 186, win 64, options [nop,nop,TS val 1725291734 ecr 2872061006], length 0
20:01:35.891883 IP 127.0.0.1.8000 > 127.0.0.1.51620: Flags [P.], seq 186:646, ack 82, win 64, options [nop,nop,TS val 2872061006 ecr 1725291734], length 460
20:01:35.891886 IP 127.0.0.1.51620 > 127.0.0.1.8000: Flags [.], ack 646, win 64, options [nop,nop,TS val 1725291734 ecr 2872061006], length 0
20:01:35.891913 IP 127.0.0.1.8000 > 127.0.0.1.51620: Flags [F.], seq 646, ack 82, win 64, options [nop,nop,TS val 2872061006 ecr 1725291734], length 0
20:01:35.892006 IP 127.0.0.1.51620 > 127.0.0.1.8000: Flags [F.], seq 82, ack 647, win 64, options [nop,nop,TS val 1725291734 ecr 2872061006], length 0
20:01:35.892023 IP 127.0.0.1.8000 > 127.0.0.1.51620: Flags [.], ack 83, win 64, options [nop,nop,TS val 2872061006 ecr 1725291734], length 0
```

Pcap có 12 packet của một kết nối: SYN ở packet 1, GET 81 byte ở packet 4, response header 185 byte ở packet 6.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=36 avg_candidates=3.0 rules_indexed=3 matches_total=3 detections_written=3 rule_errors=0
0
```

Lệnh 2, kiểm tra log nạp rule: không có dòng warning hay error nào, tổng kết 3 rule hợp lệ:

```bash
(btids) odixe@LapcuaTriet:~/ids$ grep -c -E "WARNING|ERROR" $D/run_log.txt
grep -E "Rules loaded|Rules indexed" $D/run_log.txt
0
2026-11-02 20:04:35,675 INFO idscore.detection.loader: Rules loaded: files=1 failed_files=0 valid=3 invalid=0 unsupported=0 disabled=0
2026-11-02 20:04:35,676 INFO idscore.detection.repository: Rules indexed: indexed=3 skipped_not_valid=0 duplicate_sid=0
```

Lệnh 3, `line_no` của rule đã nạp so với số dòng trong file:

```bash
(btids) odixe@LapcuaTriet:~/ids$ grep -n "^alert" $D/test.rules | cut -d'(' -f1
python -c "
from idscore.config import load_config
from idscore.detection.loader import load_rules
for r in load_rules(load_config('$D/config.yaml')['detection']):
    print(r.line_no, r.sid, r.status, r.msg)
"
4:alert tcp 127.0.0.1 any -> 127.0.0.1 8000 
7:alert tcp 127.0.0.1 any -> 127.0.0.1 8000 
10:alert tcp 127.0.0.1 8000 -> 127.0.0.1 any 
4 3010001 valid T01 SYN to port 8000
7 3010002 valid T01 GET to port 8000
10 3010003 valid T01 response from port 8000
```

Lệnh 4, in Detection Event và cờ TCP của các packet tương ứng:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, msg, matches}' $D/detections.jsonl
jq -c 'select(.packet_id == 1 or .packet_id == 4 or .packet_id == 6) | {packet_id, tcp_flags, payload_len, direction}' $D/events.jsonl
{"packet_id":1,"sid":3010001,"msg":"T01 SYN to port 8000","matches":[]}
{"packet_id":4,"sid":3010002,"msg":"T01 GET to port 8000","matches":[{"content":"GET ","buffer":"payload","start":0,"end":4}]}
{"packet_id":6,"sid":3010003,"msg":"T01 response from port 8000","matches":[{"content":"HTTP/1.0","buffer":"payload","start":0,"end":8}]}
{"packet_id":1,"tcp_flags":"SYN","payload_len":0,"direction":"forward"}
{"packet_id":4,"tcp_flags":"PSH-ACK","payload_len":81,"direction":"forward"}
{"packet_id":6,"tcp_flags":"PSH-ACK","payload_len":185,"direction":"backward"}
```

### T01 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Dòng trống, khoảng trắng, comment không sang parser | chỉ 3 rule được nạp, không có Rule nào cho dòng 3, 5, 6, 8, 9 | Đạt |
| 2 | `line_no` đúng dòng thật | `line_no` 4, 7, 10 trùng kết quả `grep -n` | Đạt |
| 3 | Không warning hay error, tổng kết đúng | 0 dòng `WARNING`/`ERROR`, `valid=3 invalid=0 unsupported=0`, rule `1999999` không có mặt | Đạt |
| 4 | Rule nạp được dùng được thật | sid `3010001` ở SYN packet 1, `3010002` ở GET packet 4, `3010003` ở response packet 6 | Đạt |
| 5 | Chương trình thoát mã 0 | mã thoát `0`, 12 packet OK | Đạt |

## T02: Rule sai cú pháp

### Mục tiêu

1. Mỗi rule hỏng được đánh dấu `invalid` kèm lý do, có một dòng warning nêu file và số dòng.
2. Rule hỏng không làm dừng việc nạp: rule hợp lệ vẫn được nạp và sinh Detection Event.
3. Tổng kết `valid=1 invalid=8`.
4. Chương trình chạy hết pcap và thoát mã 0.

### Bộ rule

1 rule hợp lệ cùng 8 rule hỏng, mỗi rule hỏng đúng một chỗ, dòng comment phía trên ghi chỗ hỏng.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t02_invalid_rules
cat $D/test.rules
# T02: 1 rule hợp lệ và 8 rule hỏng, mỗi rule hỏng đúng một chỗ
alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:"T02 valid GET to port 8000"; flow:to_server,established; content:"GET "; offset:0; depth:4; sid:3020001; rev:1;)
# thiếu dấu ) cuối
alert tcp any any -> any 8000 (msg:"T02 missing closing parenthesis"; sid:3020002; rev:1;
# header thiếu token (thiếu dst_port)
alert tcp any any -> any (msg:"T02 header has 6 tokens"; sid:3020003; rev:1;)
# thiếu sid
alert tcp any any -> any 8000 (msg:"T02 missing sid"; rev:1;)
# IP sai
alert tcp 300.1.1.1 any -> any 8000 (msg:"T02 bad ip"; sid:3020005; rev:1;)
# CIDR /33
alert tcp 10.0.0.0/33 any -> any 8000 (msg:"T02 bad cidr"; sid:3020006; rev:1;)
# port ngoài 0-65535
alert tcp any 70000 -> any 8000 (msg:"T02 bad port"; sid:3020007; rev:1;)
# range ngược
alert tcp any 2000:1000 -> any 8000 (msg:"T02 reversed range"; sid:3020008; rev:1;)
# content thiếu dấu " đóng
alert tcp any any -> any 8000 (msg:"T02 unterminated content"; content:"GET; sid:3020009; rev:1;)
```

### Input

Dùng lại pcap của T01 vì testcase chỉ khác bộ rule.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t02_invalid_rules
python main.py --pcap TEST/requirements3/t01_load_rules/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:4 (sid 3020002) is invalid: rule must end with ')'
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:6 (sid 3020003) is invalid: header: expected 7 tokens (action protocol src_ip src_port direction dst_ip dst_port), got 6
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:8 is invalid: missing required option 'sid'
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:10 (sid 3020005) is invalid: src_ip: '300.1.1.1' is not a valid IPv4 network (Octet 300 (> 255) not permitted in '300.1.1.1')
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:12 (sid 3020006) is invalid: src_ip: '10.0.0.0/33' is not a valid IPv4 network ('33' is not a valid netmask)
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:14 (sid 3020007) is invalid: src_port: '70000' is outside 0-65535
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:16 (sid 3020008) is invalid: src_port: '2000:1000' has low greater than high
2026-11-02 20:56:18,464 WARNING idscore.detection.loader: Rule TEST/requirements3/t02_invalid_rules/test.rules:18 is invalid: option #2: quote is not closed; missing required option 'sid'
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=12 avg_candidates=1.0 rules_indexed=1 matches_total=1 detections_written=1 rule_errors=0
0
```

Mỗi rule hỏng in một dòng warning ra màn hình trước dòng tổng kết.

Lệnh 2, tổng kết nạp rule:

```bash
(btids) odixe@LapcuaTriet:~/ids$ grep -E "Rules loaded|Rules indexed" $D/run_log.txt
2026-11-02 20:04:48,569 INFO idscore.detection.loader: Rules loaded: files=1 failed_files=0 valid=1 invalid=8 unsupported=0 disabled=0
2026-11-02 20:04:48,569 INFO idscore.detection.repository: Rules indexed: indexed=1 skipped_not_valid=8 duplicate_sid=0
```

Lệnh 3, Detection Event của rule hợp lệ:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, msg, matches}' $D/detections.jsonl
{"packet_id":4,"sid":3020001,"msg":"T02 valid GET to port 8000","matches":[{"content":"GET ","buffer":"payload","start":0,"end":4}]}
```

### T02 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Mỗi rule hỏng là `invalid` kèm lý do và vị trí | 8 dòng warning ở dòng 4, 6, 8, 10, 12, 14, 16, 18, lý do lần lượt: thiếu `)`, header 6 token, thiếu `sid`, octet `300`, netmask `33`, port `70000`, range `2000:1000` ngược, ngoặc kép chưa đóng | Đạt |
| 2 | Rule hỏng không làm dừng việc nạp | rule hợp lệ `3020001` vẫn được index và khớp GET packet 4 | Đạt |
| 3 | Tổng kết đúng | `valid=1 invalid=8 unsupported=0`, `skipped_not_valid=8` | Đạt |
| 4 | Chạy hết pcap, thoát mã 0 | 12 packet OK, mã thoát `0` | Đạt |

**Ghi chú:** rule thiếu `"` đóng ở dòng 18 còn báo thêm thiếu `sid` vì mọi ký tự sau dấu `"` mở đều nằm trong chuỗi, kể cả `sid:3020009`. Rule vẫn bị loại đúng là `invalid`.

## T03: Keyword, protocol, action ngoài phạm vi

### Mục tiêu

1. Rule đúng cú pháp Snort nhưng ngoài phạm vi được đánh dấu `unsupported`, không bị nhầm thành `invalid`.
2. Lý do trong warning nêu đúng keyword hoặc phần header ngoài phạm vi.
3. Rule vừa ngoài phạm vi vừa sai cú pháp được đánh dấu `invalid`, lý do `invalid` đứng trước.
4. Không crash, rule hợp lệ vẫn khớp, thoát mã 0.

### Bộ rule

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t03_unsupported_rules
cat $D/test.rules
# T03: 1 rule hợp lệ, 9 rule đúng cú pháp Snort nhưng ngoài phạm vi, 1 rule vừa ngoài phạm vi vừa thiếu sid
alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:"T03 valid GET to port 8000"; flow:to_server,established; content:"GET "; offset:0; depth:4; sid:3030001; rev:1;)
alert tcp any any -> any 8000 (msg:"T03 pcre"; pcre:"/GET \/t0[0-9]/"; sid:3030002; rev:1;)
alert tcp any any -> any 8000 (msg:"T03 byte_test"; byte_test:1,>,0,0; sid:3030003; rev:1;)
alert tcp any any -> any 8000 (msg:"T03 http_uri"; content:"/t01"; http_uri; sid:3030004; rev:1;)
alert icmp any any -> any any (msg:"T03 protocol icmp"; sid:3030005; rev:1;)
drop tcp any any -> any 8000 (msg:"T03 action drop"; sid:3030006; rev:1;)
alert tcp !127.0.0.1 any -> any 8000 (msg:"T03 negated ip"; sid:3030007; rev:1;)
alert tcp $HOME_NET any -> any 8000 (msg:"T03 variable"; sid:3030008; rev:1;)
alert tcp any any -> any 8000 (msg:"T03 flow stateless"; flow:stateless; sid:3030009; rev:1;)
alert tcp any any -> any 8000 (msg:"T03 dsize >="; dsize:>=10; sid:3030010; rev:1;)
# vừa có pcre (unsupported) vừa thiếu sid (invalid): invalid được ưu tiên
alert tcp any any -> any 8000 (msg:"T03 pcre and missing sid"; pcre:"/x/"; rev:1;)
```

### Input

Dùng lại pcap của T01.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t03_unsupported_rules
python main.py --pcap TEST/requirements3/t01_load_rules/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
2026-11-02 20:56:18,632 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:3 (sid 3030002) is unsupported: option #2 (pcre): keyword is not supported
2026-11-02 20:56:18,632 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:4 (sid 3030003) is unsupported: option #2 (byte_test): keyword is not supported
2026-11-02 20:56:18,632 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:5 (sid 3030004) is unsupported: option #3 (http_uri): keyword is not supported
2026-11-02 20:56:18,632 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:6 (sid 3030005) is unsupported: protocol: 'icmp' is not supported, only tcp, udp, ip
2026-11-02 20:56:18,632 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:7 (sid 3030006) is unsupported: action: 'drop' is not supported, only 'alert'
2026-11-02 20:56:18,633 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:8 (sid 3030007) is unsupported: src_ip: negation '!' is not supported, got '!127.0.0.1'
2026-11-02 20:56:18,633 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:9 (sid 3030008) is unsupported: src_ip: variable '$...' is not supported, got '$HOME_NET'
2026-11-02 20:56:18,633 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:10 (sid 3030009) is unsupported: option #2 (flow): 'stateless' is not supported
2026-11-02 20:56:18,633 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:11 (sid 3030010) is unsupported: option #2 (dsize): '>=10' is not supported, use N, >N, <N, N<>M or N<=>M
2026-11-02 20:56:18,633 WARNING idscore.detection.loader: Rule TEST/requirements3/t03_unsupported_rules/test.rules:13 is invalid: missing required option 'sid'; option #2 (pcre): keyword is not supported
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=12 avg_candidates=1.0 rules_indexed=1 matches_total=1 detections_written=1 rule_errors=0
0
```

Lệnh 2, tổng kết nạp rule và Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ grep -E "Rules loaded|Rules indexed" $D/run_log.txt
jq -c '{packet_id, sid, msg}' $D/detections.jsonl
2026-11-02 20:05:49,687 INFO idscore.detection.loader: Rules loaded: files=1 failed_files=0 valid=1 invalid=1 unsupported=9 disabled=0
2026-11-02 20:05:49,687 INFO idscore.detection.repository: Rules indexed: indexed=1 skipped_not_valid=10 duplicate_sid=0
{"packet_id":4,"sid":3030001,"msg":"T03 valid GET to port 8000"}
```

### T03 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Rule ngoài phạm vi là `unsupported` | 9 rule dòng 3 đến 11 đều `unsupported`, không rule nào bị đánh `invalid` | Đạt |
| 2 | Lý do nêu đúng keyword hoặc phần header | `pcre`, `byte_test`, `http_uri`, protocol `icmp`, action `drop`, phủ định `!127.0.0.1`, biến `$HOME_NET`, `flow:stateless`, `dsize:>=10` | Đạt |
| 3 | `invalid` được ưu tiên hơn `unsupported` | dòng 13 có `pcre` và thiếu `sid` là `invalid`, lý do thiếu `sid` đứng trước lý do `pcre` | Đạt |
| 4 | Không crash, rule hợp lệ vẫn khớp, thoát mã 0 | `valid=1 invalid=1 unsupported=9`, sid `3030001` khớp GET packet 4, mã thoát `0` | Đạt |

## T04: Parse header

### Mục tiêu

1. Mỗi dạng header bắt buộc được parse thành Internal Rule Object đúng: `any`, IP đơn, CIDR, port đơn, range, range mở, protocol `tcp`, `udp`, `ip`, direction `->` và `<>`.
2. `any` thành `None`, IP đơn thành mạng `/32`, port đơn thành `(p, p)`, range mở `:1023` thành `(0, 1023)` và `8000:` thành `(8000, 65535)`.
3. Mọi rule đều `valid`.
4. Script thoát mã 0.

### Bộ rule

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t04_header_parse
cat $D/test.rules
# T04: mỗi rule một dạng header, chỉ kiểm tra Internal Rule Object
alert tcp any any -> any any (msg:"T04 any to any"; sid:3040001; rev:1;)
alert tcp 127.0.0.1 any -> any any (msg:"T04 single ip"; sid:3040002; rev:1;)
alert tcp 10.0.0.0/8 any -> any any (msg:"T04 cidr"; sid:3040003; rev:1;)
alert tcp any any -> any 80 (msg:"T04 single port"; sid:3040004; rev:1;)
alert tcp any 1024:65535 -> any any (msg:"T04 port range"; sid:3040005; rev:1;)
alert tcp any :1023 -> any 8000: (msg:"T04 open ranges"; sid:3040006; rev:1;)
alert udp any any -> 8.8.8.8 53 (msg:"T04 udp"; sid:3040007; rev:1;)
alert ip 192.168.1.0/24 any -> any any (msg:"T04 ip"; sid:3040008; rev:1;)
alert tcp any 80 <> 10.0.0.1 any (msg:"T04 bidirectional"; sid:3040009; rev:1;)
```

### Tạo input

Testcase chỉ kiểm tra parser nên không cần pcap. Script header_parse.py gọi `load_rules` với `config.yaml` của testcase rồi in phần header của từng rule, so với kỳ vọng tính tay ghi trong script.

### Chạy và kiểm tra

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t04_header_parse
PYTHONPATH=. python $D/header_parse.py 2>&1 | tee $D/run_log.txt
echo ${PIPESTATUS[0]}
[3040001] line 2: alert tcp any any -> any any
    protocol=TCP src_ip=None src_port=None direction=-> dst_ip=None dst_port=None
    status=valid | khớp kỳ vọng
[3040002] line 3: alert tcp 127.0.0.1 any -> any any
    protocol=TCP src_ip=127.0.0.1/32 src_port=None direction=-> dst_ip=None dst_port=None
    status=valid | khớp kỳ vọng
[3040003] line 4: alert tcp 10.0.0.0/8 any -> any any
    protocol=TCP src_ip=10.0.0.0/8 src_port=None direction=-> dst_ip=None dst_port=None
    status=valid | khớp kỳ vọng
[3040004] line 5: alert tcp any any -> any 80
    protocol=TCP src_ip=None src_port=None direction=-> dst_ip=None dst_port=(80, 80)
    status=valid | khớp kỳ vọng
[3040005] line 6: alert tcp any 1024:65535 -> any any
    protocol=TCP src_ip=None src_port=(1024, 65535) direction=-> dst_ip=None dst_port=None
    status=valid | khớp kỳ vọng
[3040006] line 7: alert tcp any :1023 -> any 8000:
    protocol=TCP src_ip=None src_port=(0, 1023) direction=-> dst_ip=None dst_port=(8000, 65535)
    status=valid | khớp kỳ vọng
[3040007] line 8: alert udp any any -> 8.8.8.8 53
    protocol=UDP src_ip=None src_port=None direction=-> dst_ip=8.8.8.8/32 dst_port=(53, 53)
    status=valid | khớp kỳ vọng
[3040008] line 9: alert ip 192.168.1.0/24 any -> any any
    protocol=IP src_ip=192.168.1.0/24 src_port=None direction=-> dst_ip=None dst_port=None
    status=valid | khớp kỳ vọng
[3040009] line 10: alert tcp any 80 <> 10.0.0.1 any
    protocol=TCP src_ip=None src_port=(80, 80) direction=<> dst_ip=10.0.0.1/32 dst_port=None
    status=valid | khớp kỳ vọng
rules: 9, sai kỳ vọng: 0
0
```

### T04 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Mọi dạng header được parse đúng | 9 rule khớp kỳ vọng, `sai kỳ vọng: 0` | Đạt |
| 2 | `any`, IP đơn, port đơn, range mở | `any` là `None`, `127.0.0.1` thành `127.0.0.1/32`, `80` thành `(80, 80)`, `:1023` thành `(0, 1023)`, `8000:` thành `(8000, 65535)` | Đạt |
| 3 | Protocol và direction | `tcp`, `udp`, `ip` thành `TCP`, `UDP`, `IP`; rule 3040009 giữ direction `<>` | Đạt |
| 4 | Mọi rule `valid`, thoát mã 0 | 9 rule `valid`, mã thoát `0` | Đạt |

## T05: Direction `->` và `<>`

### Mục tiêu

1. Rule `->` chỉ khớp đúng chiều khai báo.
2. Rule `<>` khớp cả hai chiều.
3. `src_ip`/`src_port` trong Detection Event là của packet thật, không lấy từ rule.
4. Chương trình thoát mã 0.

### Bộ rule

Ba rule cùng content `HTTP/1.`, chuỗi này có trong cả request (`GET /t05 HTTP/1.1`) lẫn response (`HTTP/1.0 404`).

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t05_direction
cat $D/test.rules
# T05: cùng content HTTP/1. (có trong cả request lẫn response), chỉ khác direction
alert tcp any any -> any 8000 (msg:"T05 R1 -> to port 8000"; content:"HTTP/1."; sid:3050001; rev:1;)
alert tcp any 8000 -> any any (msg:"T05 R2 -> from port 8000"; content:"HTTP/1."; sid:3050002; rev:1;)
alert tcp any 8000 <> any any (msg:"T05 R3 <> port 8000"; content:"HTTP/1."; sid:3050003; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t05_direction
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/t05
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t05_direction
tcpdump -nn -A -r $D/input.pcap | grep -a -E "^(GET|HTTP)"
reading from file TEST/requirements3/t05_direction/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
```

Request ở chiều client tới 8000, response ở chiều ngược lại, cả hai chứa `HTTP/1.`.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=36 avg_candidates=3.0 rules_indexed=3 matches_total=4 detections_written=4 rule_errors=0
0
```

Lệnh 2, in Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, src: "\(.src_ip):\(.src_port)", dst: "\(.dst_ip):\(.dst_port)", matches}' $D/detections.jsonl
{"packet_id":4,"sid":3050001,"src":"127.0.0.1:59192","dst":"127.0.0.1:8000","matches":[{"content":"HTTP/1.","buffer":"payload","start":9,"end":16}]}
{"packet_id":4,"sid":3050003,"src":"127.0.0.1:59192","dst":"127.0.0.1:8000","matches":[{"content":"HTTP/1.","buffer":"payload","start":9,"end":16}]}
{"packet_id":6,"sid":3050002,"src":"127.0.0.1:8000","dst":"127.0.0.1:59192","matches":[{"content":"HTTP/1.","buffer":"payload","start":0,"end":7}]}
{"packet_id":6,"sid":3050003,"src":"127.0.0.1:8000","dst":"127.0.0.1:59192","matches":[{"content":"HTTP/1.","buffer":"payload","start":0,"end":7}]}
```

### T05 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | `->` chỉ khớp đúng chiều | R1 `-> any 8000` chỉ khớp GET packet 4, R2 `any 8000 ->` chỉ khớp response packet 6 | Đạt |
| 2 | `<>` khớp cả hai chiều | R3 khớp cả packet 4 và packet 6 | Đạt |
| 3 | 5-tuple lấy từ packet thật | R3 ở packet 4 là `127.0.0.1:59192 -> 127.0.0.1:8000`, ở packet 6 là `127.0.0.1:8000 -> 127.0.0.1:59192` | Đạt |
| 4 | Thoát mã 0 | mã thoát `0`, 4 Detection Event | Đạt |

## T06: Indexer với `ip`, `tcp`, `udp` và any

### Mục tiêu

1. Mỗi rule nằm đúng bucket của indexer theo protocol và port.
2. `candidates` trả đúng tập rule theo protocol và port của event, giữ thứ tự nạp.
3. Rule `ip` có mặt ở cả event TCP lẫn UDP.
4. Event không có transport không có candidate.
5. Script thoát mã 0.

### Bộ rule

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t06_indexer
cat $D/test.rules
# T06: mỗi rule rơi vào một bucket khác nhau của indexer
alert tcp any any -> any 80 (msg:"T06 tcp exact 80"; sid:3060001; rev:1;)
alert tcp any any -> any 1024:65535 (msg:"T06 tcp range 1024:65535"; sid:3060002; rev:1;)
alert tcp any any -> any any (msg:"T06 tcp any"; sid:3060003; rev:1;)
alert tcp any 80 <> any any (msg:"T06 tcp <> src port 80"; sid:3060004; rev:1;)
alert udp any any -> any 53 (msg:"T06 udp exact 53"; sid:3060005; rev:1;)
alert udp any any -> any any (msg:"T06 udp any"; sid:3060006; rev:1;)
alert ip any any -> any any (msg:"T06 ip"; sid:3060007; rev:1;)
```

### Tạo input

Không cần pcap. Script indexer.py dựng `RuleRepository` từ `config.yaml` của testcase, in `stats()` và `describe()`, rồi dựng tay 6 `Event` như `missing_fields.py` của t06 bài 2 và in sid candidate của từng event so với kỳ vọng tính tay.

| packet_id | Event | Candidate kỳ vọng |
| --- | --- | --- |
| 1 | TCP 40000 -> 80 | exact 80 (`3060001`, `3060004`), range chứa 40000 (`3060002`), tcp any (`3060003`), ip (`3060007`) |
| 2 | TCP 80 -> 40000 | như packet 1 vì indexer tra cả `src_port` lẫn `dst_port` |
| 3 | TCP 40000 -> 5000 | range (`3060002`), tcp any (`3060003`), ip (`3060007`) |
| 4 | UDP 40000 -> 53 | udp exact 53 (`3060005`), udp any (`3060006`), ip (`3060007`) |
| 5 | UDP 40000 -> 123 | udp any (`3060006`), ip (`3060007`) |
| 6 | UNKNOWN không có transport | không có |

### Chạy và kiểm tra

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t06_indexer
PYTHONPATH=. python $D/indexer.py 2>&1 | tee $D/run_log.txt
echo ${PIPESTATUS[0]}
stats   : {"indexed": 7, "skipped_not_valid": 0, "duplicate_sid": 0, "TCP": {"exact_ports": 1, "exact_rules": 2, "ranges": 1, "any": 1}, "UDP": {"exact_ports": 1, "exact_rules": 1, "ranges": 0, "any": 1}, "IP": 1}
describe: {"TCP": {"exact": {"80": [3060001, 3060004]}, "ranges": [[1024, 65535, 3060002]], "any": [3060003]}, "UDP": {"exact": {"53": [3060005]}, "ranges": [], "any": [3060006]}, "IP": [3060007]}
[1] TCP 40000 -> 80
    candidates: [3060001, 3060002, 3060003, 3060004, 3060007]
    kỳ vọng   : [3060001, 3060002, 3060003, 3060004, 3060007] | khớp
[2] TCP 80 -> 40000
    candidates: [3060001, 3060002, 3060003, 3060004, 3060007]
    kỳ vọng   : [3060001, 3060002, 3060003, 3060004, 3060007] | khớp
[3] TCP 40000 -> 5000
    candidates: [3060002, 3060003, 3060007]
    kỳ vọng   : [3060002, 3060003, 3060007] | khớp
[4] UDP 40000 -> 53
    candidates: [3060005, 3060006, 3060007]
    kỳ vọng   : [3060005, 3060006, 3060007] | khớp
[5] UDP 40000 -> 123
    candidates: [3060006, 3060007]
    kỳ vọng   : [3060006, 3060007] | khớp
[6] UNKNOWN không có transport
    candidates: []
    kỳ vọng   : [] | khớp
events: 6, sai kỳ vọng: 0
0
```

### T06 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Rule nằm đúng bucket | TCP exact `80: [3060001, 3060004]`, range `[1024, 65535, 3060002]`, any `[3060003]`; UDP exact `53: [3060005]`, any `[3060006]`; IP `[3060007]` | Đạt |
| 2 | `candidates` đúng tập và đúng thứ tự nạp | 6 event đều khớp bảng kỳ vọng, `sai kỳ vọng: 0` | Đạt |
| 3 | Rule `ip` có ở cả TCP và UDP | `3060007` có trong candidate của packet 1 đến 5 | Đạt |
| 4 | Event không có transport không có candidate | packet 6 UNKNOWN ra `[]` | Đạt |
| 5 | Script thoát mã 0 | mã thoát `0` | Đạt |

**Ghi chú:** rule `3060004` `tcp any 80 <> any any` được index theo port đơn 80 ở phía nguồn. Nhờ indexer tra cả hai port của event, nó có mặt ở cả packet 1 (80 là port đích) lẫn packet 2 (80 là port nguồn).

## T07: Header không match bị loại trước content

### Mục tiêu

1. Rule sai protocol hoặc sai port bị indexer loại, không tới matcher.
2. Rule lọt vào candidate nhưng sai IP bị phần header của matcher loại, không tới bước so content.
3. Rule đúng header được so content và sinh Detection Event.
4. Chương trình thoát mã 0.

### Bộ rule

Bốn rule cùng content `GET`, chỉ R1 đúng header.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t07_header_mismatch
cat $D/test.rules
# T07: cùng content GET, chỉ R1 đúng header
alert tcp any any -> any 8000 (msg:"T07 R1 correct header"; content:"GET"; sid:3070001; rev:1;)
alert udp any any -> any 8000 (msg:"T07 R2 wrong protocol"; content:"GET"; sid:3070002; rev:1;)
alert tcp any any -> any 9999 (msg:"T07 R3 wrong dst port"; content:"GET"; sid:3070003; rev:1;)
alert tcp 10.0.0.0/8 any -> any 8000 (msg:"T07 R4 wrong src ip"; content:"GET"; sid:3070004; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t07_header_mismatch
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/t07
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t07_header_mismatch
tcpdump -nn -A -r $D/input.pcap | grep -a "GET "
reading from file TEST/requirements3/t07_header_mismatch/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
*o.E...PGET /t07 HTTP/1.1
```

### Chạy IDS và kiểm tra

Script count_contents.py chạy `cli.main` với đúng tham số như `python main.py`, đồng thời bọc `matcher._match_contents` để đếm số lần mỗi rule được đưa tới bước so content.

Lệnh 1: chạy IDS qua script đếm

```bash
(btids) odixe@LapcuaTriet:~/ids$ PYTHONPATH=. python $D/count_contents.py 2>&1 | tee $D/content_calls.txt
echo ${PIPESTATUS[0]}
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=24 avg_candidates=2.0 rules_indexed=4 matches_total=1 detections_written=1 rule_errors=0
exit code: 0
sid 3070001: _match_contents gọi 6 lần
sid 3070002: _match_contents gọi 0 lần
sid 3070003: _match_contents gọi 0 lần
sid 3070004: _match_contents gọi 0 lần
0
```

Lệnh 2, nội dung index và Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python -c "
import json
from idscore.config import load_config
from idscore.detection.loader import load_rules
from idscore.detection.repository import RuleRepository
print(json.dumps(RuleRepository(load_rules(load_config('$D/config.yaml')['detection'])).describe()))
"
jq -c '{packet_id, sid, matches}' $D/detections.jsonl
{"TCP": {"exact": {"8000": [3070001, 3070004], "9999": [3070003]}, "ranges": [], "any": []}, "UDP": {"exact": {"8000": [3070002]}, "ranges": [], "any": []}, "IP": []}
{"packet_id":4,"sid":3070001,"matches":[{"content":"GET","buffer":"payload","start":0,"end":3}]}
```

### T07 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Sai protocol, sai port bị indexer loại | R2 nằm ở bucket UDP, R3 ở port 9999, không có trong candidate của event TCP tới 8000; `_match_contents` 0 lần | Đạt |
| 2 | Sai IP bị header của matcher loại trước content | R4 cùng bucket 8000 với R1 nên lọt candidate (`candidates_total=24` = 12 event × 2 rule) nhưng `_match_contents` 0 lần | Đạt |
| 3 | Đúng header thì được so content | R1 được so content 6 lần ứng với 6 packet client gửi tới 8000, khớp GET packet 4 | Đạt |
| 4 | Thoát mã 0 | mã thoát `0`, 1 Detection Event | Đạt |

## T08: `flow:to_server,established`

### Mục tiêu

1. `to_server` và `to_client` lấy đúng chiều từ Flow Tracker: client là bên gửi SYN.
2. `established` chỉ khớp khi flow đã qua handshake, `not_established` khớp khi chưa established.
3. Cùng một content có trong cả request và response, `flow` quyết định rule nào khớp.
4. Chương trình thoát mã 0.

### Bộ rule

Cả 4 rule dùng header `tcp any any -> any any` để chỉ có `flow` quyết định.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t08_flow
cat $D/test.rules
# T08: header any any -> any any để chỉ có flow quyết định
alert tcp any any -> any any (msg:"T08 R1 to_server established"; flow:to_server,established; sid:3080001; rev:1;)
alert tcp any any -> any any (msg:"T08 R2 to_server established HTTP/1."; flow:to_server,established; content:"HTTP/1."; sid:3080002; rev:1;)
alert tcp any any -> any any (msg:"T08 R3 to_client established HTTP/1."; flow:to_client,established; content:"HTTP/1."; sid:3080003; rev:1;)
alert tcp any any -> any any (msg:"T08 R4 to_server not_established"; flow:to_server,not_established; sid:3080004; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t08_flow
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/t08
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t08_flow
tcpdump -nn -r $D/input.pcap
reading from file TEST/requirements3/t08_flow/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
20:02:00.207550 IP 127.0.0.1.53826 > 127.0.0.1.8000: Flags [S], seq 829212188, win 65495, options [mss 65495,sackOK,TS val 1816518283 ecr 0,nop,wscale 10], length 0
20:02:00.207571 IP 127.0.0.1.8000 > 127.0.0.1.53826: Flags [S.], seq 3010177157, ack 829212189, win 65483, options [mss 65495,sackOK,TS val 4099235024 ecr 1816518283,nop,wscale 10], length 0
20:02:00.207589 IP 127.0.0.1.53826 > 127.0.0.1.8000: Flags [.], ack 1, win 64, options [nop,nop,TS val 1816518283 ecr 4099235024], length 0
20:02:00.207656 IP 127.0.0.1.53826 > 127.0.0.1.8000: Flags [P.], seq 1:82, ack 1, win 64, options [nop,nop,TS val 1816518283 ecr 4099235024], length 81
20:02:00.207665 IP 127.0.0.1.8000 > 127.0.0.1.53826: Flags [.], ack 82, win 64, options [nop,nop,TS val 4099235024 ecr 1816518283], length 0
20:02:00.208898 IP 127.0.0.1.8000 > 127.0.0.1.53826: Flags [P.], seq 1:186, ack 82, win 64, options [nop,nop,TS val 4099235025 ecr 1816518283], length 185
20:02:00.208923 IP 127.0.0.1.53826 > 127.0.0.1.8000: Flags [.], ack 186, win 64, options [nop,nop,TS val 1816518284 ecr 4099235025], length 0
20:02:00.208957 IP 127.0.0.1.8000 > 127.0.0.1.53826: Flags [P.], seq 186:646, ack 82, win 64, options [nop,nop,TS val 4099235025 ecr 1816518284], length 460
20:02:00.208966 IP 127.0.0.1.53826 > 127.0.0.1.8000: Flags [.], ack 646, win 64, options [nop,nop,TS val 1816518284 ecr 4099235025], length 0
20:02:00.209014 IP 127.0.0.1.8000 > 127.0.0.1.53826: Flags [F.], seq 646, ack 82, win 64, options [nop,nop,TS val 4099235025 ecr 1816518284], length 0
20:02:00.209093 IP 127.0.0.1.53826 > 127.0.0.1.8000: Flags [F.], seq 82, ack 647, win 64, options [nop,nop,TS val 1816518284 ecr 4099235025], length 0
20:02:00.209123 IP 127.0.0.1.8000 > 127.0.0.1.53826: Flags [.], ack 83, win 64, options [nop,nop,TS val 4099235025 ecr 1816518284], length 0
```

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=48 avg_candidates=4.0 rules_indexed=4 matches_total=8 detections_written=8 rule_errors=0
0
```

Lệnh 2, `events.jsonl` không có trạng thái flow nên script flow_states.py chạy lại pcap qua pipeline giống `cli.py` và in `FlowContext` của từng packet, kèm sid khớp lấy từ `detections.jsonl`:

```bash
(btids) odixe@LapcuaTriet:~/ids$ PYTHONPATH=. python $D/flow_states.py | tee $D/flow_states.txt
#1  SYN      payload=0   direction=forward  from_client=True  state=HANDSHAKE   sid=[3080004]
#2  SYN-ACK  payload=0   direction=backward from_client=False state=HANDSHAKE   sid=[]
#3  ACK      payload=0   direction=forward  from_client=True  state=ESTABLISHED sid=[3080001]
#4  PSH-ACK  payload=81  direction=forward  from_client=True  state=ESTABLISHED sid=[3080001, 3080002]
#5  ACK      payload=0   direction=backward from_client=False state=ESTABLISHED sid=[]
#6  PSH-ACK  payload=185 direction=backward from_client=False state=ESTABLISHED sid=[3080003]
#7  ACK      payload=0   direction=forward  from_client=True  state=ESTABLISHED sid=[3080001]
#8  PSH-ACK  payload=460 direction=backward from_client=False state=ESTABLISHED sid=[]
#9  ACK      payload=0   direction=forward  from_client=True  state=ESTABLISHED sid=[3080001]
#10 FIN-ACK  payload=0   direction=backward from_client=False state=CLOSING     sid=[]
#11 FIN-ACK  payload=0   direction=forward  from_client=True  state=CLOSED      sid=[3080004]
#12 ACK      payload=0   direction=backward from_client=False state=CLOSED      sid=[]
```

Lệnh 3, đối chiếu `direction` trong `events.jsonl` và thống kê theo sid:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, tcp_flags, direction}' $D/events.jsonl | head -4
grep "Matches by sid" $D/run_log.txt
{"packet_id":1,"tcp_flags":"SYN","direction":"forward"}
{"packet_id":2,"tcp_flags":"SYN-ACK","direction":"backward"}
{"packet_id":3,"tcp_flags":"ACK","direction":"forward"}
{"packet_id":4,"tcp_flags":"PSH-ACK","direction":"forward"}
2026-11-02 20:09:05,411 INFO idscore.cli: Matches by sid: 3080001=4 3080002=1 3080003=1 3080004=2
```

### T08 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Chiều lấy đúng từ Flow Tracker | packet client có `from_client=True`, packet server có `from_client=False`, khớp `direction` forward/backward trong `events.jsonl` | Đạt |
| 2 | R1 `to_server,established` không content | khớp packet 3, 4, 7, 9: các packet client ở trạng thái `ESTABLISHED`; không khớp SYN packet 1 | Đạt |
| 3 | Cùng content, `flow` quyết định | R2 chỉ khớp GET packet 4, R3 chỉ khớp response packet 6 | Đạt |
| 4 | R4 `to_server,not_established` | khớp SYN packet 1 (`HANDSHAKE`) và FIN của client packet 11 (`CLOSED`) | Đạt |
| 5 | Thoát mã 0 | mã thoát `0`, 8 Detection Event | Đạt |

**Ghi chú:**
- R1 khớp cả ACK cuối handshake (packet 3) vì `context_of` được gọi sau khi tracker xử lý packet, lúc đó flow vừa chuyển sang `ESTABLISHED`.
- Server gửi FIN trước (packet 10), flow chuyển `CLOSING` rồi `CLOSED`. Bài làm không tính `CLOSING`/`CLOSED` là established, nên FIN của client ở packet 11 không khớp R1 mà khớp R4.

## T09: Content có và không có `nocase`

### Mục tiêu

1. Content không có `nocase` phân biệt hoa thường.
2. Content có `nocase` khớp bất kể hoa thường, ở cả pattern viết thường và viết hoa.
3. `start`/`end` trong `matches` trỏ đúng vị trí trong payload.
4. Chương trình thoát mã 0.

### Bộ rule

Payload chứa header `X-Test: AbCdEf`, không có chuỗi `abcdef` viết thường.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t09_nocase
cat $D/test.rules
# T09: payload chứa header X-Test: AbCdEf
alert tcp any any -> any 8000 (msg:"T09 R1 abcdef case sensitive"; content:"abcdef"; sid:3090001; rev:1;)
alert tcp any any -> any 8000 (msg:"T09 R2 abcdef nocase"; content:"abcdef"; nocase; sid:3090002; rev:1;)
alert tcp any any -> any 8000 (msg:"T09 R3 AbCdEf exact case"; content:"AbCdEf"; sid:3090003; rev:1;)
alert tcp any any -> any 8000 (msg:"T09 R4 ABCDEF nocase"; content:"ABCDEF"; nocase; sid:3090004; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t09_nocase
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null -H "X-Test: AbCdEf" http://127.0.0.1:8000/t09
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t09_nocase
tcpdump -nn -A -r $D/input.pcap | grep -a "X-Test"
reading from file TEST/requirements3/t09_nocase/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
X-Test: AbCdEf
```

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=48 avg_candidates=4.0 rules_indexed=4 matches_total=3 detections_written=3 rule_errors=0
0
```

Lệnh 2, in Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, matches}' $D/detections.jsonl
{"packet_id":4,"sid":3090002,"matches":[{"content":"abcdef","buffer":"payload","start":87,"end":93}]}
{"packet_id":4,"sid":3090003,"matches":[{"content":"AbCdEf","buffer":"payload","start":87,"end":93}]}
{"packet_id":4,"sid":3090004,"matches":[{"content":"ABCDEF","buffer":"payload","start":87,"end":93}]}
```

Lệnh 3, vị trí `AbCdEf` trong payload của packet GET:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python -c "
from scapy.all import rdpcap, TCP
payload = bytes(rdpcap('$D/input.pcap')[3][TCP].payload)
print(len(payload), payload.find(b'AbCdEf'), payload[87:93], payload.find(b'abcdef'))
"
97 87 b'AbCdEf' -1
```

### T09 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Không `nocase` thì phân biệt hoa thường | R1 `abcdef` không khớp vì payload không có chuỗi viết thường (`find` trả `-1`); R3 `AbCdEf` đúng chữ thì khớp | Đạt |
| 2 | Có `nocase` thì không phân biệt | R2 `abcdef` và R4 `ABCDEF` đều khớp `AbCdEf` | Đạt |
| 3 | `start`/`end` đúng vị trí | cả 3 rule `start=87, end=93`, trùng vị trí `AbCdEf` trong payload 97 byte | Đạt |
| 4 | Thoát mã 0 | mã thoát `0`, 3 Detection Event | Đạt |

**Ghi chú:** `matches` ghi `content` theo pattern gốc người viết rule khai báo (`abcdef`, `ABCDEF`), không phải chuỗi đã đổi hoa thường.

## T10: `offset`/`depth`

### Mục tiêu

1. Content chỉ được tìm trong vùng `[offset, offset + depth)`.
2. Biên được xử lý đúng: vùng vừa khít thì khớp, thiếu 1 byte thì không.
3. `start`/`end` trong `matches` đúng vị trí.
4. Chương trình thoát mã 0.

### Bộ rule

Request bắt đầu bằng `GET /admin HTTP/1.1`: `GET` ở byte 0 đến 3, `admin` ở byte 5 đến 10.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t10_offset_depth
cat $D/test.rules
# T10: request bắt đầu bằng "GET /admin", admin nằm ở byte 5 đến 10
alert tcp any any -> any 8000 (msg:"T10 GET offset 0 depth 3"; content:"GET"; offset:0; depth:3; sid:3100001; rev:1;)
alert tcp any any -> any 8000 (msg:"T10 GET offset 1"; content:"GET"; offset:1; sid:3100002; rev:1;)
alert tcp any any -> any 8000 (msg:"T10 admin offset 5 depth 5"; content:"admin"; offset:5; depth:5; sid:3100003; rev:1;)
alert tcp any any -> any 8000 (msg:"T10 admin offset 6"; content:"admin"; offset:6; sid:3100004; rev:1;)
alert tcp any any -> any 8000 (msg:"T10 admin depth 10"; content:"admin"; depth:10; sid:3100005; rev:1;)
alert tcp any any -> any 8000 (msg:"T10 admin depth 9"; content:"admin"; depth:9; sid:3100006; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t10_offset_depth
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/admin
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t10_offset_depth
tcpdump -nn -A -r $D/input.pcap | grep -a "GET "
reading from file TEST/requirements3/t10_offset_depth/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
GET /admin HTTP/1.1
```

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=72 avg_candidates=6.0 rules_indexed=6 matches_total=3 detections_written=3 rule_errors=0
0
```

Lệnh 2, in Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, msg, matches}' $D/detections.jsonl
{"packet_id":4,"sid":3100001,"msg":"T10 GET offset 0 depth 3","matches":[{"content":"GET","buffer":"payload","start":0,"end":3}]}
{"packet_id":4,"sid":3100003,"msg":"T10 admin offset 5 depth 5","matches":[{"content":"admin","buffer":"payload","start":5,"end":10}]}
{"packet_id":4,"sid":3100005,"msg":"T10 admin depth 10","matches":[{"content":"admin","buffer":"payload","start":5,"end":10}]}
```

### T10 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Chỉ tìm trong `[offset, offset + depth)` | `GET` offset 1 không khớp (vùng bắt đầu sau `G`); `admin` offset 6 không khớp (vùng bắt đầu sau `a`) | Đạt |
| 2 | Biên vừa khít thì khớp, thiếu 1 byte thì không | `admin` offset 5 depth 5 và `admin` depth 10 khớp; `admin` depth 9 không khớp | Đạt |
| 3 | `start`/`end` đúng | `GET` `0-3`, `admin` `5-10` | Đạt |
| 4 | Thoát mã 0 | mã thoát `0`, đúng 3 Detection Event của sid `3100001`, `3100003`, `3100005` | Đạt |

## T11: Hai content với `distance`/`within`

### Mục tiêu

1. Content thứ hai được tìm tương đối so với điểm kết thúc của content thứ nhất.
2. `distance` đẩy điểm bắt đầu tìm, `within` giới hạn độ dài cửa sổ tìm.
3. Rule khớp có đủ hai `ContentMatch` với vị trí đúng, rule không khớp không có dòng nào.
4. Chương trình thoát mã 0.

### Bộ rule

`GET` kết thúc ở byte 3, `admin` ở byte 5 đến 10, `HTTP/1.1` ở byte 11 đến 19. Cửa sổ của content thứ hai là `[cursor + distance, cursor + distance + within)`.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t11_distance_within
cat $D/test.rules
# T11: GET kết thúc ở byte 3, admin nằm ở byte 5 đến 10, HTTP/1.1 nằm ở byte 11 đến 19
alert tcp any any -> any 8000 (msg:"T11 GET then admin distance 2 within 5"; content:"GET"; content:"admin"; distance:2; within:5; sid:3110001; rev:1;)
alert tcp any any -> any 8000 (msg:"T11 GET then admin distance 3"; content:"GET"; content:"admin"; distance:3; sid:3110002; rev:1;)
# within:4 nhỏ hơn độ dài admin sẽ bị parser đánh invalid, nên dùng distance 1 within 5: cửa sổ [4, 9) thiếu 1 byte so với admin [5, 10)
alert tcp any any -> any 8000 (msg:"T11 GET then admin distance 1 within 5"; content:"GET"; content:"admin"; distance:1; within:5; sid:3110003; rev:1;)
alert tcp any any -> any 8000 (msg:"T11 admin then HTTP/1.1 distance 1 within 8"; content:"admin"; content:"HTTP/1.1"; distance:1; within:8; sid:3110004; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t11_distance_within
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/admin
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t11_distance_within
tcpdump -nn -A -r $D/input.pcap | grep -a "GET "
reading from file TEST/requirements3/t11_distance_within/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
.E......GET /admin HTTP/1.1
```

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=48 avg_candidates=4.0 rules_indexed=4 matches_total=2 detections_written=2 rule_errors=0
0
```

Lệnh 2, in Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, msg, matches}' $D/detections.jsonl
{"packet_id":4,"sid":3110001,"msg":"T11 GET then admin distance 2 within 5","matches":[{"content":"GET","buffer":"payload","start":0,"end":3},{"content":"admin","buffer":"payload","start":5,"end":10}]}
{"packet_id":4,"sid":3110004,"msg":"T11 admin then HTTP/1.1 distance 1 within 8","matches":[{"content":"admin","buffer":"payload","start":5,"end":10},{"content":"HTTP/1.1","buffer":"payload","start":11,"end":19}]}
```

### T11 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Content thứ hai tìm tương đối | sid `3110001`: `GET` kết thúc ở 3, `admin` tìm trong `[5, 10)` và khớp vừa khít | Đạt |
| 2 | `distance` và `within` giới hạn đúng | `distance 3` bắt đầu ở 6 nên không khớp; `distance 1 within 5` có cửa sổ `[4, 9)` thiếu 1 byte nên không khớp | Đạt |
| 3 | Đủ hai `ContentMatch`, vị trí đúng | sid `3110001`: `GET 0-3`, `admin 5-10`; sid `3110004`: `admin 5-10`, `HTTP/1.1 11-19` | Đạt |
| 4 | Thoát mã 0 | mã thoát `0`, đúng 2 Detection Event | Đạt |

**Ghi chú:** kế hoạch ban đầu dùng `distance 2; within 4` cho trường hợp cửa sổ thiếu 1 byte, nhưng `within 4` nhỏ hơn độ dài `admin` nên parser loại rule là `invalid` ngay lúc nạp. Bộ rule dùng `distance 1; within 5` để rule hợp lệ mà cửa sổ vẫn thiếu đúng 1 byte.

## T12: `flags` và `dsize`

### Mục tiêu

1. `flags` không modifier khớp đúng tập cờ: `flags:S` khớp SYN, không khớp SYN-ACK.
2. `dsize` so đúng kích thước payload, kể cả `dsize:0`.
3. `flags` và `dsize` trong cùng rule phải thỏa cả hai.
4. Chương trình thoát mã 0.

### Bộ rule

Header `<> any 8000` để xét packet cả hai chiều. Request GET trong pcap dài 81 byte nên rule cuối dùng `dsize:81`.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t12_flags_dsize
cat $D/test.rules
# T12: header <> port 8000 để xét packet cả hai chiều; request GET trong pcap dài 81 byte
alert tcp any any <> any 8000 (msg:"T12 flags S"; flags:S; sid:3120001; rev:1;)
alert tcp any any <> any 8000 (msg:"T12 flags SA"; flags:SA; sid:3120002; rev:1;)
alert tcp any any <> any 8000 (msg:"T12 flags A dsize 0"; flags:A; dsize:0; sid:3120003; rev:1;)
alert tcp any any <> any 8000 (msg:"T12 flags PA"; flags:PA; sid:3120004; rev:1;)
alert tcp any any <> any 8000 (msg:"T12 dsize >0"; dsize:>0; sid:3120005; rev:1;)
alert tcp any any <> any 8000 (msg:"T12 dsize 81"; dsize:81; sid:3120006; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t12_flags_dsize
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/t12
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t12_flags_dsize
tcpdump -nn -S -r $D/input.pcap
reading from file TEST/requirements3/t12_flags_dsize/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
20:02:32.638122 IP 127.0.0.1.58802 > 127.0.0.1.8000: Flags [S], seq 1218576458, win 65495, options [mss 65495,sackOK,TS val 4096689821 ecr 0,nop,wscale 10], length 0
20:02:32.638138 IP 127.0.0.1.8000 > 127.0.0.1.58802: Flags [S.], seq 2871412387, ack 1218576459, win 65483, options [mss 65495,sackOK,TS val 267731348 ecr 4096689821,nop,wscale 10], length 0
20:02:32.638150 IP 127.0.0.1.58802 > 127.0.0.1.8000: Flags [.], ack 2871412388, win 64, options [nop,nop,TS val 4096689821 ecr 267731348], length 0
20:02:32.638191 IP 127.0.0.1.58802 > 127.0.0.1.8000: Flags [P.], seq 1218576459:1218576540, ack 2871412388, win 64, options [nop,nop,TS val 4096689821 ecr 267731348], length 81
20:02:32.638196 IP 127.0.0.1.8000 > 127.0.0.1.58802: Flags [.], ack 1218576540, win 64, options [nop,nop,TS val 267731348 ecr 4096689821], length 0
20:02:32.639152 IP 127.0.0.1.8000 > 127.0.0.1.58802: Flags [P.], seq 2871412388:2871412573, ack 1218576540, win 64, options [nop,nop,TS val 267731349 ecr 4096689821], length 185
20:02:32.639179 IP 127.0.0.1.58802 > 127.0.0.1.8000: Flags [.], ack 2871412573, win 64, options [nop,nop,TS val 4096689822 ecr 267731349], length 0
20:02:32.639206 IP 127.0.0.1.8000 > 127.0.0.1.58802: Flags [P.], seq 2871412573:2871413033, ack 1218576540, win 64, options [nop,nop,TS val 267731349 ecr 4096689822], length 460
20:02:32.639212 IP 127.0.0.1.58802 > 127.0.0.1.8000: Flags [.], ack 2871413033, win 64, options [nop,nop,TS val 4096689822 ecr 267731349], length 0
20:02:32.639250 IP 127.0.0.1.8000 > 127.0.0.1.58802: Flags [F.], seq 2871413033, ack 1218576540, win 64, options [nop,nop,TS val 267731349 ecr 4096689822], length 0
20:02:32.639343 IP 127.0.0.1.58802 > 127.0.0.1.8000: Flags [F.], seq 1218576540, ack 2871413034, win 64, options [nop,nop,TS val 4096689822 ecr 267731349], length 0
20:02:32.639374 IP 127.0.0.1.8000 > 127.0.0.1.58802: Flags [.], ack 1218576541, win 64, options [nop,nop,TS val 267731349 ecr 4096689822], length 0
```

`-S` in sequence number tuyệt đối. Pcap có SYN, SYN-ACK, 5 ACK không payload, 3 PSH-ACK có payload 81, 185, 460 byte và 2 FIN-ACK.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=72 avg_candidates=6.0 rules_indexed=6 matches_total=14 detections_written=14 rule_errors=0
0
```

Lệnh 2, ghép `tcp_flags`, `payload_len` từng packet với sid khớp:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python -c "
import json
matched = {}
for line in open('$D/detections.jsonl'):
    d = json.loads(line)
    matched.setdefault(d['packet_id'], []).append(d['sid'])
for line in open('$D/events.jsonl'):
    e = json.loads(line)
    print(e['packet_id'], e['tcp_flags'], e['payload_len'], matched.get(e['packet_id'], []))
"
1 SYN 0 [3120001]
2 SYN-ACK 0 [3120002]
3 ACK 0 [3120003]
4 PSH-ACK 81 [3120004, 3120005, 3120006]
5 ACK 0 [3120003]
6 PSH-ACK 185 [3120004, 3120005]
7 ACK 0 [3120003]
8 PSH-ACK 460 [3120004, 3120005]
9 ACK 0 [3120003]
10 FIN-ACK 0 []
11 FIN-ACK 0 []
12 ACK 0 [3120003]
```

### T12 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | `flags` so đúng tập cờ | `flags:S` chỉ khớp SYN packet 1, không khớp SYN-ACK packet 2; `flags:SA` chỉ khớp packet 2; `flags:PA` khớp 3 packet PSH-ACK 4, 6, 8 | Đạt |
| 2 | `dsize` so đúng kích thước | `dsize:>0` khớp packet 4, 6, 8; `dsize:81` chỉ khớp GET packet 4 | Đạt |
| 3 | `flags` kết hợp `dsize` | `flags:A; dsize:0` khớp 5 ACK không payload 3, 5, 7, 9, 12; không khớp PSH-ACK có payload và FIN-ACK | Đạt |
| 4 | Thoát mã 0 | mã thoát `0`, 14 Detection Event; 2 FIN-ACK không khớp rule nào | Đạt |

## T13: Một event khớp nhiều rule

### Mục tiêu

1. Engine không dừng ở rule khớp đầu tiên: packet GET có một Detection Event cho mỗi rule khớp.
2. Các rule khớp nằm ở 3 bucket khác nhau của indexer: port đơn, any, `ip`.
3. Rule không khớp không sinh Detection Event.
4. `Matches by sid` trong log khớp số dòng `detections.jsonl`.
5. Chương trình thoát mã 0.

### Bộ rule

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t13_multi_match
cat $D/test.rules
# T13: 3 rule cùng khớp packet GET, nằm ở 3 bucket khác nhau của indexer (exact, any, ip), 1 rule đối chứng
alert tcp any any -> any 8000 (msg:"T13 R1 exact port 8000 GET"; content:"GET"; sid:3130001; rev:1;)
alert tcp any any -> any any (msg:"T13 R2 any to_server established"; flow:to_server,established; sid:3130002; rev:1;)
alert ip any any -> 127.0.0.1 any (msg:"T13 R3 ip HTTP/1.1"; content:"HTTP/1.1"; sid:3130003; rev:1;)
alert tcp any any -> any 8000 (msg:"T13 R4 POST never matches"; content:"POST"; sid:3130004; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t13_multi_match
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl -s -o /dev/null http://127.0.0.1:8000/t13
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t13_multi_match
tcpdump -nn -A -r $D/input.pcap | grep -a "GET "
reading from file TEST/requirements3/t13_multi_match/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
m.nt....GET /t13 HTTP/1.1
```

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=48 avg_candidates=4.0 rules_indexed=4 matches_total=6 detections_written=6 rule_errors=0
0
```

Lệnh 2, in Detection Event và đếm theo sid:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, sid, msg, matches}' $D/detections.jsonl
grep "Matches by sid" $D/run_log.txt
jq -s 'group_by(.sid) | map({sid: .[0].sid, count: length})' -c $D/detections.jsonl
{"packet_id":3,"sid":3130002,"msg":"T13 R2 any to_server established","matches":[]}
{"packet_id":4,"sid":3130001,"msg":"T13 R1 exact port 8000 GET","matches":[{"content":"GET","buffer":"payload","start":0,"end":3}]}
{"packet_id":4,"sid":3130002,"msg":"T13 R2 any to_server established","matches":[]}
{"packet_id":4,"sid":3130003,"msg":"T13 R3 ip HTTP/1.1","matches":[{"content":"HTTP/1.1","buffer":"payload","start":9,"end":17}]}
{"packet_id":7,"sid":3130002,"msg":"T13 R2 any to_server established","matches":[]}
{"packet_id":9,"sid":3130002,"msg":"T13 R2 any to_server established","matches":[]}
2026-11-02 20:47:41,954 INFO idscore.cli: Matches by sid: 3130001=1 3130002=4 3130003=1
[{"sid":3130001,"count":1},{"sid":3130002,"count":4},{"sid":3130003,"count":1}]
```

### T13 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Không dừng ở rule khớp đầu tiên | packet GET 4 có 3 dòng cùng `packet_id` của sid `3130001`, `3130002`, `3130003`, theo thứ tự nạp | Đạt |
| 2 | 3 rule ở 3 bucket khác nhau | `3130001` bucket exact 8000, `3130002` bucket tcp any, `3130003` nhóm `ip` | Đạt |
| 3 | Rule không khớp không sinh Detection Event | `3130004` content `POST` không có dòng nào | Đạt |
| 4 | `Matches by sid` khớp số dòng | `3130001=1 3130002=4 3130003=1`, tổng 6 bằng 6 dòng `detections.jsonl` | Đạt |
| 5 | Thoát mã 0 | mã thoát `0` | Đạt |

**Ghi chú:** R2 `flow:to_server,established` không có content nên còn khớp 3 ACK của client ở packet 3, 7, 9. Ba dòng này không ảnh hưởng tiêu chí của testcase là packet GET có đủ 3 Detection Event.

## T14: Detection Event

### Mục tiêu

1. Detection Event có đủ field theo mục 4.6: `timestamp`, `sid`, `rev`, `msg`, `priority`, `classtype`, 5-tuple, `protocol`, `application_protocol`, `flow_id`, thông tin match.
2. `timestamp`, 5-tuple và `protocol` trùng event cùng `packet_id` trong `events.jsonl`.
3. `flow_id` có trong `flows.jsonl`.
4. `matches` ghi `content="../"` với vị trí đúng.
5. Chương trình thoát mã 0.

### Bộ rule

Một rule theo ví dụ của đề.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t14_detection_event
cat $D/test.rules
# T14: rule theo ví dụ của đề, phát hiện path traversal
alert tcp any any -> any 8000 (msg:"Directory traversal detected"; flow:to_server,established; content:"../"; classtype:web-application-attack; priority:1; sid:3140001; rev:1;)
```

### Tạo pcap

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements3/t14_detection_event
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
curl --path-as-is -s -o /dev/null "http://127.0.0.1:8000/../../etc/passwd"
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements3/t14_detection_event
tcpdump -nn -A -r $D/input.pcap | grep -a "GET "
reading from file TEST/requirements3/t14_detection_event/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
..54....GET /../../etc/passwd HTTP/1.1
```

`--path-as-is` giữ nguyên `../` trong request thay vì để curl tự rút gọn path.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --detection-output $D/detections.jsonl --log-file $D/run_log.txt --config $D/config.yaml
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
Detection: events_evaluated=12 events_skipped=0 events_failed=0 candidates_total=12 avg_candidates=1.0 rules_indexed=1 matches_total=1 detections_written=1 rule_errors=0
0
```

Lệnh 2, in đủ field của Detection Event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq . $D/detections.jsonl
{
  "packet_id": 4,
  "timestamp": 1793624568.839587,
  "sid": 3140001,
  "rev": 1,
  "msg": "Directory traversal detected",
  "priority": 1,
  "classtype": "web-application-attack",
  "src_ip": "127.0.0.1",
  "src_port": 58568,
  "dst_ip": "127.0.0.1",
  "dst_port": 8000,
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "flow_id": "e40b0a8faabe93ea",
  "matches": [
    {
      "content": "../",
      "buffer": "payload",
      "start": 5,
      "end": 8
    }
  ]
}
```

Lệnh 3, đối chiếu với event cùng `packet_id` và với flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c 'select(.packet_id == 4) | {packet_id, timestamp, src_ip, src_port, dst_ip, dst_port, transport_protocol, app_protocol, flow_id}' $D/events.jsonl
jq -c '{flow_id, protocol, application_protocol, packet_count, state}' $D/flows.jsonl
{"packet_id":4,"timestamp":1793624568.839587,"src_ip":"127.0.0.1","src_port":58568,"dst_ip":"127.0.0.1","dst_port":8000,"transport_protocol":"TCP","app_protocol":"HTTP","flow_id":"e40b0a8faabe93ea"}
{"flow_id":"e40b0a8faabe93ea","protocol":"TCP","application_protocol":"HTTP","packet_count":12,"state":"CLOSED"}
```

### T14 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Đủ field mục 4.6 | 15 key: `packet_id`, `timestamp`, `sid`, `rev`, `msg`, `priority`, `classtype`, 5-tuple, `protocol`, `application_protocol`, `flow_id`, `matches` | Đạt |
| 2 | Trùng event cùng `packet_id` | `timestamp` `1793624568.839587`, `127.0.0.1:58568 -> 127.0.0.1:8000`, `TCP`, `HTTP` trùng event packet 4 | Đạt |
| 3 | `flow_id` có trong `flows.jsonl` | `e40b0a8faabe93ea` trùng `flow_id` của event và của flow duy nhất | Đạt |
| 4 | `matches` đúng | `content` `../`, `buffer` `payload`, `start=5, end=8`, đúng lần xuất hiện đầu tiên trong `GET /../../etc/passwd` | Đạt |
| 5 | Thoát mã 0 | mã thoát `0`, 1 Detection Event | Đạt |

# TESTCASE

## T01: HTTP URL Decode

### Mục tiêu cần kiểm chứng:

1. Decoder decode đúng percent-encoding trong URI, ví dụ `%27%20OR%201%3D1` thành `' OR 1=1`.
2. Phần query được decode theo kiểu `application/x-www-form-urlencoded`, tức `+` thành dấu cách.
3. Field `app.uri` giữ nguyên chuỗi gốc chưa decode, bản decode nằm ở `uri_decoded`.
4. `decode_status` là `ok`.
5. Chương trình thoát mã 0.

### Yêu cầu file pcap:

**Yêu cầu pcap:** một kết nối HTTP có request GET mà URI chứa percent-encoding ở cả path lẫn query, có thêm dấu `+` trong query.

**Cách tạo:** dùng server cục bộ trên `lo`, mở 3 terminal trong thư mục `ids`.

**Yêu cầu pcap:** một kết nối HTTP có request GET mà URI chứa percent-encoding ở cả path lẫn query, có thêm dấu `+` trong query.

**Cách tạo:** dùng server cục bộ trên `lo`, mở 3 terminal trong thư mục `ids`.

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
mkdir -p TEST/requirements2/t01_http_url_decodesudo tcpdump -i lo -nn -Z $USER -w TEST/requirements2/t01_http_url_decode/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request. 

```bash
curl --path-as-is "http://127.0.0.1:8000/admin%2Fpanel/login.php?user=admin%27%20OR%201%3D1--&pass=a+b"
```

Server trả 404 là bình thường, chỉ cần có request. Sau đó `Ctrl+C` ở terminal 2 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ tcpdump -nn -A -r TEST/requirements2/t01_http_url_decode/input.pcap | grep "GET "
reading from file TEST/requirements2/t01_http_url_decode/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
....99..GET /admin%2Fpanel/login.php?user=admin%27%20OR%201%3D1--&pass=a+b HTTP/1.1
```

Dòng GET chưa được decode → còn nguyên `%27%20OR%201%3D1` và `a+b`

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t01_http_url_decode
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in các field cần kiểm tra của event có URI:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python -c "
import json
for l in open('$D/events.jsonl'):
    e = json.loads(l)
    uri = (e.get('app') or {}).get('uri')
    if uri:
        print('packet_id   :', e['packet_id'])
        print('uri gốc     :', uri)
        print('uri_decoded :', e.get('uri_decoded'))
        print('decode_status:', e.get('decode_status'))
"
packet_id   : 4
uri gốc     : /admin%2Fpanel/login.php?user=admin%27%20OR%201%3D1--&pass=a+b
uri_decoded : /admin/panel/login.php?user=admin' OR 1=1--&pass=a b
decode_status: ok
```

### T01 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Percent-encoding trong URI được decode đúng | `%27%20OR%201%3D1` thành `' OR 1=1`, `%2F` thành `/` | Đạt |
| 2 | Query decode theo `application/x-www-form-urlencoded` | `pass=a+b` thành `pass=a b` | Đạt |
| 3 | `app.uri` giữ nguyên chuỗi gốc | `/admin%2Fpanel/login.php?user=admin%27%20OR%201%3D1--&pass=a+b` | Đạt |
| 4 | `decode_status` là `ok` | `ok` | Đạt |
| 5 | Chương trình không crash, thoát mã 0 | mã thoát `0`, 12 packet OK, 1 flow | Đạt |

## T02: HTML entity

*HTML entity là cách biểu diễn các ký tự đặc biệt trong HTML bằng một chuỗi mã thay vì viết trực tiếp ký tự đó.*

### Mục tiêu

1. Body HTTP có `Content-Type: text/html` được decode HTML entity đúng, gồm entity tên như `&lt;`, `&quot;`, `&amp;` và entity số như `&#39;`, `&#x41;`.
2. `app.body` giữ nguyên bản gốc, bản decode nằm ở `body_decoded`.
3. `decode_status` là `ok`.
4. Chương trình không crash, thoát mã 0.

### Tạo pcap

Header và body của response phải nằm chung một TCP segment, vì chưa có TCP reassembly nên body nằm ở segment riêng sẽ không biết `Content-Type` để decode. Do đó dùng script serve_html.py gửi cả response bằng một lần `sendall` thay cho `python -m http.server`.

Terminal 1, bắt packet:

```bash
D=TEST/requirements2/t02_html_entity
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 2, chạy server:

```bash
python TEST/requirements2/t02_html_entity/serve_html.py
```

Terminal 3, gửi request:

```bash
curl http://127.0.0.1:8000/page.html
```

Sau khi curl in ra body, `Ctrl+C` ở terminal 1 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ tcpdump -nn -A -r TEST/requirements2/t02_html_entity/input.pcap | grep -A6 "HTTP/1.1 200"
reading from file TEST/requirements2/t02_html_entity/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
.V=.    YZwHTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 84
Connection: close

<p>&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt; &amp; &#39;OR&#39; &#x41;</p>
21:10:55.515109 IP 127.0.0.1.38696 > 127.0.0.1.8000: Flags [.], ack 183, win 64, options [nop,nop,TS val 156850807 ecr 3914743174], length 0
```

Header `Content-Type: text/html` và body chứa entity nằm trong cùng một packet.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t02_html_entity
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 10 (OK 10, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in các field cần kiểm tra của event có body:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python -c "
import json
for l in open('$D/events.jsonl'):
    e = json.loads(l)
    app = e.get('app') or {}
    if app.get('body'):
        print('packet_id    :', e['packet_id'])
        print('content-type :', (app.get('headers') or {}).get('content-type'))
        print('body gốc     :', app.get('body'))
        print('body_decoded :', e.get('body_decoded'))
        print('decode_status:', e.get('decode_status'))
"
packet_id    : 6
content-type : text/html; charset=utf-8
body gốc     : <p>&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt; &amp; &#39;OR&#39; &#x41;</p>
body_decoded : <p><script>alert("xss")</script> & 'OR' A</p>
decode_status: ok
```

### T02 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Entity tên được decode đúng | `&lt;` `&gt;` `&quot;` `&amp;` thành `<` `>` `"` `&` | Đạt |
| 2 | Entity số được decode đúng | `&#39;` thành `'`, `&#x41;` thành `A` | Đạt |
| 3 | Chỉ decode khi `Content-Type` là HTML | `text/html; charset=utf-8`, có tham số charset vẫn nhận đúng | Đạt |
| 4 | `app.body` giữ nguyên chuỗi gốc | body gốc còn nguyên các entity | Đạt |
| 5 | `decode_status` là `ok` | `ok` | Đạt |
| 6 | Chương trình không crash, thoát mã 0 | mã thoát `0`, 10 packet OK, 1 flow | Đạt |

## T03: SMTP Base64 và Quoted-Printable

*MIME dùng header `Content-Transfer-Encoding` để báo body được mã hóa thế nào. Base64 biểu diễn dữ liệu nhị phân bằng 64 ký tự ASCII, còn Quoted-Printable giữ nguyên ký tự ASCII và biểu diễn byte đặc biệt dưới dạng `=XX`, dấu `=` ở cuối dòng là soft line break.*

### Mục tiêu

1. Body MIME có `Content-Transfer-Encoding: base64` được decode đúng.
2. Body MIME có `Content-Transfer-Encoding: quoted-printable` được decode đúng, gồm `=XX`, `=3D` và soft line break.
3. Packet thuộc pha DATA được phân loại `message_type` là `data`.
4. `app.payload_text` giữ nguyên bản gốc, bản decode nằm ở `body_decoded`, kèm `decode_status`.
5. Hai mail trong cùng một phiên SMTP được decode độc lập theo encoding riêng của từng mail.
6. Chương trình không crash, thoát mã 0.

### Tạo pcap

Header và body của mỗi mail phải nằm chung một TCP segment để IDS đọc được `Content-Transfer-Encoding` trước khi decode body. Dùng script send_mime.py gửi hai mail trong cùng một phiên SMTP bằng `smtplib`: một mail Base64, một mail Quoted-Printable.

Terminal 1, chạy SMTP server:

```bash
sudo $(which python) -m aiosmtpd -n -l 127.0.0.1:25
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements2/t03_smtp_mime
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 25'
```

Terminal 3, gửi mail:

```bash
python TEST/requirements2/t03_smtp_mime/send_mime.py
```

Server in ra hai mail đã nhận. Sau đó `Ctrl+C` ở terminal 2 và terminal 1 rồi kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t03_smtp_mime
(btids) odixe@LapcuaTriet:~/ids$ tcpdump -nn -A -r $D/input.pcap | grep -B1 -A9 "Content-Transfer-Encoding"
reading from file TEST/requirements2/t03_smtp_mime/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

WGluIGNow6BvLCDEkcOieSBsw6AgdGjGsCB0aOG7rSBuZ2hp4buHbSBUMDMgQmFzZTY0Lg==
.

21:21:35.078590 IP 127.0.0.1.25 > 127.0.0.1.36212: Flags [P.], seq 154:162, ack 332, win 64, options [nop,nop,TS val 939757149 ecr 3895225089], length 8: SMTP: 250 OK
E..<..@.@.7............t        ...96.H...@.0.....
8..].,k.250 OK

21:21:35.078635 IP 127.0.0.1.36212 > 127.0.0.1.25: Flags [P.], seq 332:362, ack 162, win 64, options [nop,nop,TS val 3895225089 ecr 939757149], length 30: SMTP: mail FROM:<alice@test.local>
--
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Gi=C3=A1 tr=E1=BB=8B: 1+1=3D2, d=C3=B2ng n=C3=A0y r=E1=BA=A5t d=C3=A0i n=C3=
=AAn =C4=91=C6=B0=E1=BB=A3c ng=E1=BA=AFt b=E1=BA=B1ng soft line break c=E1=
=BB=A7a Quoted-Printable.
.

21:21:35.079181 IP 127.0.0.1.25 > 127.0.0.1.36212: Flags [P.], seq 215:223, ack 761, win 64, options [nop,nop,TS val 939757150 ecr 3895225090], length 8: SMTP: 250 OK
E..<..@.@.7............t        ...96.....@.0.....
8..^.,k.250 OK
```

Với mỗi mail, header `Content-Transfer-Encoding`, body đã mã hóa và dòng kết thúc `.` nằm trong cùng một packet.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 32 (OK 32, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in các event thuộc pha DATA:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq '{packet_id, message_type: .app.message_type, payload_text: .app.payload_text, body_decoded, decode_status}' <(jq -c 'select(.app.message_type == "data")' $D/events.jsonl)
{
  "packet_id": 18,
  "message_type": "data",
  "payload_text": "From: alice@test.local\r\nTo: bob@test.local\r\nSubject: t03 base64\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nWGluIGNow6BvLCDEkcOieSBsw6AgdGjGsCB0aOG7rSBuZ2hp4buHbSBUMDMgQmFzZTY0Lg==\r\n.\r\n",
  "body_decoded": "Xin chào, đây là thư thử nghiệm T03 Base64.",
  "decode_status": "ok"
}
{
  "packet_id": 26,
  "message_type": "data",
  "payload_text": "From: alice@test.local\r\nTo: bob@test.local\r\nSubject: t03 quoted-printable\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nGi=C3=A1 tr=E1=BB=8B: 1+1=3D2, d=C3=B2ng n=C3=A0y r=E1=BA=A5t d=C3=A0i n=C3=\r\n=AAn =C4=91=C6=B0=E1=BB=A3c ng=E1=BA=AFt b=E1=BA=B1ng soft line break c=E1=\r\n=BB=A7a Quoted-Printable.\r\n.\r\n",
  "body_decoded": "Giá trị: 1+1=2, dòng này rất dài nên được ngắt bằng soft line break của Quoted-Printable.\r\n",
  "decode_status": "ok"
}
```

Lệnh 3, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{flow_id, protocol, application_protocol, packet_count, state, end_reason}' $D/flows.jsonl
{"flow_id":"e034813dce5c4ba9","protocol":"TCP","application_protocol":"SMTP","packet_count":32,"state":"CLOSED","end_reason":"end_of_capture"}
```

### T03 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Base64 được decode đúng | packet 18: `Xin chào, đây là thư thử nghiệm T03 Base64.` | Đạt |
| 2 | Quoted-Printable được decode đúng | packet 26: `=3D` thành `=`, `=C3=A1` thành `á`, soft line break được nối lại, kể cả khi cắt giữa một ký tự UTF-8 như `n=C3=` và `=AAn` | Đạt |
| 3 | Packet pha DATA được phân loại đúng | `message_type` của packet 18 và 26 là `data` | Đạt |
| 4 | `payload_text` giữ nguyên bản gốc, có `body_decoded` và `decode_status` | chuỗi mã hóa còn nguyên, `decode_status` là `ok` ở cả hai mail | Đạt |
| 5 | Hai mail cùng phiên decode độc lập theo encoding riêng | mail 1 dùng Base64, mail 2 dùng Quoted-Printable, cả hai đều decode đúng trong cùng 1 flow SMTP | Đạt |
| 6 | Chương trình không crash, thoát mã 0 | mã thoát `0`, 32 packet OK, 1 flow, `packet_count` 32 khớp số event | Đạt |

**Ghi chú:** `body_decoded` của Base64 không có `\r\n` cuối, còn Quoted-Printable giữ `\r\n` cuối. Base64 bỏ toàn bộ khoảng trắng trước khi decode, còn Quoted-Printable giữ xuống dòng vì đó là một phần nội dung. 

## T04: Invalid bytes

*UTF-8 là cách mã hóa ký tự thành 1 đến 4 byte theo quy tắc cố định. Byte sequence không theo quy tắc đó, như byte `ff`, `fe` hoặc ký tự nhiều byte bị cắt thiếu, là invalid UTF-8 và không decode trực tiếp thành chuỗi được.*

### Mục tiêu

1. Payload HTTP chứa byte không phải UTF-8 hợp lệ không làm chương trình crash.
2. Byte lỗi được thay bằng ký tự `�`, phần hợp lệ như `café` vẫn decode đúng.
3. Event bị đánh dấu `body_text_status` và `decode_status` là `partial`.
4. Request hợp lệ gửi ngay sau đó vẫn được xử lý bình thường với `decode_status` là `ok`, chứng tỏ chương trình tiếp tục chạy.
5. Chương trình thoát mã 0.

### Tạo pcap

Body POST gồm ba loại byte: `caf\xc3\xa9` là UTF-8 hợp lệ, `\xff\xfe` là byte không bao giờ hợp lệ trong UTF-8, `\xe1\xbb` là ký tự 3 byte bị cắt thiếu byte cuối. 

Dùng `Content-Type: text/plain` để decoder không áp form decode lên body, chỉ kiểm tra phần decode ký tự.

Terminal 1, chạy server:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python -m http.server 8000 --bind 127.0.0.1
Serving HTTP on 127.0.0.1 port 8000 (http://127.0.0.1:8000/) ...
127.0.0.1 - - [12/Oct/2026 21:26:52] code 501, message Unsupported method ('POST')
127.0.0.1 - - [12/Oct/2026 21:26:52] "POST /upload HTTP/1.1" 501 -
127.0.0.1 - - [12/Oct/2026 21:26:52] code 404, message File not found
127.0.0.1 - - [12/Oct/2026 21:26:52] "GET /after HTTP/1.1" 404 -
^C
Keyboard interrupt received, exiting.
```

Terminal 2, tạo body và bắt packet:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t04_invalid_bytes
mkdir -p $D
printf 'msg=caf\xc3\xa9 bad=\xff\xfe cut=\xe1\xbb' > $D/body.bin
xxd $D/body.bin
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
00000000: 6d73 673d 6361 66c3 a920 6261 643d fffe  msg=caf.. bad=..
00000010: 2063 7574 3de1 bb                         cut=..
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C24 packets captured
48 packets received by filter
0 packets dropped by kernel
```

`xxd` cho thấy body có đúng các byte `c3 a9`, `ff fe` và `e1 bb` như thiết kế.

Terminal 3, gửi request chứa byte lỗi rồi một request hợp lệ:

```bash
(btids) odixe@LapcuaTriet:~/ids$ curl -H "Content-Type: text/plain" --data-binary @TEST/requirements2/t04_invalid_bytes/body.bin http://127.0.0.1:8000/upload
curl http://127.0.0.1:8000/after
```

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t04_invalid_bytes
python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 24 (OK 24, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 2, flows timed out: 0
0
```

Lệnh 2, in các event HTTP request:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c 'select(.app.uri != null) | {packet_id, method: .app.method, uri: .app.uri, body: .app.body, body_text_status: .app.body_text_status, decode_status, parse_status, errors}' $D/events.jsonl
{"packet_id":4,"method":"POST","uri":"/upload","body":"msg=café bad=�� cut=�","body_text_status":"partial","decode_status":"partial","parse_status":"OK","errors":[]}
{"packet_id":16,"method":"GET","uri":"/after","body":"","body_text_status":"ok","decode_status":"ok","parse_status":"OK","errors":[]}
```

Lệnh 3, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{flow_id, application_protocol, packet_count, state}' $D/flows.jsonl
{"flow_id":"f2f7d9dddd1e6a11","application_protocol":"HTTP","packet_count":12,"state":"CLOSED"}
{"flow_id":"58387a5610ae2ba5","application_protocol":"HTTP","packet_count":12,"state":"CLOSED"}
```

### T04 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Byte không hợp lệ không làm chương trình crash | 24 packet đều được xử lý, không có lỗi trong `errors` | Đạt |
| 2 | Byte lỗi được thay bằng `�`, phần hợp lệ vẫn decode đúng | `café` giữ nguyên, `ff fe` thành `��`, `e1 bb` bị cắt thành `�` | Đạt |
| 3 | Event bị đánh dấu `partial` | packet 4: `body_text_status` và `decode_status` đều là `partial` | Đạt |
| 4 | Chương trình tiếp tục xử lý request sau đó | packet 16 `GET /after` có `decode_status` là `ok`, 2 flow HTTP đều `CLOSED` với 12 packet | Đạt |
| 5 | Chương trình thoát mã 0 | mã thoát `0` | Đạt |

**Ghi chú:** `parse_status` của packet 4 vẫn là `OK` vì lỗi nằm ở tầng decode ký tự, không phải cấu trúc HTTP. Hai trạng thái được tách riêng nên Detection Engine biết packet parse đúng nhưng nội dung có byte lỗi.

## T05: Normalization

*Normalization là đưa cùng một giá trị được viết theo nhiều cách khác nhau về một dạng biểu diễn thống nhất, để các module phía sau so sánh và đối chiếu được mà không phải tự xử lý từng biến thể.*

### Mục tiêu

1. HTTP header name khác kiểu chữ được đưa về chữ thường, header trùng tên khác kiểu chữ được gộp thành một.
2. Giá trị `Host` được chuẩn hóa: chữ thường, bỏ dấu `.` cuối domain, giữ port.
3. URI path được chuẩn hóa an toàn: xử lý `.`, `..`, `//`, giữ nguyên kiểu chữ của path và phần query, `app.uri` gốc không đổi.
4. Domain trong DNS question và answer được đưa về chữ thường, bỏ dấu `.` cuối.
5. Tên protocol, IP và timestamp khác format được đưa về dạng thống nhất.
6. Chương trình không crash, thoát mã 0.

### Tạo input

Input gồm hai phần:

- **Pcap thật:** một DNS query/response tới 8.8.8.8 với domain viết hoa lẫn lộn, và một HTTP request có header khác kiểu chữ cùng URI chứa `.`, `..`, `//`.
- **Event giả:** parser của bài 1 luôn sinh tên protocol in hoa, IP và timestamp đúng format, nên không tạo được dữ liệu lệch format từ pcap. Dùng script fake_event.py đưa một event lệch format thẳng vào `Preprocessor` để kiểm tra mục 1 và mục 5.

Terminal 1, bắt packet trên `eth0`:

```bash
D=TEST/requirements2/t05_normalization
sudo tcpdump -i eth0 -nn -Z $USER -w $D/input.pcap '(udp port 53 and host 8.8.8.8) or tcp port 80'
```

Terminal 2, gửi DNS query và HTTP request:

```bash
(btids) odixe@LapcuaTriet:~/ids$ dig @8.8.8.8 +tries=1 WWW.ExAmPlE.CoM
curl --path-as-is -H "HOST: WWW.Example.COM.:80" -H "X-Test: one" -H "x-TEST: two" "http://example.com/A/./b/../c//d/?q=1"

; <<>> DiG 9.18.39-0ubuntu0.24.04.7-Ubuntu <<>> @8.8.8.8 +tries=1 WWW.ExAmPlE.CoM
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8188
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;WWW.ExAmPlE.CoM.               IN      A

;; ANSWER SECTION:
WWW.ExAmPlE.CoM.        300     IN      A       172.66.147.243
WWW.ExAmPlE.CoM.        300     IN      A       104.20.23.154

;; Query time: 40 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
;; WHEN: Mon Oct 12 21:34:06 +07 2026
;; MSG SIZE  rcvd: 76

<!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=data:,><meta name=viewport content="width=device-width,initial-scale=1"><title>Example Domain</title><style>html{color-scheme:light dark;background:light-dark(#eee,#222)}body{font:16px/1.6 system-ui,sans-serif;max-width:26em;margin:auto;padding:25vh 2em 2em;text-align:center}</style></head><body><p>This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.</p><script src=/s.js></script></body></html>
```

DNS server trả về domain giữ nguyên kiểu chữ `WWW.ExAmPlE.CoM.` ở cả question và answer

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t05_normalization
(btids) odixe@LapcuaTriet:~/ids$ tcpdump -nn -r $D/input.pcap 'udp port 53'
tcpdump -nn -A -r $D/input.pcap 'tcp port 80' | grep -i -E "^(GET|HOST|X-TEST)"
reading from file TEST/requirements2/t05_normalization/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:34:06.221785 IP 172.18.124.92.50366 > 8.8.8.8.53: 8188+ [1au] A? WWW.ExAmPlE.CoM. (56)
21:34:06.262308 IP 8.8.8.8.53 > 172.18.124.92.50366: 8188$ 2/0/1 A 172.66.147.243, A 104.20.23.154 (76)
reading from file TEST/requirements2/t05_normalization/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
Host: WWW.Example.COM.:80
X-Test: one
x-TEST: two

```

Dữ liệu gốc trong pcap còn nguyên kiểu chữ: domain `WWW.ExAmPlE.CoM`, header `HOST`, `X-Test`, `x-TEST` và URI chưa chuẩn hóa.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 2, flows timed out: 0
0
```

Lệnh 2, in event DNS:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c 'select(.app_protocol == "DNS") | {packet_id, questions: [.app.questions[]?.name], answers: [.app.answers[]? | {name, rdata}], preprocess_status}' $D/events.jsonl
{"packet_id":1,"questions":["www.example.com"],"answers":[],"preprocess_status":"valid"}
{"packet_id":2,"questions":["www.example.com"],"answers":[{"name":"www.example.com","rdata":"172.66.147.243"},{"name":"www.example.com","rdata":"104.20.23.154"}],"preprocess_status":"valid"}
```

Lệnh 3, in event HTTP request:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c 'select(.app.method != null) | {packet_id, uri: .app.uri, uri_normalized, headers: .app.headers, preprocess_status}' $D/events.jsonl
{"packet_id":6,"uri":"/A/./b/../c//d/?q=1","uri_normalized":"/A/c/d/?q=1","headers":{"host":"www.example.com:80","user-agent":"curl/8.5.0","accept":"*/*","x-test":"one, two"},"preprocess_status":"valid"}
```

Lệnh 4, chạy event giả:

```bash
(btids) odixe@LapcuaTriet:~/ids$ PYTHONPATH=. python $D/fake_event.py
before: {"packet_id": 1, "timestamp": "1790604355.5", "source": "fake", "source_type": "pcap", "src_ip": " 10.0.0.1 ", "dst_ip": "10.0.0.2", "ip_version": 4, "ip_proto": 6, "src_port": 40000, "dst_port": 80, "transport_protocol": " tcp ", "tcp_flags": "PSH-ACK", "app_protocol": "http", "app": {"message_type": "request", "method": "GET", "uri": "/A/./b/../c//d/?q=1", "headers": {"Host": "WWW.Example.COM.:80", "X-Test": "one", "x-TEST": "two"}}, "parse_status": "OK", "errors": [], "reason": []}
after : {"packet_id": 1, "timestamp": 1790604355.5, "source": "fake", "source_type": "pcap", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "ip_version": 4, "ip_proto": 6, "src_port": 40000, "dst_port": 80, "transport_protocol": "TCP", "tcp_flags": "PSH-ACK", "app_protocol": "HTTP", "app": {"message_type": "request", "method": "GET", "uri": "/A/./b/../c//d/?q=1", "headers": {"host": "www.example.com:80", "x-test": "one, two"}}, "parse_status": "OK", "errors": [], "uri_normalized": "/A/c/d/?q=1", "preprocess_status": "valid", "processing_action": "pass", "reason": []}
```

### T05 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Header name về chữ thường, header trùng tên được gộp | pcap: `HOST`, `X-Test`, `x-TEST` thành `host`, `x-test`. Event giả: `Host`, `X-Test`, `x-TEST` thành `host` và `x-test: one, two` | Đạt |
| 2 | Giá trị `Host` được chuẩn hóa | `WWW.Example.COM.:80` thành `www.example.com:80` ở cả pcap và event giả | Đạt |
| 3 | URI path được chuẩn hóa an toàn | `/A/./b/../c//d/?q=1` thành `/A/c/d/?q=1`, chữ `A` hoa giữ nguyên, query giữ nguyên, `app.uri` gốc không đổi | Đạt |
| 4 | Domain DNS về chữ thường, bỏ dấu `.` cuối | question và cả hai answer `WWW.ExAmPlE.CoM.` thành `www.example.com` | Đạt |
| 5 | Protocol, IP, timestamp về dạng thống nhất | `tcp` thành `TCP`, `http` thành `HTTP`, `10.0.0.1` thành `10.0.0.1`, chuỗi `"1790604355.5"` thành số `1790604355.5` | Đạt |
| 6 | Chương trình không crash, thoát mã 0 | mã thoát `0`, 12 packet OK, 2 flow, mọi event `preprocess_status` là `valid` | Đạt |

## T06: Missing field

Missing field là trường hợp event thiếu một field hoặc field có giá trị `None`. Nếu không xử lý, module phía sau phải tự kiểm tra từng field trước khi dùng, dễ gây exception khi duyệt danh sách hoặc truy cập dict.

### Mục tiêu

1. Event thiếu field không bắt buộc không gây exception ở Decoder, Preprocessor và Flow Tracker.
2. Field dạng danh sách bị thiếu hoặc là `None` được điền `[]`: `errors`, `reason`, `answers` của DNS, `commands` của SMTP.
3. Field dạng dict bị thiếu hoặc là `None` được điền `{}`: `headers` của HTTP.
4. Event không có `app` vẫn giữ `app` là `null`, không bị tạo ra dict rỗng.
5. Thiếu field không bắt buộc không làm hạ trạng thái: `preprocess_status` là `valid`, `processing_action` là `pass`, event vẫn được gắn `flow_id`.
6. Chương trình thoát mã 0.

### Tạo input

Pcap thật luôn đi qua parser của bài 1, parser này đã tự điền đủ các field nên không tạo được event thiếu field từ mạng. Dùng script missing_fields.py tạo 5 event giả, mỗi event thiếu một kiểu field khác nhau, rồi cho chạy lần lượt qua `Decoder`, `Preprocessor`, `FlowTracker` giống chuỗi xử lý trong `cli.py`.

| packet_id | Event | Field bị thiếu |
| --- | --- | --- |
| 1 | HTTP request | không có `headers`, `errors` và `reason` là `None` |
| 2 | HTTP response | `headers` là `None` |
| 3 | DNS | `answers` là `None` |
| 4 | SMTP command | không có `commands` |
| 5 | UDP | không có `app` |

### Chạy và kiểm tra

`tee` lưu output vào `run_log.txt` làm bằng chứng, `PIPESTATUS[0]` lấy mã thoát của python thay vì của `tee`.

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t06_missing_field
PYTHONPATH=. python $D/missing_fields.py | tee $D/run_log.txt
echo ${PIPESTATUS[0]}
[1] HTTP request, không có headers và body
    app              : {"message_type": "request", "method": "GET", "uri": "/", "headers": {}}
    errors / reason  : [] / []
    preprocess_status: valid | action: pass
    flow_id          : 02644f1e2a82e302
[2] HTTP response, headers là None
    app              : {"message_type": "response", "status_code": 200, "headers": {}}
    errors / reason  : [] / []
    preprocess_status: valid | action: pass
    flow_id          : 02644f1e2a82e302
[3] DNS, answers là None
    app              : {"questions": [{"name": "a.com", "qtype": 1}], "answers": []}
    errors / reason  : [] / []
    preprocess_status: valid | action: pass
    flow_id          : a8bc0da4b7336ad7
[4] SMTP command, không có commands
    app              : {"message_type": "command", "commands": []}
    errors / reason  : [] / []
    preprocess_status: valid | action: pass
    flow_id          : db07fcc89129925c
[5] UDP, không có app
    app              : null
    errors / reason  : [] / []
    preprocess_status: valid | action: pass
    flow_id          : 9a21bb48d4e4a3a7
flows: 4
0
```

### T06 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Không exception ở cả ba module | 5 event đều chạy hết Decoder, Preprocessor, FlowTracker, script in đủ kết quả | Đạt |
| 2 | Field danh sách thiếu hoặc `None` thành `[]` | packet 1: `errors`, `reason` từ `None` thành `[]`. packet 3: `answers` thành `[]`. packet 4: thêm `commands: []` | Đạt |
| 3 | Field dict thiếu hoặc `None` thành `{}` | packet 1: thêm `headers: {}`. packet 2: `headers` từ `None` thành `{}` | Đạt |
| 4 | Event không có `app` giữ `null` | packet 5: `app` là `null` | Đạt |
| 5 | Không hạ trạng thái, vẫn gắn flow | cả 5 event `valid` và `pass`, đều có `flow_id`. packet 1 và 2 cùng 5-tuple nên chung flow `02644f1e2a82e302`, tổng `flows: 4` | Đạt |
| 6 | Chương trình thoát mã 0 | mã thoát `0` | Đạt |

## T07: TCP handshake

TCP handshake là quá trình 3 bước mở kết nối TCP: client gửi SYN, server trả SYN/ACK, client gửi ACK. Sau bước thứ ba, hai bên đã thống nhất sequence number và kết nối chuyển sang trạng thái ESTABLISHED.

### Mục tiêu

1. Ba packet SYN, SYN/ACK, ACK được gom vào đúng 1 flow, cùng `flow_id`.
2. Direction đúng: SYN và ACK là `forward` từ client, SYN/ACK là `backward` từ server.
3. Flow có `state` là `ESTABLISHED` sau ACK cuối của handshake.
4. Bộ đếm cờ đúng: `syn_count` 2, `ack_count` 2, `fin_count` 0, `rst_count` 0.
5. Packet không có payload vẫn được tính: `packet_count` 3, `fwd_packet_count` 2, `bwd_packet_count` 1.
6. Chương trình thoát mã 0.

### Tạo pcap

Pcap chỉ chứa đúng 3 packet đầu của một kết nối TCP. Dùng `tcpdump -c 3` để tự dừng sau 3 packet, phần trao đổi dữ liệu và đóng kết nối phía sau không bị bắt.

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements2/t07_tcp_handshake
mkdir -p $D
sudo tcpdump -i lo -nn -S -c 3 -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, mở kết nối:

```bash
(btids) odixe@LapcuaTriet:~/ids$ curl -s -o /dev/null http://127.0.0.1:8000/
```

Kiểm tra pcap: 

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t07_tcp_handshake
tcpdump -nn -S -r $D/input.pcap
reading from file TEST/requirements2/t07_tcp_handshake/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:42:39.590833 IP 127.0.0.1.39198 > 127.0.0.1.8000: Flags [S], seq 3494912531, win 65495, options [mss 65495,sackOK,TS val 2897236041 ecr 0,nop,wscale 10], length 0
21:42:39.590845 IP 127.0.0.1.8000 > 127.0.0.1.39198: Flags [S.], seq 1838209599, ack 3494912532, win 65483, options [mss 65495,sackOK,TS val 2041455956 ecr 2897236041,nop,wscale 10], length 0
21:42:39.590852 IP 127.0.0.1.39198 > 127.0.0.1.8000: Flags [.], ack 1838209600, win 64, options [nop,nop,TS val 2897236041 ecr 2041455956], length 0
```

Pcap có đúng 3 packet `[S]`, `[S.]`, `[.]`, đều `length 0`. Ack của SYN/ACK là `3494912532` bằng seq của SYN cộng 1, ack của ACK cuối là `1838209600` bằng seq của SYN/ACK cộng 1, đúng một lần handshake hoàn chỉnh.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 3 (OK 3, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, src: "\(.src_ip):\(.src_port)", dst: "\(.dst_ip):\(.dst_port)", tcp_flags, payload_len, flow_id, direction}' $D/events.jsonl
{"packet_id":1,"src":"127.0.0.1:39198","dst":"127.0.0.1:8000","tcp_flags":"SYN","payload_len":0,"flow_id":"2cd873f3effb0c51","direction":"forward"}
{"packet_id":2,"src":"127.0.0.1:8000","dst":"127.0.0.1:39198","tcp_flags":"SYN-ACK","payload_len":0,"flow_id":"2cd873f3effb0c51","direction":"backward"}
{"packet_id":3,"src":"127.0.0.1:39198","dst":"127.0.0.1:8000","tcp_flags":"ACK","payload_len":0,"flow_id":"2cd873f3effb0c51","direction":"forward"}
```

Lệnh 3, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{flow_id, protocol, a: "\(.a_ip):\(.a_port)", b: "\(.b_ip):\(.b_port)", state, syn_count, ack_count, fin_count, rst_count, packet_count, fwd_packet_count, bwd_packet_count, end_reason}' $D/flows.jsonl
{"flow_id":"2cd873f3effb0c51","protocol":"TCP","a":"127.0.0.1:39198","b":"127.0.0.1:8000","state":"ESTABLISHED","syn_count":2,"ack_count":2,"fin_count":0,"rst_count":0,"packet_count":3,"fwd_packet_count":2,"bwd_packet_count":1,"end_reason":"end_of_capture"}
```

### T07 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Ba packet thuộc đúng 1 flow | cả 3 event có `flow_id` `2cd873f3effb0c51`, `flows.jsonl` có 1 dòng, summary `flows created: 1` | Đạt |
| 2 | Direction đúng | SYN `forward`, SYN-ACK `backward`, ACK `forward`. Endpoint A là client `127.0.0.1:39198`, B là server `127.0.0.1:8000` | Đạt |
| 3 | Flow ở trạng thái `ESTABLISHED` | `state` là `ESTABLISHED` | Đạt |
| 4 | Bộ đếm cờ đúng | `syn_count` 2 từ SYN và SYN-ACK, `ack_count` 2 từ SYN-ACK và ACK, `fin_count` 0, `rst_count` 0 | Đạt |
| 5 | Packet không payload vẫn được tính | cả 3 packet `payload_len` 0, `packet_count` 3, `fwd_packet_count` 2, `bwd_packet_count` 1 | Đạt |
| 6 | Chương trình thoát mã 0 | mã thoát `0`, 3 packet OK | Đạt |

## T08: Bidirectional flow

Bidirectional flow là cách gom packet của cả hai chiều trong một phiên giao tiếp vào cùng một flow. Packet A→B và B→A có 5-tuple đảo chiều nhau, nên flow key phải được sắp xếp theo một thứ tự cố định để hai chiều ra cùng một key.

### Mục tiêu

1. Packet A→B và B→A của cùng một kết nối, tức 5-tuple đảo chiều, được gắn chung một `flow_id`.
2. Direction đúng: packet đi từ client là `forward`, packet đi từ server là `backward`, bên khởi tạo kết nối là endpoint A.
3. Bộ đếm hai chiều đúng: `fwd_packet_count` và `bwd_packet_count` khớp số event theo direction, `fwd_byte_count` và `bwd_byte_count` khớp tổng `ip_len` theo direction.
4. `flow_id` ổn định: chạy lại IDS trên cùng pcap cho ra cùng `flow_id`.
5. Chương trình thoát mã 0.

### Tạo pcap

Pcap chứa trọn một kết nối HTTP có dữ liệu đi cả hai chiều: request từ client, response từ server, cùng handshake và đóng kết nối.

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements2/t08_bidirectional_flow
mkdir -p $D
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, gửi request:

```bash
(btids) odixe@LapcuaTriet:~/ids$ curl -s -o /dev/null http://127.0.0.1:8000/
```

Kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t08_bidirectional_flow
tcpdump -nn -r $D/input.pcap
reading from file TEST/requirements2/t08_bidirectional_flow/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:48:31.760223 IP 127.0.0.1.44238 > 127.0.0.1.8000: Flags [S], seq 3394470258, win 65495, options [mss 65495,sackOK,TS val 2348396968 ecr 0,nop,wscale 10], length 0
21:48:31.760250 IP 127.0.0.1.8000 > 127.0.0.1.44238: Flags [S.], seq 2930370874, ack 3394470259, win 65483, options [mss 65495,sackOK,TS val 3912500175 ecr 2348396968,nop,wscale 10], length 0
21:48:31.760260 IP 127.0.0.1.44238 > 127.0.0.1.8000: Flags [.], ack 1, win 64, options [nop,nop,TS val 2348396968 ecr 3912500175], length 0
21:48:31.760311 IP 127.0.0.1.44238 > 127.0.0.1.8000: Flags [P.], seq 1:78, ack 1, win 64, options [nop,nop,TS val 2348396968 ecr 3912500175], length 77
21:48:31.760315 IP 127.0.0.1.8000 > 127.0.0.1.44238: Flags [.], ack 78, win 64, options [nop,nop,TS val 3912500175 ecr 2348396968], length 0
21:48:31.761227 IP 127.0.0.1.8000 > 127.0.0.1.44238: Flags [P.], seq 1:157, ack 78, win 64, options [nop,nop,TS val 3912500176 ecr 2348396968], length 156
21:48:31.761245 IP 127.0.0.1.44238 > 127.0.0.1.8000: Flags [.], ack 157, win 64, options [nop,nop,TS val 2348396969 ecr 3912500176], length 0
21:48:31.761259 IP 127.0.0.1.8000 > 127.0.0.1.44238: Flags [P.], seq 157:887, ack 78, win 64, options [nop,nop,TS val 3912500176 ecr 2348396969], length 730
21:48:31.761261 IP 127.0.0.1.44238 > 127.0.0.1.8000: Flags [.], ack 887, win 64, options [nop,nop,TS val 2348396969 ecr 3912500176], length 0
21:48:31.761283 IP 127.0.0.1.8000 > 127.0.0.1.44238: Flags [F.], seq 887, ack 78, win 64, options [nop,nop,TS val 3912500176 ecr 2348396969], length 0
21:48:31.761294 IP 127.0.0.1.44238 > 127.0.0.1.8000: Flags [F.], seq 78, ack 888, win 64, options [nop,nop,TS val 2348396969 ecr 3912500176], length 0
21:48:31.761306 IP 127.0.0.1.8000 > 127.0.0.1.44238: Flags [.], ack 79, win 64, options [nop,nop,TS val 3912500176 ecr 2348396969], length 0
```

Pcap có 12 packet của một kết nối giữa `127.0.0.1.44238` và `127.0.0.1.8000`, đi cả hai chiều: 6 packet từ client, 6 packet từ server, có payload ở cả request 77 byte và response 156 + 730 byte.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, src: "\(.src_ip):\(.src_port)", dst: "\(.dst_ip):\(.dst_port)", tcp_flags, ip_len, flow_id, direction}' $D/events.jsonl
{"packet_id":1,"src":"127.0.0.1:44238","dst":"127.0.0.1:8000","tcp_flags":"SYN","ip_len":60,"flow_id":"2f28d9706145c21e","direction":"forward"}
{"packet_id":2,"src":"127.0.0.1:8000","dst":"127.0.0.1:44238","tcp_flags":"SYN-ACK","ip_len":60,"flow_id":"2f28d9706145c21e","direction":"backward"}
{"packet_id":3,"src":"127.0.0.1:44238","dst":"127.0.0.1:8000","tcp_flags":"ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"forward"}
{"packet_id":4,"src":"127.0.0.1:44238","dst":"127.0.0.1:8000","tcp_flags":"PSH-ACK","ip_len":129,"flow_id":"2f28d9706145c21e","direction":"forward"}
{"packet_id":5,"src":"127.0.0.1:8000","dst":"127.0.0.1:44238","tcp_flags":"ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"backward"}
{"packet_id":6,"src":"127.0.0.1:8000","dst":"127.0.0.1:44238","tcp_flags":"PSH-ACK","ip_len":208,"flow_id":"2f28d9706145c21e","direction":"backward"}
{"packet_id":7,"src":"127.0.0.1:44238","dst":"127.0.0.1:8000","tcp_flags":"ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"forward"}
{"packet_id":8,"src":"127.0.0.1:8000","dst":"127.0.0.1:44238","tcp_flags":"PSH-ACK","ip_len":782,"flow_id":"2f28d9706145c21e","direction":"backward"}
{"packet_id":9,"src":"127.0.0.1:44238","dst":"127.0.0.1:8000","tcp_flags":"ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"forward"}
{"packet_id":10,"src":"127.0.0.1:8000","dst":"127.0.0.1:44238","tcp_flags":"FIN-ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"backward"}
{"packet_id":11,"src":"127.0.0.1:44238","dst":"127.0.0.1:8000","tcp_flags":"FIN-ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"forward"}
{"packet_id":12,"src":"127.0.0.1:8000","dst":"127.0.0.1:44238","tcp_flags":"ACK","ip_len":52,"flow_id":"2f28d9706145c21e","direction":"backward"}
```

Lệnh 3, đếm packet và byte theo direction từ `events.jsonl`:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -s '{flow_ids: (map(.flow_id) | unique), fwd_packets: (map(select(.direction == "forward")) | length), bwd_packets: (map(select(.direction == "backward")) | length), fwd_bytes: (map(select(.direction == "forward").ip_len) | add), bwd_bytes: (map(select(.direction == "backward").ip_len) | add)}' $D/events.jsonl
{
  "flow_ids": [
    "2f28d9706145c21e"
  ],
  "fwd_packets": 6,
  "bwd_packets": 6,
  "fwd_bytes": 397,
  "bwd_bytes": 1206
}
```

Lệnh 4, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{flow_id, a: "\(.a_ip):\(.a_port)", b: "\(.b_ip):\(.b_port)", packet_count, fwd_packet_count, bwd_packet_count, byte_count, fwd_byte_count, bwd_byte_count, state}' $D/flows.jsonl
{"flow_id":"2f28d9706145c21e","a":"127.0.0.1:44238","b":"127.0.0.1:8000","packet_count":12,"fwd_packet_count":6,"bwd_packet_count":6,"byte_count":1603,"fwd_byte_count":397,"bwd_byte_count":1206,"state":"CLOSED"}
```

Lệnh 5, chạy lại IDS ra file tạm để kiểm tra `flow_id` ổn định:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output /tmp/t08_events.jsonl --flow-output /tmp/t08_flows.jsonl --log-file /tmp/t08.log
jq -r .flow_id $D/flows.jsonl /tmp/t08_flows.jsonl
rm /tmp/t08_events.jsonl /tmp/t08_flows.jsonl /tmp/t08.log
Total packets: 12 (OK 12, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
2f28d9706145c21e
2f28d9706145c21e
```

### T08 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Hai chiều chung một `flow_id` | 12 event đều có `flow_id` `2f28d9706145c21e`, `flow_ids` chỉ có 1 phần tử, `flows created: 1` | Đạt |
| 2 | Direction đúng | 6 event từ `127.0.0.1:44238` là `forward`, 6 event từ `127.0.0.1:8000` là `backward`. Endpoint A là client `127.0.0.1:44238`, B là server `127.0.0.1:8000` | Đạt |
| 3 | Bộ đếm hai chiều khớp event | packet: 6 và 6 khớp `fwd_packet_count` 6 và `bwd_packet_count` 6. byte: 397 và 1206 khớp `fwd_byte_count` 397 và `bwd_byte_count` 1206, tổng 1603 bằng `byte_count` | Đạt |
| 4 | `flow_id` ổn định | hai lần chạy cùng ra `2f28d9706145c21e` | Đạt |
| 5 | Chương trình thoát mã 0 | mã thoát `0`, 12 packet OK | Đạt |

## T09: TCP close

Kết nối TCP có hai cách kết thúc. Đóng bình thường dùng cờ FIN: mỗi phía gửi FIN để báo đã gửi xong dữ liệu và chờ phía kia xác nhận. Ngắt đột ngột dùng cờ RST: một phía hủy kết nối ngay lập tức, không chờ xác nhận, thường gặp khi ứng dụng bị hủy hoặc khi kết nối tới cổng không có server.

### Mục tiêu

1. Kết nối đóng bình thường bằng FIN/ACK từ cả hai phía chuyển sang `state` là `CLOSED`, `fin_count` là 2, `rst_count` là 0.
2. Kết nối đã `ESTABLISHED` bị ngắt đột ngột bằng RST chuyển sang `state` là `RESET`, `rst_count` lớn hơn 0.
3. Kết nối bị từ chối ngay trong handshake, SYN rồi nhận RST/ACK, cũng chuyển sang `RESET`.
4. Ba kết nối được tách thành 3 flow riêng, mỗi packet gắn đúng `flow_id` của kết nối mình.
5. Chương trình thoát mã 0.

### Tạo pcap

Pcap chứa 3 kết nối TCP trên `lo`, mỗi kết nối kết thúc theo một cách:

| Kết nối | Cách tạo | Cách kết thúc |
| --- | --- | --- |
| 1 | `curl` tới `http.server` cổng 8000 | FIN/ACK hai phía |
| 2 | script mở kết nối tới cổng 8000 rồi đóng với `SO_LINGER` bằng 0 | client gửi RST sau khi đã ESTABLISHED |
| 3 | script kết nối tới cổng 8001 không có server | server trả RST/ACK cho SYN |

`SO_LINGER` bằng 0 khiến kernel bỏ qua bước FIN và gửi RST ngay khi `close()`, đây là cách chuẩn để tạo RST chủ động từ client. Kết nối 2 và 3 được tạo bằng script rst_client.py.

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements2/t09_tcp_close
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000 or tcp port 8001'
```

Terminal 3, tạo 3 kết nối theo thứ tự:

```bash
(btids) odixe@LapcuaTriet:~/ids$ curl -s -o /dev/null http://127.0.0.1:8000/
python TEST/requirements2/t09_tcp_close/rst_client.py
port 8001 refused
```

Kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t09_tcp_close
tcpdump -nn -r $D/input.pcap
reading from file TEST/requirements2/t09_tcp_close/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:52:27.494092 IP 127.0.0.1.55816 > 127.0.0.1.8000: Flags [S], seq 1632605971, win 65495, options [mss 65495,sackOK,TS val 214761146 ecr 0,nop,wscale 10], length 0
21:52:27.494104 IP 127.0.0.1.8000 > 127.0.0.1.55816: Flags [S.], seq 2586291971, ack 1632605972, win 65483, options [mss 65495,sackOK,TS val 3400768775 ecr 214761146,nop,wscale 10], length 0
21:52:27.494111 IP 127.0.0.1.55816 > 127.0.0.1.8000: Flags [.], ack 1, win 64, options [nop,nop,TS val 214761146 ecr 3400768775], length 0
21:52:27.494158 IP 127.0.0.1.55816 > 127.0.0.1.8000: Flags [P.], seq 1:78, ack 1, win 64, options [nop,nop,TS val 214761146 ecr 3400768775], length 77
21:52:27.494160 IP 127.0.0.1.8000 > 127.0.0.1.55816: Flags [.], ack 78, win 64, options [nop,nop,TS val 3400768775 ecr 214761146], length 0
21:52:27.494979 IP 127.0.0.1.8000 > 127.0.0.1.55816: Flags [P.], seq 1:157, ack 78, win 64, options [nop,nop,TS val 3400768776 ecr 214761146], length 156
21:52:27.494994 IP 127.0.0.1.55816 > 127.0.0.1.8000: Flags [.], ack 157, win 64, options [nop,nop,TS val 214761147 ecr 3400768776], length 0
21:52:27.495009 IP 127.0.0.1.8000 > 127.0.0.1.55816: Flags [P.], seq 157:887, ack 78, win 64, options [nop,nop,TS val 3400768776 ecr 214761147], length 730
21:52:27.495011 IP 127.0.0.1.55816 > 127.0.0.1.8000: Flags [.], ack 887, win 64, options [nop,nop,TS val 214761147 ecr 3400768776], length 0
21:52:27.495032 IP 127.0.0.1.8000 > 127.0.0.1.55816: Flags [F.], seq 887, ack 78, win 64, options [nop,nop,TS val 3400768776 ecr 214761147], length 0
21:52:27.495137 IP 127.0.0.1.55816 > 127.0.0.1.8000: Flags [F.], seq 78, ack 888, win 64, options [nop,nop,TS val 214761147 ecr 3400768776], length 0
21:52:27.495148 IP 127.0.0.1.8000 > 127.0.0.1.55816: Flags [.], ack 79, win 64, options [nop,nop,TS val 3400768776 ecr 214761147], length 0
21:52:27.512341 IP 127.0.0.1.55828 > 127.0.0.1.8000: Flags [S], seq 2156019903, win 65495, options [mss 65495,sackOK,TS val 678124396 ecr 0,nop,wscale 10], length 0
21:52:27.512353 IP 127.0.0.1.8000 > 127.0.0.1.55828: Flags [S.], seq 1458221631, ack 2156019904, win 65483, options [mss 65495,sackOK,TS val 883274308 ecr 678124396,nop,wscale 10], length 0
21:52:27.512361 IP 127.0.0.1.55828 > 127.0.0.1.8000: Flags [.], ack 1, win 64, options [nop,nop,TS val 678124396 ecr 883274308], length 0
21:52:27.512416 IP 127.0.0.1.55828 > 127.0.0.1.8000: Flags [R.], seq 1, ack 1, win 64, options [nop,nop,TS val 678124396 ecr 883274308], length 0
21:52:27.512523 IP 127.0.0.1.34946 > 127.0.0.1.8001: Flags [S], seq 1209783293, win 65495, options [mss 65495,sackOK,TS val 1901369378 ecr 0,nop,wscale 10], length 0
21:52:27.512544 IP 127.0.0.1.8001 > 127.0.0.1.34946: Flags [R.], seq 0, ack 1209783294, win 0, length 0
```

Pcap có đủ 3 kết nối: cổng client `55816` kết thúc bằng hai `[F.]`, cổng `55828` handshake xong rồi client gửi `[R.]`, cổng `34946` gửi `[S]` tới 8001 và nhận ngay `[R.]`.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 18 (OK 18, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 3, flows timed out: 0
0
```

Lệnh 2, in event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, src: "\(.src_ip):\(.src_port)", dst: "\(.dst_ip):\(.dst_port)", tcp_flags, flow_id, direction}' $D/events.jsonl
{"packet_id":1,"src":"127.0.0.1:55816","dst":"127.0.0.1:8000","tcp_flags":"SYN","flow_id":"72b379f978428224","direction":"forward"}
{"packet_id":2,"src":"127.0.0.1:8000","dst":"127.0.0.1:55816","tcp_flags":"SYN-ACK","flow_id":"72b379f978428224","direction":"backward"}
{"packet_id":3,"src":"127.0.0.1:55816","dst":"127.0.0.1:8000","tcp_flags":"ACK","flow_id":"72b379f978428224","direction":"forward"}
{"packet_id":4,"src":"127.0.0.1:55816","dst":"127.0.0.1:8000","tcp_flags":"PSH-ACK","flow_id":"72b379f978428224","direction":"forward"}
{"packet_id":5,"src":"127.0.0.1:8000","dst":"127.0.0.1:55816","tcp_flags":"ACK","flow_id":"72b379f978428224","direction":"backward"}
{"packet_id":6,"src":"127.0.0.1:8000","dst":"127.0.0.1:55816","tcp_flags":"PSH-ACK","flow_id":"72b379f978428224","direction":"backward"}
{"packet_id":7,"src":"127.0.0.1:55816","dst":"127.0.0.1:8000","tcp_flags":"ACK","flow_id":"72b379f978428224","direction":"forward"}
{"packet_id":8,"src":"127.0.0.1:8000","dst":"127.0.0.1:55816","tcp_flags":"PSH-ACK","flow_id":"72b379f978428224","direction":"backward"}
{"packet_id":9,"src":"127.0.0.1:55816","dst":"127.0.0.1:8000","tcp_flags":"ACK","flow_id":"72b379f978428224","direction":"forward"}
{"packet_id":10,"src":"127.0.0.1:8000","dst":"127.0.0.1:55816","tcp_flags":"FIN-ACK","flow_id":"72b379f978428224","direction":"backward"}
{"packet_id":11,"src":"127.0.0.1:55816","dst":"127.0.0.1:8000","tcp_flags":"FIN-ACK","flow_id":"72b379f978428224","direction":"forward"}
{"packet_id":12,"src":"127.0.0.1:8000","dst":"127.0.0.1:55816","tcp_flags":"ACK","flow_id":"72b379f978428224","direction":"backward"}
{"packet_id":13,"src":"127.0.0.1:55828","dst":"127.0.0.1:8000","tcp_flags":"SYN","flow_id":"12d3483ffa9f5031","direction":"forward"}
{"packet_id":14,"src":"127.0.0.1:8000","dst":"127.0.0.1:55828","tcp_flags":"SYN-ACK","flow_id":"12d3483ffa9f5031","direction":"backward"}
{"packet_id":15,"src":"127.0.0.1:55828","dst":"127.0.0.1:8000","tcp_flags":"ACK","flow_id":"12d3483ffa9f5031","direction":"forward"}
{"packet_id":16,"src":"127.0.0.1:55828","dst":"127.0.0.1:8000","tcp_flags":"RST-ACK","flow_id":"12d3483ffa9f5031","direction":"forward"}
{"packet_id":17,"src":"127.0.0.1:34946","dst":"127.0.0.1:8001","tcp_flags":"SYN","flow_id":"933e21ae9562595b","direction":"forward"}
{"packet_id":18,"src":"127.0.0.1:8001","dst":"127.0.0.1:34946","tcp_flags":"RST-ACK","flow_id":"933e21ae9562595b","direction":"backward"}
```

Lệnh 3, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{flow_id, a: "\(.a_ip):\(.a_port)", b: "\(.b_ip):\(.b_port)", state, syn_count, ack_count, fin_count, rst_count, packet_count, end_reason}' $D/flows.jsonl
{"flow_id":"72b379f978428224","a":"127.0.0.1:55816","b":"127.0.0.1:8000","state":"CLOSED","syn_count":2,"ack_count":11,"fin_count":2,"rst_count":0,"packet_count":12,"end_reason":"end_of_capture"}
{"flow_id":"12d3483ffa9f5031","a":"127.0.0.1:55828","b":"127.0.0.1:8000","state":"RESET","syn_count":2,"ack_count":3,"fin_count":0,"rst_count":1,"packet_count":4,"end_reason":"end_of_capture"}
{"flow_id":"933e21ae9562595b","a":"127.0.0.1:34946","b":"127.0.0.1:8001","state":"RESET","syn_count":1,"ack_count":1,"fin_count":0,"rst_count":1,"packet_count":2,"end_reason":"end_of_capture"}
```

### T09 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Đóng bằng FIN hai phía thành `CLOSED` | flow `72b379f978428224`: `state` `CLOSED`, `fin_count` 2 từ packet 10 và 11, `rst_count` 0 | Đạt |
| 2 | RST sau khi ESTABLISHED thành `RESET` | flow `12d3483ffa9f5031`: handshake đủ 3 packet, packet 16 `RST-ACK` từ client, `state` `RESET`, `rst_count` 1 | Đạt |
| 3 | RST trong handshake thành `RESET` | flow `933e21ae9562595b`: SYN rồi `RST-ACK` từ cổng 8001, `state` `RESET`, `syn_count` 1, `rst_count` 1 | Đạt |
| 4 | Ba kết nối tách thành 3 flow | 3 `flow_id` khác nhau, `flows created: 3`, `packet_count` 12 + 4 + 2 bằng 18 event | Đạt |
| 5 | Chương trình thoát mã 0 | mã thoát `0`, 18 packet OK | Đạt |

## T10: UDP query/response

UDP không có handshake hay trạng thái kết nối như TCP. Vì vậy flow UDP được xác định chỉ bằng 5-tuple hai chiều: các packet có cùng cặp endpoint, đi theo cả hai chiều, trong khoảng thời gian chưa vượt idle timeout được xem là một flow.

### Mục tiêu

1. DNS query và DNS response đi hai chiều qua UDP được gom vào đúng 1 flow, cùng `flow_id`.
2. `protocol` của flow là `UDP`, `application_protocol` là `DNS`.
3. Direction đúng: query từ client là `forward`, response từ DNS server là `backward`.
4. Packet và byte count đúng: `packet_count` 2, `fwd_packet_count` 1, `bwd_packet_count` 1, `byte_count` bằng tổng `ip_len` của hai event, chia đúng theo chiều.
5. Flow UDP không có các field riêng của TCP: `syn_count`, `ack_count`, `fin_count`, `rst_count`, `state` vắng mặt.
6. Chương trình thoát mã 0.

### Tạo pcap

Pcap chỉ chứa đúng 1 DNS query và 1 DNS response giữa máy và 8.8.8.8. Dùng `tcpdump -c 2` để tự dừng sau 2 packet, `dig +tries=1` để chỉ gửi một query.

Terminal 1, bắt packet trên `eth0`:

```bash
D=TEST/requirements2/t10_udp_query_response
mkdir -p $D
sudo tcpdump -i eth0 -nn -c 2 -Z $USER -w $D/input.pcap 'udp port 53 and host 8.8.8.8'
```

Terminal 2, gửi DNS query:

```bash
(btids) odixe@LapcuaTriet:~/ids$ dig @8.8.8.8 +tries=1 example.com A

; <<>> DiG 9.18.39-0ubuntu0.24.04.7-Ubuntu <<>> @8.8.8.8 +tries=1 example.com A
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9911
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;example.com.                   IN      A

;; ANSWER SECTION:
example.com.            124     IN      A       104.20.23.154
example.com.            124     IN      A       172.66.147.243

;; Query time: 43 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
;; WHEN: Mon Oct 12 21:56:26 +07 2026
;; MSG SIZE  rcvd: 72
```

Kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t10_udp_query_response
tcpdump -nn -v -r $D/input.pcap
reading from file TEST/requirements2/t10_udp_query_response/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:56:26.157162 IP (tos 0x0, ttl 64, id 34028, offset 0, flags [none], proto UDP (17), length 80)
    172.18.124.92.43387 > 8.8.8.8.53: 9911+ [1au] A? example.com. (52)
21:56:26.200029 IP (tos 0x0, ttl 63, id 0, offset 0, flags [none], proto UDP (17), length 100)
    8.8.8.8.53 > 172.18.124.92.43387: 9911$ 2/0/1 example.com. A 104.20.23.154, example.com. A 172.66.147.243 (72)
```

Pcap có đúng 2 packet UDP cùng transaction id 9911: query `A? example.com.` có IP length 80 đi từ `172.18.124.92.43387` tới `8.8.8.8.53`, response 2 answer có IP length 100 đi theo chiều ngược lại.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 2 (OK 2, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, src: "\(.src_ip):\(.src_port)", dst: "\(.dst_ip):\(.dst_port)", transport_protocol, app_protocol, message_type: .app.message_type, transaction_id: .app.transaction_id, ip_len, flow_id, direction}' $D/events.jsonl
{"packet_id":1,"src":"172.18.124.92:43387","dst":"8.8.8.8:53","transport_protocol":"UDP","app_protocol":"DNS","message_type":"query","transaction_id":9911,"ip_len":80,"flow_id":"87a6782bbc9f2fcb","direction":"forward"}
{"packet_id":2,"src":"8.8.8.8:53","dst":"172.18.124.92:43387","transport_protocol":"UDP","app_protocol":"DNS","message_type":"response","transaction_id":9911,"ip_len":100,"flow_id":"87a6782bbc9f2fcb","direction":"backward"}
```

Lệnh 3, tính tổng byte theo chiều từ event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -s '{flow_ids: (map(.flow_id) | unique), fwd_bytes: (map(select(.direction == "forward").ip_len) | add), bwd_bytes: (map(select(.direction == "backward").ip_len) | add), total: (map(.ip_len) | add)}' $D/events.jsonl
{
  "flow_ids": [
    "87a6782bbc9f2fcb"
  ],
  "fwd_bytes": 80,
  "bwd_bytes": 100,
  "total": 180
}
```

Lệnh 4, in toàn bộ flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq . $D/flows.jsonl
{
  "flow_id": "87a6782bbc9f2fcb",
  "protocol": "UDP",
  "application_protocol": "DNS",
  "a_ip": "172.18.124.92",
  "a_port": 43387,
  "b_ip": "8.8.8.8",
  "b_port": 53,
  "start_time": 1791816986.157162,
  "last_seen": 1791816986.200029,
  "duration": 0.042867,
  "packet_count": 2,
  "byte_count": 180,
  "fwd_packet_count": 1,
  "fwd_byte_count": 80,
  "bwd_packet_count": 1,
  "bwd_byte_count": 100,
  "end_reason": "end_of_capture"
}
```

### T10 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Query và response chung 1 flow | 2 event cùng `flow_id` `87a6782bbc9f2fcb`, `flow_ids` có 1 phần tử, `flows created: 1` | Đạt |
| 2 | Flow là UDP, ứng dụng DNS | `protocol` `UDP`, `application_protocol` `DNS` | Đạt |
| 3 | Direction đúng | packet 1 `query` từ `172.18.124.92:43387` là `forward`, packet 2 `response` từ `8.8.8.8:53` là `backward`. Endpoint A là client, B là `8.8.8.8:53` | Đạt |
| 4 | Packet và byte count đúng | `packet_count` 2, mỗi chiều 1 packet. `fwd_byte_count` 80, `bwd_byte_count` 100, `byte_count` 180, khớp `ip_len` trong event và `length` trong tcpdump | Đạt |
| 5 | Không có field TCP | flow không có `syn_count`, `ack_count`, `fin_count`, `rst_count`, `state` | Đạt |
| 6 | Chương trình thoát mã 0 | mã thoát `0`, 2 packet OK | Đạt |

## T11: Concurrent flows

Concurrent flows là nhiều phiên giao tiếp diễn ra cùng lúc, packet của chúng nằm xen kẽ nhau theo thời gian. Flow Tracker phải tra đúng flow cho từng packet theo 5-tuple, không được dựa vào thứ tự packet hay chỉ dựa vào IP và cổng server.

### Mục tiêu

1. Nhiều kết nối chạy xen kẽ cùng lúc được tách thành các flow riêng, không gộp nhầm.
2. Hai kết nối cùng tới một server `127.0.0.1:8000`, chỉ khác cổng client, vẫn là hai flow khác nhau.
3. Kết nối tới server khác cổng `127.0.0.1:8001` là flow riêng.
4. Mỗi event được gắn đúng flow có endpoint trùng với 5-tuple của nó, kể cả khi packet của các flow nằm xen kẽ nhau trong pcap.
5. Tổng `packet_count` của các flow bằng số event.
6. Chương trình thoát mã 0.

### Tạo pcap

Pcap chứa 3 kết nối TCP mở cùng lúc: hai kết nối tới cổng 8000, một kết nối tới cổng 8001. Script concurrent_client.py mở cả 3 kết nối trước, rồi gửi request trên cả 3, rồi mới đọc response, nên packet của 3 flow nằm xen kẽ nhau thay vì xong flow này mới tới flow kia. Request dùng `HTTP/1.0` để server tự đóng kết nối sau khi trả response.

Terminal 1, chạy server cổng 8000:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, chạy server cổng 8001:

```bash
python -m http.server 8001 --bind 127.0.0.1
```

Terminal 3, bắt packet:

```bash
D=TEST/requirements2/t11_concurrent_flows
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000 or tcp port 8001'
```

Terminal 4, chạy script:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python TEST/requirements2/t11_concurrent_flows/concurrent_client.py
35584 -> 8000: 521 bytes
35586 -> 8000: 521 bytes
45332 -> 8001: 521 bytes
```

Kiểm tra pcap:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t11_concurrent_flows
tcpdump -nn -r $D/input.pcap
reading from file TEST/requirements2/t11_concurrent_flows/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
22:01:15.362315 IP 127.0.0.1.35584 > 127.0.0.1.8000: Flags [S], seq 513214298, ... length 0
22:01:15.362345 IP 127.0.0.1.8000 > 127.0.0.1.35584: Flags [S.], seq 2895976578, ack 513214299, ... length 0
22:01:15.362354 IP 127.0.0.1.35584 > 127.0.0.1.8000: Flags [.], ack 1, ... length 0
22:01:15.362444 IP 127.0.0.1.35586 > 127.0.0.1.8000: Flags [S], seq 1088286119, ... length 0
22:01:15.362462 IP 127.0.0.1.8000 > 127.0.0.1.35586: Flags [S.], seq 1003792534, ack 1088286120, ... length 0
22:01:15.362465 IP 127.0.0.1.35586 > 127.0.0.1.8000: Flags [.], ack 1, ... length 0
22:01:15.362533 IP 127.0.0.1.45332 > 127.0.0.1.8001: Flags [S], seq 1313482707, ... length 0
22:01:15.362537 IP 127.0.0.1.8001 > 127.0.0.1.45332: Flags [S.], seq 3114033980, ack 1313482708, ... length 0
22:01:15.362539 IP 127.0.0.1.45332 > 127.0.0.1.8001: Flags [.], ack 1, ... length 0
22:01:15.362574 IP 127.0.0.1.35584 > 127.0.0.1.8000: Flags [P.], seq 1:41, ack 1, ... length 40
22:01:15.362577 IP 127.0.0.1.8000 > 127.0.0.1.35584: Flags [.], ack 41, ... length 0
22:01:15.362582 IP 127.0.0.1.35586 > 127.0.0.1.8000: Flags [P.], seq 1:41, ack 1, ... length 40
22:01:15.362584 IP 127.0.0.1.8000 > 127.0.0.1.35586: Flags [.], ack 41, ... length 0
22:01:15.362586 IP 127.0.0.1.45332 > 127.0.0.1.8001: Flags [P.], seq 1:41, ack 1, ... length 40
22:01:15.362588 IP 127.0.0.1.8001 > 127.0.0.1.45332: Flags [.], ack 41, ... length 0
...
```

Pcap có 36 packet của 3 kết nối với cổng client `35584`, `35586`, `45332`. Cả 3 handshake diễn ra trước khi có request nào, sau đó 3 request gửi liền nhau, chứng tỏ packet của các flow nằm xen kẽ.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 36 (OK 36, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 3, flows timed out: 0
0
```

Lệnh 2, in event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, src_port, dst_port, tcp_flags, flow_id, direction}' $D/events.jsonl
{"packet_id":1,"src_port":35584,"dst_port":8000,"tcp_flags":"SYN","flow_id":"61bad9f36ffd8c37","direction":"forward"}
{"packet_id":2,"src_port":8000,"dst_port":35584,"tcp_flags":"SYN-ACK","flow_id":"61bad9f36ffd8c37","direction":"backward"}
{"packet_id":3,"src_port":35584,"dst_port":8000,"tcp_flags":"ACK","flow_id":"61bad9f36ffd8c37","direction":"forward"}
{"packet_id":4,"src_port":35586,"dst_port":8000,"tcp_flags":"SYN","flow_id":"c8ba6e98af00d6a0","direction":"forward"}
{"packet_id":5,"src_port":8000,"dst_port":35586,"tcp_flags":"SYN-ACK","flow_id":"c8ba6e98af00d6a0","direction":"backward"}
{"packet_id":6,"src_port":35586,"dst_port":8000,"tcp_flags":"ACK","flow_id":"c8ba6e98af00d6a0","direction":"forward"}
{"packet_id":7,"src_port":45332,"dst_port":8001,"tcp_flags":"SYN","flow_id":"4c6948643a902da9","direction":"forward"}
{"packet_id":8,"src_port":8001,"dst_port":45332,"tcp_flags":"SYN-ACK","flow_id":"4c6948643a902da9","direction":"backward"}
{"packet_id":9,"src_port":45332,"dst_port":8001,"tcp_flags":"ACK","flow_id":"4c6948643a902da9","direction":"forward"}
{"packet_id":10,"src_port":35584,"dst_port":8000,"tcp_flags":"PSH-ACK","flow_id":"61bad9f36ffd8c37","direction":"forward"}
{"packet_id":11,"src_port":8000,"dst_port":35584,"tcp_flags":"ACK","flow_id":"61bad9f36ffd8c37","direction":"backward"}
{"packet_id":12,"src_port":35586,"dst_port":8000,"tcp_flags":"PSH-ACK","flow_id":"c8ba6e98af00d6a0","direction":"forward"}
{"packet_id":13,"src_port":8000,"dst_port":35586,"tcp_flags":"ACK","flow_id":"c8ba6e98af00d6a0","direction":"backward"}
{"packet_id":14,"src_port":45332,"dst_port":8001,"tcp_flags":"PSH-ACK","flow_id":"4c6948643a902da9","direction":"forward"}
{"packet_id":15,"src_port":8001,"dst_port":45332,"tcp_flags":"ACK","flow_id":"4c6948643a902da9","direction":"backward"}
{"packet_id":16,"src_port":8001,"dst_port":45332,"tcp_flags":"PSH-ACK","flow_id":"4c6948643a902da9","direction":"backward"}
{"packet_id":17,"src_port":45332,"dst_port":8001,"tcp_flags":"ACK","flow_id":"4c6948643a902da9","direction":"forward"}
{"packet_id":18,"src_port":8001,"dst_port":45332,"tcp_flags":"PSH-ACK","flow_id":"4c6948643a902da9","direction":"backward"}
{"packet_id":19,"src_port":45332,"dst_port":8001,"tcp_flags":"ACK","flow_id":"4c6948643a902da9","direction":"forward"}
{"packet_id":20,"src_port":8001,"dst_port":45332,"tcp_flags":"FIN-ACK","flow_id":"4c6948643a902da9","direction":"backward"}
{"packet_id":21,"src_port":8000,"dst_port":35584,"tcp_flags":"PSH-ACK","flow_id":"61bad9f36ffd8c37","direction":"backward"}
{"packet_id":22,"src_port":8000,"dst_port":35586,"tcp_flags":"PSH-ACK","flow_id":"c8ba6e98af00d6a0","direction":"backward"}
{"packet_id":23,"src_port":35586,"dst_port":8000,"tcp_flags":"ACK","flow_id":"c8ba6e98af00d6a0","direction":"forward"}
{"packet_id":24,"src_port":35584,"dst_port":8000,"tcp_flags":"ACK","flow_id":"61bad9f36ffd8c37","direction":"forward"}
...
```

Lệnh 3, gom event theo `flow_id`:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -s 'group_by(.flow_id) | map({flow_id: .[0].flow_id, client_port: (map(select(.direction == "forward").src_port) | unique), server_port: (map(select(.direction == "forward").dst_port) | unique), events: length})' $D/events.jsonl
[
  {"flow_id": "4c6948643a902da9", "client_port": [45332], "server_port": [8001], "events": 12},
  {"flow_id": "61bad9f36ffd8c37", "client_port": [35584], "server_port": [8000], "events": 12},
  {"flow_id": "c8ba6e98af00d6a0", "client_port": [35586], "server_port": [8000], "events": 12}
]
```

Lệnh 4, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{flow_id, a: "\(.a_ip):\(.a_port)", b: "\(.b_ip):\(.b_port)", application_protocol, packet_count, state}' $D/flows.jsonl
{"flow_id":"61bad9f36ffd8c37","a":"127.0.0.1:35584","b":"127.0.0.1:8000","application_protocol":"HTTP","packet_count":12,"state":"CLOSED"}
{"flow_id":"c8ba6e98af00d6a0","a":"127.0.0.1:35586","b":"127.0.0.1:8000","application_protocol":"HTTP","packet_count":12,"state":"CLOSED"}
{"flow_id":"4c6948643a902da9","a":"127.0.0.1:45332","b":"127.0.0.1:8001","application_protocol":"HTTP","packet_count":12,"state":"CLOSED"}
```

Lệnh 5, đếm event bị gắn sai flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -n --slurpfile e $D/events.jsonl --slurpfile f $D/flows.jsonl '{mismatched: ([$e[] as $x | ($f[] | select(.flow_id == $x.flow_id)) as $fl | select(([$x.src_port, $x.dst_port] | sort) != ([$fl.a_port, $fl.b_port] | sort))] | length), events: ($e | length), sum_packet_count: ([$f[].packet_count] | add)}'
{
  "mismatched": 0,
  "events": 36,
  "sum_packet_count": 36
}
```

### T11 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Các kết nối xen kẽ tách thành flow riêng | 3 `flow_id` khác nhau, `flows created: 3`, packet 1 đến 24 cho thấy event của 3 flow nằm xen kẽ | Đạt |
| 2 | Cùng server, khác cổng client là hai flow | `35584` → `8000` là `61bad9f36ffd8c37`, `35586` → `8000` là `c8ba6e98af00d6a0` | Đạt |
| 3 | Server khác cổng là flow riêng | `45332` → `8001` là `4c6948643a902da9` | Đạt |
| 4 | Mỗi event gắn đúng flow | mỗi nhóm `flow_id` chỉ có một `client_port` và một `server_port`, `mismatched` là 0 | Đạt |
| 5 | Tổng `packet_count` bằng số event | 12 + 12 + 12 bằng 36, khớp 36 event | Đạt |
| 6 | Chương trình thoát mã 0 | mã thoát `0`, 36 packet OK, cả 3 flow `CLOSED` | Đạt |

## T12: Idle timeout

Idle timeout là khoảng thời gian tối đa một flow được phép không có packet mới. Vượt quá ngưỡng này, flow được xem là đã kết thúc, bị xuất ra và xóa khỏi active table để giải phóng bộ nhớ, đặc biệt cần thiết với UDP vốn không có cờ báo kết thúc như FIN hay RST của TCP.

### Mục tiêu

1. Flow không có packet mới lâu hơn idle timeout bị đóng với `end_reason` là `timeout`, được ghi ra `flows.jsonl` và xóa khỏi active table.
2. TCP và UDP dùng timeout riêng: cùng một khoảng im lặng, flow UDP hết hạn còn flow TCP thì chưa.
3. Timeout tính theo timestamp của packet trong pcap, không theo đồng hồ hệ thống.
4. Sau khi flow hết hạn, packet mới cùng 5-tuple tạo flow mới với `flow_id` khác, chứng tỏ flow cũ đã bị loại khỏi active table.
5. Giá trị timeout cấu hình được: chạy cùng pcap với config mặc định thì không có flow nào hết hạn.
6. Chương trình thoát mã 0.

### Tạo input

Dùng config riêng timeout.yaml đặt timeout nhỏ để không phải chờ lâu: TCP 6 giây, UDP 2 giây. Các key không ghi trong file giữ giá trị mặc định.

Script idle_client.py tạo 7 packet theo mốc thời gian:

| Thời điểm | Packet | Flow | Tác dụng |
| --- | --- | --- | --- |
| t = 0 | 2 UDP từ cổng 50001 | A | flow UDP rồi im lặng |
| t = 0 | handshake TCP tới cổng 8000, giữ kết nối mở | B | flow TCP rồi im lặng |
| t = 4 | 1 UDP từ cổng 50002 | C | đẩy clock lên 4: A im lặng 4 > 2 nên hết hạn, B im lặng 4 < 6 nên còn |
| t = 8 | 1 UDP từ cổng 50001 | A2 | đẩy clock vượt 6: B và C hết hạn. Packet cùng 5-tuple với A tạo flow mới |

`tcpdump -c 7` dừng ngay sau packet thứ 7, nên FIN của kết nối TCP khi script thoát không bị bắt, flow B chỉ có thể kết thúc do timeout.

Terminal 1, chạy server TCP:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements2/t12_idle_timeout
sudo tcpdump -i lo -nn -c 7 -Z $USER -w $D/input.pcap 'udp port 9999 or tcp port 8000'
```

Terminal 3, chạy script:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python TEST/requirements2/t12_idle_timeout/idle_client.py
t=0  sent UDP A x2 from 50001, opened TCP B
t=4  sent UDP C from 50002
t=8  sent UDP from 50001 again
```

Kiểm tra pcap, `-ttt` in khoảng cách thời gian so với packet trước, output đã rút gọn phần options:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t12_idle_timeout
tcpdump -nn -ttt -r $D/input.pcap
reading from file TEST/requirements2/t12_idle_timeout/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
 00:00:00.000000 IP 127.0.0.1.50001 > 127.0.0.1.9999: UDP, length 12
 00:00:00.000022 IP 127.0.0.1.50001 > 127.0.0.1.9999: UDP, length 12
 00:00:00.002568 IP 127.0.0.1.60508 > 127.0.0.1.8000: Flags [S], seq 3362739140, ... length 0
 00:00:00.000011 IP 127.0.0.1.8000 > 127.0.0.1.60508: Flags [S.], seq 2247117897, ack 3362739141, ... length 0
 00:00:00.000009 IP 127.0.0.1.60508 > 127.0.0.1.8000: Flags [.], ack 1, ... length 0
 00:00:04.000296 IP 127.0.0.1.50002 > 127.0.0.1.9999: UDP, length 12
 00:00:06.950315 IP 127.0.0.1.50001 > 127.0.0.1.9999: UDP, length 12
```

Pcap có đúng 7 packet, không có FIN. Khoảng cách giữa packet 5 và 6 là 4 giây, giữa packet 6 và 7 là 6.95 giây thay vì 4 giây như script sleep, nên packet cuối nằm ở t = 10.95. Độ lệch này không làm thay đổi kết quả mong đợi vì tại t = 10.95, B và C đều vẫn vượt timeout.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS với config timeout nhỏ

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --config $D/timeout.yaml --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 7 (OK 7, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 4, flows timed out: 3
0
```

Lệnh 2, in event với thời điểm tương đối so với packet đầu:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -s -c '.[0].timestamp as $t0 | .[] | {packet_id, t: ((.timestamp - $t0) * 100 | round / 100), src_port, dst_port, transport_protocol, flow_id}' $D/events.jsonl
{"packet_id":1,"t":0,"src_port":50001,"dst_port":9999,"transport_protocol":"UDP","flow_id":"1a02bc05e47be153"}
{"packet_id":2,"t":0,"src_port":50001,"dst_port":9999,"transport_protocol":"UDP","flow_id":"1a02bc05e47be153"}
{"packet_id":3,"t":0,"src_port":60508,"dst_port":8000,"transport_protocol":"TCP","flow_id":"d28abc281be0860a"}
{"packet_id":4,"t":0,"src_port":8000,"dst_port":60508,"transport_protocol":"TCP","flow_id":"d28abc281be0860a"}
{"packet_id":5,"t":0,"src_port":60508,"dst_port":8000,"transport_protocol":"TCP","flow_id":"d28abc281be0860a"}
{"packet_id":6,"t":4,"src_port":50002,"dst_port":9999,"transport_protocol":"UDP","flow_id":"2c6d4e6d868728a4"}
{"packet_id":7,"t":10.95,"src_port":50001,"dst_port":9999,"transport_protocol":"UDP","flow_id":"026ef201d68ab8fd"}
```

Lệnh 3, in flow theo thứ tự được ghi ra file:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -s -c '(map(.start_time) | min) as $t0 | .[] | {flow_id, protocol, a_port, b_port, packet_count, start: ((.start_time - $t0) * 100 | round / 100), last_seen: ((.last_seen - $t0) * 100 | round / 100), end_reason}' $D/flows.jsonl
{"flow_id":"1a02bc05e47be153","protocol":"UDP","a_port":50001,"b_port":9999,"packet_count":2,"start":0,"last_seen":0,"end_reason":"timeout"}
{"flow_id":"d28abc281be0860a","protocol":"TCP","a_port":60508,"b_port":8000,"packet_count":3,"start":0,"last_seen":0,"end_reason":"timeout"}
{"flow_id":"2c6d4e6d868728a4","protocol":"UDP","a_port":50002,"b_port":9999,"packet_count":1,"start":4,"last_seen":4,"end_reason":"timeout"}
{"flow_id":"026ef201d68ab8fd","protocol":"UDP","a_port":50001,"b_port":9999,"packet_count":1,"start":10.95,"last_seen":10.95,"end_reason":"end_of_capture"}
```

Lệnh 4, chạy lại cùng pcap với config mặc định ra file tạm:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output /tmp/t12_events.jsonl --flow-output /tmp/t12_flows.jsonl --log-file /tmp/t12.log
jq -c '{flow_id, protocol, a_port, packet_count, end_reason}' /tmp/t12_flows.jsonl
rm /tmp/t12_events.jsonl /tmp/t12_flows.jsonl /tmp/t12.log
Total packets: 7 (OK 7, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 3, flows timed out: 0
{"flow_id":"1a02bc05e47be153","protocol":"UDP","a_port":50001,"packet_count":3,"end_reason":"end_of_capture"}
{"flow_id":"d28abc281be0860a","protocol":"TCP","a_port":60508,"packet_count":3,"end_reason":"end_of_capture"}
{"flow_id":"2c6d4e6d868728a4","protocol":"UDP","a_port":50002,"packet_count":1,"end_reason":"end_of_capture"}
```

### T12 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Flow im lặng quá timeout bị đóng và xuất ra | 3 flow A, B, C có `end_reason` `timeout`, summary `flows timed out: 3`, cả 3 được ghi vào `flows.jsonl` trước flow A2 | Đạt |
| 2 | TCP và UDP dùng timeout riêng | tại t = 4, A là UDP im lặng 4 giây đã hết hạn, B là TCP im lặng 4 giây vẫn còn: B được ghi ra sau A, chỉ hết hạn khi clock lên 10.95 | Đạt |
| 3 | Timeout tính theo timestamp trong pcap | IDS chạy pcap trong chưa tới 1 giây nhưng flow vẫn hết hạn đúng theo khoảng cách 4 giây và 6.95 giây giữa các packet | Đạt |
| 4 | Packet cùng 5-tuple sau khi hết hạn tạo flow mới | packet 7 cùng 5-tuple `50001` → `9999` với A nhưng có `flow_id` mới `026ef201d68ab8fd`, khác `1a02bc05e47be153` của A | Đạt |
| 5 | Timeout cấu hình được | config mặc định cho `flows timed out: 0`, packet 7 được gộp vào flow A với `packet_count` 3 | Đạt |
| 6 | Chương trình thoát mã 0 | mã thoát `0`, 7 packet OK ở cả hai lần chạy | Đạt |

## T13: Statistics

Thống kê flow là các số liệu tổng hợp trên toàn bộ packet của một phiên: số packet, số byte, chia theo từng chiều, số lần xuất hiện mỗi cờ TCP và thời gian kéo dài. Đây là đầu vào chính cho Feature Extractor ở bài sau, nên phải khớp tuyệt đối với dữ liệu từng packet.

### Mục tiêu

1. Với một flow có nhiều packet đi cả hai chiều, các thống kê trong `flows.jsonl` khớp với số liệu tính lại độc lập từ `events.jsonl`:
    - `packet_count`, `byte_count`.
    - `fwd_packet_count`, `fwd_byte_count`, `bwd_packet_count`, `bwd_byte_count`.
    - `syn_count`, `ack_count`, `fin_count`, `rst_count`.
2. `start_time` bằng timestamp packet đầu, `last_seen` bằng timestamp packet cuối, `duration` bằng `last_seen` trừ `start_time`.
3. `duration` phản ánh đúng khoảng thời gian thật của kết nối trong pcap.
4. Chương trình thoát mã 0.

### Tạo pcap

Pcap chứa một kết nối HTTP keep-alive gửi 3 request trên cùng kết nối, mỗi request cách nhau 1 giây, rồi đóng bằng FIN. Nhờ vậy flow có nhiều packet hai chiều, đủ các loại cờ SYN, ACK, PSH, FIN, và `duration` khoảng 3 giây đủ lớn để kiểm tra. Request được gửi bằng script stats_client.py.

`http.server` mặc định trả lời theo `HTTP/1.0` và đóng kết nối sau mỗi request, nên chạy với `--protocol HTTP/1.1` để giữ kết nối mở.

Terminal 1, chạy server:

```bash
python -m http.server 8000 --bind 127.0.0.1 --protocol HTTP/1.1
```

Terminal 2, bắt packet:

```bash
D=TEST/requirements2/t13_statistics
sudo tcpdump -i lo -nn -Z $USER -w $D/input.pcap 'tcp port 8000'
```

Terminal 3, chạy script:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python TEST/requirements2/t13_statistics/stats_client.py
request 0: 200, 738 bytes
request 1: 200, 738 bytes
request 2: 200, 738 bytes
```

Kiểm tra pcap, `-ttt` in khoảng cách thời gian so với packet trước, output đã rút gọn phần options và một phần packet ở giữa:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t13_statistics
tcpdump -nn -ttt -r $D/input.pcap
reading from file TEST/requirements2/t13_statistics/input.pcap, link-type EN10MB (Ethernet), snapshot length 262144
 00:00:00.000000 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [S], seq 454424730, ... length 0
 00:00:00.000028 IP 127.0.0.1.8000 > 127.0.0.1.60658: Flags [S.], seq 2714365110, ack 454424731, ... length 0
 00:00:00.000009 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [.], ack 1, ... length 0
 00:00:00.000050 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [P.], seq 1:72, ack 1, ... length 71
 ...
 00:00:01.000516 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [P.], seq 72:143, ack 895, ... length 71
 ...
 00:00:01.000400 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [P.], seq 143:214, ack 1789, ... length 71
 ...
 00:00:01.000274 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [F.], seq 214, ack 2683, ... length 0
 00:00:00.000117 IP 127.0.0.1.8000 > 127.0.0.1.60658: Flags [F.], seq 2683, ack 215, ... length 0
 00:00:00.000016 IP 127.0.0.1.60658 > 127.0.0.1.8000: Flags [.], ack 2684, ... length 0
```

Pcap có 22 packet của một kết nối duy nhất từ cổng client `60658`. Ba request 71 byte cách nhau khoảng 1 giây, mỗi request được trả lời bằng header 156 byte và body 738 byte, cuối cùng hai bên gửi FIN. Tổng các khoảng thời gian xấp xỉ 3.003 giây.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 22 (OK 22, PARTIAL 0, UNKNOWN 0, MALFORMED 0)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in flow:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq . $D/flows.jsonl
{
  "flow_id": "d33954586db89d92",
  "protocol": "TCP",
  "application_protocol": "HTTP",
  "a_ip": "127.0.0.1",
  "a_port": 60658,
  "b_ip": "127.0.0.1",
  "b_port": 8000,
  "start_time": 1791817988.482262,
  "last_seen": 1791817991.485693,
  "duration": 3.003431,
  "packet_count": 22,
  "byte_count": 4055,
  "fwd_packet_count": 13,
  "fwd_byte_count": 897,
  "bwd_packet_count": 9,
  "bwd_byte_count": 3158,
  "syn_count": 2,
  "ack_count": 21,
  "fin_count": 2,
  "rst_count": 0,
  "state": "CLOSED",
  "end_reason": "end_of_capture"
}
```

Lệnh 3, so sánh từng thống kê của flow với giá trị tính lại từ `events.jsonl` bằng `jq`. Mỗi dòng có dạng `[giá trị trong flow, giá trị tính lại, khớp]`:

```bash
{"packet_count":[22,22,true]}
{"byte_count":[4055,4055,true]}
{"fwd_packet_count":[13,13,true]}
{"fwd_byte_count":[897,897,true]}
{"bwd_packet_count":[9,9,true]}
{"bwd_byte_count":[3158,3158,true]}
{"syn_count":[2,2,true]}
{"ack_count":[21,21,true]}
{"fin_count":[2,2,true]}
{"rst_count":[0,0,true]}
{"start_time":[1791817988.482262,1791817988.482262,true]}
{"last_seen":[1791817991.485693,1791817991.485693,true]}
{"duration":[3.003431,3.003431,true]}
```

### T13 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Packet và byte count khớp event | `packet_count` 22, `byte_count` 4055 đều khớp | Đạt |
| 2 | Thống kê hai chiều khớp event | forward 13 packet 897 byte, backward 9 packet 3158 byte, tổng hai chiều bằng 22 packet 4055 byte | Đạt |
| 3 | Bộ đếm cờ TCP khớp event | `syn_count` 2, `ack_count` 21 vì mọi packet trừ SYN đầu đều có ACK, `fin_count` 2, `rst_count` 0 | Đạt |
| 4 | `start_time`, `last_seen`, `duration` đúng | `start_time` và `last_seen` bằng timestamp nhỏ nhất và lớn nhất của event, `duration` 3.003431 bằng hiệu của chúng | Đạt |
| 5 | `duration` phản ánh thời gian thật | 3.003431 giây khớp ba khoảng nghỉ 1 giây giữa các request trong cột `-ttt` của tcpdump | Đạt |
| 6 | Chương trình thoát mã 0 | mã thoát `0`, 22 packet OK, flow `CLOSED` | Đạt |

## T14: Malformed event

Malformed event là event mà packet gốc sai cấu trúc như header bị cắt hoặc khai báo độ dài sai, hoặc có field mang giá trị không hợp lệ như port ngoài khoảng, IP sai định dạng. Unsupported event là packet đúng cấu trúc nhưng thuộc giao thức IDS không xử lý như ARP, IPv6. Cả hai loại phải được đánh dấu rõ lý do thay vì làm dừng chương trình hoặc lọt vào flow.

### Mục tiêu

1. Packet malformed từ pcap không làm chương trình crash, được gắn `parse_status` `MALFORMED`, `preprocess_status` `invalid`, có `errors` và `reason` mô tả lỗi cụ thể.
2. Packet không hỗ trợ như ARP và IPv6 được gắn `parse_status` `UNKNOWN`, `reason` ghi rõ lý do unsupported.
3. Event invalid và unsupported không được đưa vào flow, không có `flow_id`.
4. Event có field sai giá trị mà parser không tự sinh ra được, như port ngoài khoảng, IP sai, timestamp không phải số, protocol lạ, được preprocessor phát hiện với status và reason phù hợp.
5. Chính sách xử lý cấu hình được: với `keep` event bị đánh dấu `mark` và vẫn ghi ra file, với `drop` event bị loại khỏi `events.jsonl`.
6. Packet hợp lệ phía sau vẫn được xử lý bình thường, chương trình thoát mã 0.

### Tạo input

Input gồm ba phần:

- **Pcap sinh bằng script** gen_malformed.py: 5 packet gồm 2 malformed, 2 unsupported và 1 HTTP request hợp lệ ở cuối. Packet malformed không bắt được từ mạng thật vì kernel không gửi đi packet sai cấu trúc, nên dùng Scapy dựng byte trực tiếp như tc12 của bài 1.
- **Config drop** drop.yaml: đặt `invalid_policy` và `unsupported_policy` là `drop` để so sánh với config mặc định là `keep`.
- **Event giả** fake_invalid.py: parser luôn sinh port, IP, timestamp đúng kiểu, nên các giá trị sai được đưa thẳng vào chuỗi `Decoder`, `Preprocessor`, `FlowTracker`.

| Nguồn | packet_id | Nội dung |
| --- | --- | --- |
| pcap | 1 | IPv4 `ihl` 3, header khai báo chỉ 12 byte |
| pcap | 2 | TCP header bị cắt còn 8 byte |
| pcap | 3 | ARP request |
| pcap | 4 | UDP trên IPv6 |
| pcap | 5 | HTTP request hợp lệ |
| event giả | 1 | `dst_port` 70000 |
| event giả | 2 | `src_ip` `999.1.1.1` |
| event giả | 3 | `timestamp` là chuỗi `"abc"` |
| event giả | 4 | `transport_protocol` `SCTP` |
| event giả | 5 | `app_protocol` `FTP` |

Sinh pcap và kiểm tra:

```bash
(btids) odixe@LapcuaTriet:~/ids$ D=TEST/requirements2/t14_malformed_event
python $D/gen_malformed.py
tcpdump -nn -e -r $D/input.pcap
wrote 5 frames to /home/odixe/ids/TEST/requirements2/t14_malformed_event/input.pcap
  packet 1: malformed ihl=3, 54 bytes
  packet 2: malformed truncated TCP, 42 bytes
  packet 3: unsupported ARP, 42 bytes
  packet 4: unsupported IPv6, 62 bytes
  packet 5: valid HTTP, 84 bytes
reading from file TEST/requirements2/t14_malformed_event/input.pcap, link-type EN10MB (Ethernet), snapshot length 65535
22:16:47.098691 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv4 (0x0800), length 54: bad-hlen 12
22:16:47.098715 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv4 (0x0800), length 42: truncated-ip - 12 bytes missing! 10.0.0.1.40000 > 10.0.0.2.80:  [|tcp]
22:16:47.098720 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype ARP (0x0806), length 42: Request who-has 10.0.0.2 tell 10.0.0.1, length 28
22:16:47.098721 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv6 (0x86dd), length 62: fe80::1.5000 > fe80::2.53: domain [length 0 < 12] (invalid)
22:16:47.098722 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv4 (0x0800), length 84: 10.0.0.1.40000 > 10.0.0.2.80: Flags [P.], seq 0:30, ack 0, win 8192, length 30: HTTP: GET / HTTP/1.1
```

tcpdump xác nhận đúng 5 loại packet: packet 1 báo `bad-hlen 12`, packet 2 báo `truncated-ip` và `[|tcp]`, packet 3 là ARP, packet 4 là IPv6, packet 5 là HTTP request hợp lệ.

### Chạy IDS và kiểm tra

Lệnh 1: chạy IDS với config mặc định

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --output $D/events.jsonl --flow-output $D/flows.jsonl --log-file $D/run_log.txt
echo $?
Total packets: 5 (OK 1, PARTIAL 0, UNKNOWN 2, MALFORMED 2)
Dropped events: 0, flows created: 1, flows timed out: 0
0
```

Lệnh 2, in status của từng event:

```bash
(btids) odixe@LapcuaTriet:~/ids$ jq -c '{packet_id, parse_status, preprocess_status, processing_action, reason, errors, flow_id}' $D/events.jsonl
{"packet_id":1,"parse_status":"MALFORMED","preprocess_status":"invalid","processing_action":"mark","reason":["transport_protocol: missing","src_port: missing","dst_port: missing","parse_status: MALFORMED"],"errors":["ipv4: invalid ihl: header is 12 bytes, captured 40","tcp: ip_proto is TCP but the TCP header is missing or shorter than 20 bytes"],"flow_id":null}
{"packet_id":2,"parse_status":"MALFORMED","preprocess_status":"invalid","processing_action":"mark","reason":["transport_protocol: missing","src_port: missing","dst_port: missing","parse_status: MALFORMED"],"errors":["ipv4: ip_len 40 exceeds the 28 bytes captured","tcp: ip_proto is TCP but the TCP header is missing or shorter than 20 bytes"],"flow_id":null}
{"packet_id":3,"parse_status":"UNKNOWN","preprocess_status":"valid","processing_action":"mark","reason":["unsupported: parse_status UNKNOWN"],"errors":[],"flow_id":null}
{"packet_id":4,"parse_status":"UNKNOWN","preprocess_status":"valid","processing_action":"mark","reason":["unsupported: parse_status UNKNOWN"],"errors":[],"flow_id":null}
{"packet_id":5,"parse_status":"OK","preprocess_status":"valid","processing_action":"pass","reason":[],"errors":[],"flow_id":"77b37ae7a6ee7d02"}
```

Lệnh 3, chạy IDS với config drop ra file tạm:

```bash
(btids) odixe@LapcuaTriet:~/ids$ python main.py --pcap $D/input.pcap --config $D/drop.yaml --output /tmp/t14_events.jsonl --flow-output /tmp/t14_flows.jsonl --log-file /tmp/t14.log
echo $?
jq -c '{packet_id, parse_status, processing_action}' /tmp/t14_events.jsonl
rm /tmp/t14_events.jsonl /tmp/t14_flows.jsonl /tmp/t14.log
Total packets: 5 (OK 1, PARTIAL 0, UNKNOWN 2, MALFORMED 2)
Dropped events: 4, flows created: 1, flows timed out: 0
0
{"packet_id":5,"parse_status":"OK","processing_action":"pass"}
```

Lệnh 4, chạy event giả:

```bash
(btids) odixe@LapcuaTriet:~/ids$ PYTHONPATH=. python $D/fake_invalid.py
echo $?
[1] dst_port ngoài khoảng
    preprocess_status: invalid | action: mark
    reason : ['dst_port: out of range 70000']
    errors : []
    flow_id: None
[2] src_ip không hợp lệ
    preprocess_status: invalid | action: mark
    reason : ["src_ip: invalid address '999.1.1.1'"]
    errors : []
    flow_id: None
[3] timestamp không phải số
    preprocess_status: invalid | action: mark
    reason : ["timestamp: not a float 'abc'"]
    errors : []
    flow_id: None
[4] transport_protocol lạ
    preprocess_status: invalid | action: mark
    reason : ["transport_protocol: unsupported value 'SCTP'"]
    errors : []
    flow_id: None
[5] app_protocol lạ
    preprocess_status: partial | action: mark
    reason : ["app_protocol: unsupported value 'FTP'"]
    errors : []
    flow_id: 403988a59ce5faa6
flows: 1
0
```

### T14 đạt

| # | Tiêu chí | Kết quả thực tế | Đánh giá |
| --- | --- | --- | --- |
| 1 | Packet malformed được đánh dấu đúng | packet 1 và 2: `MALFORMED`, `invalid`, `errors` nêu đúng lỗi `invalid ihl` và `ip_len 40 exceeds the 28 bytes captured`, `reason` liệt kê các field thiếu kèm `parse_status: MALFORMED` | Đạt |
| 2 | Packet unsupported được đánh dấu đúng | packet 3 ARP và packet 4 IPv6: `UNKNOWN`, `reason` là `unsupported: parse_status UNKNOWN` | Đạt |
| 3 | Event invalid và unsupported không vào flow | packet 1 đến 4 có `flow_id` `null`, `flows created: 1` chỉ từ packet 5. Event giả 1 đến 4 có `flow_id` `None` | Đạt |
| 4 | Field sai giá trị được preprocessor phát hiện | port 70000, IP `999.1.1.1`, timestamp `"abc"`, transport `SCTP` đều thành `invalid` với `reason` cụ thể. `app_protocol` `FTP` chỉ là `partial` vì 5-tuple vẫn đúng nên event vẫn vào flow | Đạt |
| 5 | Chính sách keep và drop cấu hình được | `keep`: 5 event đều được ghi, 4 event lỗi có `mark`. `drop`: `Dropped events: 4`, file chỉ còn packet 5 | Đạt |
| 6 | Packet hợp lệ vẫn xử lý bình thường, không crash | packet 5 `OK`, `valid`, `pass`, có `flow_id` ở cả hai config. Mọi lần chạy thoát mã `0` | Đạt |
import http.client
import time

conn = http.client.HTTPConnection("127.0.0.1", 8000)

for i in range(3):
    conn.request("GET", f"/?n={i}")
    resp = conn.getresponse()
    body = resp.read()
    print(f"request {i}: {resp.status}, {len(body)} bytes")
    time.sleep(1)

conn.close()

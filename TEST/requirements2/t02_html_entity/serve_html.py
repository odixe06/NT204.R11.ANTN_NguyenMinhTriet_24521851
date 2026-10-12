import socket

BODY = b"<p>&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt; &amp; &#39;OR&#39; &#x41;</p>"
HEAD = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    f"Content-Length: {len(BODY)}\r\n"
    "Connection: close\r\n\r\n"
).encode()

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8000))
srv.listen(1)
conn, _ = srv.accept()
conn.recv(4096)
conn.sendall(HEAD + BODY)
conn.close()
srv.close()
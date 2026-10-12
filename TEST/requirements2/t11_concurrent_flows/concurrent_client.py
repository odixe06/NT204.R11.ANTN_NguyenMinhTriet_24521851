import socket

TARGETS = [8000, 8000, 8001]

socks = [socket.create_connection(("127.0.0.1", port)) for port in TARGETS]

for sock, port in zip(socks, TARGETS):
    sock.sendall(f"GET /c{port} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".encode())

for sock in socks:
    data = b""
    while chunk := sock.recv(4096):
        data += chunk
    print(f"{sock.getsockname()[1]} -> {sock.getpeername()[1]}: {len(data)} bytes")
    sock.close()

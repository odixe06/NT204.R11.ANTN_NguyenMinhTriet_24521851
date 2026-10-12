import socket
import struct

# kết nối 2: ESTABLISHED rồi đóng bằng RST
s = socket.create_connection(("127.0.0.1", 8000))
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()

# kết nối 3: cổng không có server, nhận RST/ACK cho SYN
try:
    socket.create_connection(("127.0.0.1", 8001)).close()
except ConnectionRefusedError:
    print("port 8001 refused")
import socket
import time

SERVER = ("127.0.0.1", 9999)

# UDP server nhận packet để kernel không trả ICMP port unreachable
receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(SERVER)


def udp_from(port: int, count: int = 1) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    for i in range(count):
        sock.sendto(f"udp {port} #{i}".encode(), SERVER)
    sock.close()


# t = 0: flow A là UDP 50001, flow B là TCP mở rồi để yên
udp_from(50001, count=2)
tcp = socket.create_connection(("127.0.0.1", 8000))
print("t=0  sent UDP A x2 from 50001, opened TCP B")

# t = 4: flow C là UDP 50002, đẩy clock lên 4 giây 
time.sleep(4)
udp_from(50002)
print("t=4  sent UDP C from 50002")

# t = 8: UDP 50001 gửi lại, cùng 5-tuple với flow A
time.sleep(4)
udp_from(50001)
print("t=8  sent UDP from 50001 again")

time.sleep(1)

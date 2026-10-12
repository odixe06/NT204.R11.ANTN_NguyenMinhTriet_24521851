"""Sinh input.pcap cho T14: 2 packet malformed, 2 packet unsupported, 1 packet hợp lệ."""
from pathlib import Path
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import RawPcapWriter

OUTPUT = Path(__file__).with_name("input.pcap")
LINKTYPE_ETHERNET = 1
ETHER_LEN = 14
IPV4_LEN = 20
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
PAYLOAD = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"


def ether() -> Ether:
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ip(**fields) -> IP:
    return IP(src="10.0.0.1", dst="10.0.0.2", **fields)


def tcp(**fields) -> TCP:
    return TCP(sport=40000, dport=80, flags="PA", **fields)


FRAMES = [
    # 1. malformed: ihl khai báo header IPv4 chỉ 12 byte
    ("malformed ihl=3", bytes(ether() / ip(ihl=3) / tcp())),
    # 2. malformed: TCP header bị cắt còn 8 byte
    (
        "malformed truncated TCP",
        bytes(ether() / ip() / tcp())[: ETHER_LEN + IPV4_LEN + 8],
    ),
    # 3. unsupported: ARP request
    (
        "unsupported ARP",
        bytes(ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2")),
    ),
    # 4. unsupported: UDP trên IPv6
    (
        "unsupported IPv6",
        bytes(
            ether()
            / IPv6(src="fe80::1", dst="fe80::2")
            / UDP(sport=5000, dport=53)
        ),
    ),
    # 5. hợp lệ: HTTP request
    ("valid HTTP", bytes(ether() / ip() / tcp() / PAYLOAD)),
]


def main() -> None:
    with RawPcapWriter(str(OUTPUT), linktype=LINKTYPE_ETHERNET) as writer:
        for _, frame in FRAMES:
            writer.write(frame)
    print(f"wrote {len(FRAMES)} frames to {OUTPUT}")
    for number, (title, frame) in enumerate(FRAMES, start=1):
        print(f"  packet {number}: {title}, {len(frame)} bytes")


if __name__ == "__main__":
    main()

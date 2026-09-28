"""Generate input.pcap for tc12: six malformed packets followed by a valid one."""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter

OUTPUT = Path(__file__).with_name("input.pcap")
LINKTYPE_ETHERNET = 1

ETHER_LEN = 14
IPV4_LEN = 20

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
SRC_PORT = 40000
DST_PORT = 80
PAYLOAD = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"


def ether() -> Ether:
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ip(**fields) -> IP:
    return IP(src=SRC_IP, dst=DST_IP, **fields)


def tcp(**fields) -> TCP:
    return TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA", **fields)


def build_frames() -> list[bytes]:
    valid = bytes(ether() / ip() / tcp() / PAYLOAD)

    return [
        # 1. link: frame shorter than the Ethernet header
        valid[:10],
        # 2. network: IPv4 header cut after 10 bytes
        bytes(ether() / ip() / tcp())[: ETHER_LEN + 10],
        # 3. network: ihl claims a 12-byte header
        bytes(ether() / ip(ihl=3) / tcp()),
        # 4. network: ip_len claims 1000 bytes
        bytes(ether() / ip(len=1000) / tcp()),
        # 5. transport: TCP header cut after 8 bytes
        bytes(ether() / ip() / tcp())[: ETHER_LEN + IPV4_LEN + 8],
        # 6. transport: dataofs claims an 8-byte header
        bytes(ether() / ip() / tcp(dataofs=2)),
        # 7. valid HTTP request
        valid,
    ]


def main() -> None:
    frames = build_frames()

    with RawPcapWriter(str(OUTPUT), linktype=LINKTYPE_ETHERNET) as writer:
        for frame in frames:
            writer.write(frame)

    print(f"wrote {len(frames)} frames to {OUTPUT}")
    for number, frame in enumerate(frames, start=1):
        print(f"  packet {number}: {len(frame)} bytes")


if __name__ == "__main__":
    main()

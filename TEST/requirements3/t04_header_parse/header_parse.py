# T04: nạp test.rules qua load_rules rồi in phần header của Internal Rule Object
# chạy từ thư mục gốc project: PYTHONPATH=. python TEST/requirements3/t04_header_parse/header_parse.py

from ipaddress import IPv4Network

from idscore.config import load_config
from idscore.detection.loader import load_rules

CONFIG = "TEST/requirements3/t04_header_parse/config.yaml"

# kỳ vọng tính tay cho từng sid: (protocol, src_ip, src_port, direction, dst_ip, dst_port)
EXPECTED = {
    3040001: ("TCP", None, None, "->", None, None),
    3040002: ("TCP", IPv4Network("127.0.0.1/32"), None, "->", None, None),
    3040003: ("TCP", IPv4Network("10.0.0.0/8"), None, "->", None, None),
    3040004: ("TCP", None, None, "->", None, (80, 80)),
    3040005: ("TCP", None, (1024, 65535), "->", None, None),
    3040006: ("TCP", None, (0, 1023), "->", None, (8000, 65535)),
    3040007: ("UDP", None, None, "->", IPv4Network("8.8.8.8/32"), (53, 53)),
    3040008: ("IP", IPv4Network("192.168.1.0/24"), None, "->", None, None),
    3040009: ("TCP", None, (80, 80), "<>", IPv4Network("10.0.0.1/32"), None),
}


def show(value: object) -> str:
    return "None" if value is None else str(value)


rules = load_rules(load_config(CONFIG)["detection"])
failed = 0
for rule in rules:
    header = (
        rule.protocol,
        rule.src_ip,
        rule.src_port,
        rule.direction,
        rule.dst_ip,
        rule.dst_port,
    )
    ok = rule.status == "valid" and header == EXPECTED[rule.sid]
    failed += not ok
    print(f"[{rule.sid}] line {rule.line_no}: {rule.raw.split(' (')[0]}")
    print(
        f"    protocol={rule.protocol} src_ip={show(rule.src_ip)} src_port={show(rule.src_port)} "
        f"direction={rule.direction} dst_ip={show(rule.dst_ip)} dst_port={show(rule.dst_port)}"
    )
    print(f"    status={rule.status} | {'khớp kỳ vọng' if ok else 'SAI KỲ VỌNG'}")
print(f"rules: {len(rules)}, sai kỳ vọng: {failed}")
raise SystemExit(1 if failed else 0)

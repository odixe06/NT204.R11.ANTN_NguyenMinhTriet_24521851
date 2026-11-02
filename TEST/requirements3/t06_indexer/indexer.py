# T06: dựng RuleRepository từ test.rules, in nội dung index rồi in candidate của các event dựng tay
# chạy từ thư mục gốc project: PYTHONPATH=. python TEST/requirements3/t06_indexer/indexer.py

import json

from idscore.config import load_config
from idscore.detection.loader import load_rules
from idscore.detection.repository import RuleRepository
from idscore.models.event import Event

CONFIG = "TEST/requirements3/t06_indexer/config.yaml"

BASE = {"source": "fake", "source_type": "pcap", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}

# (mô tả, event, candidate kỳ vọng tính tay theo thứ tự nạp)
CASES = [
    ("TCP 40000 -> 80", Event(packet_id=1, timestamp=1.0, transport_protocol="TCP", src_port=40000, dst_port=80, **BASE),
     [3060001, 3060002, 3060003, 3060004, 3060007]),
    ("TCP 80 -> 40000", Event(packet_id=2, timestamp=2.0, transport_protocol="TCP", src_port=80, dst_port=40000, **BASE),
     [3060001, 3060002, 3060003, 3060004, 3060007]),
    ("TCP 40000 -> 5000", Event(packet_id=3, timestamp=3.0, transport_protocol="TCP", src_port=40000, dst_port=5000, **BASE),
     [3060002, 3060003, 3060007]),
    ("UDP 40000 -> 53", Event(packet_id=4, timestamp=4.0, transport_protocol="UDP", src_port=40000, dst_port=53, **BASE),
     [3060005, 3060006, 3060007]),
    ("UDP 40000 -> 123", Event(packet_id=5, timestamp=5.0, transport_protocol="UDP", src_port=40000, dst_port=123, **BASE),
     [3060006, 3060007]),
    ("UNKNOWN không có transport", Event(packet_id=6, timestamp=6.0, parse_status="UNKNOWN", **BASE),
     []),
]

repository = RuleRepository(load_rules(load_config(CONFIG)["detection"]))
print("stats   :", json.dumps(repository.stats()))
print("describe:", json.dumps(repository.describe()))

failed = 0
for title, event, expected in CASES:
    got = [rule.sid for rule in repository.candidates(event)]
    ok = got == expected
    failed += not ok
    print(f"[{event.packet_id}] {title}")
    print(f"    candidates: {got}")
    print(f"    kỳ vọng   : {expected} | {'khớp' if ok else 'SAI'}")
print(f"events: {len(CASES)}, sai kỳ vọng: {failed}")
raise SystemExit(1 if failed else 0)

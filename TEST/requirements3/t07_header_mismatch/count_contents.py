# T07: chạy cli.main như lệnh python main.py, bọc matcher._match_contents để đếm số lần mỗi rule
# được đưa tới bước so content; rule sai header phải có 0 lần
# chạy từ thư mục gốc project: PYTHONPATH=. python TEST/requirements3/t07_header_mismatch/count_contents.py

from collections import Counter
from unittest.mock import patch

from idscore import cli
from idscore.detection import matcher

D = "TEST/requirements3/t07_header_mismatch"
SIDS = (3070001, 3070002, 3070003, 3070004)

calls: Counter = Counter()
real_match_contents = matcher._match_contents


def counting_match_contents(rule, event):
    calls[rule.sid] += 1
    return real_match_contents(rule, event)


argv = [
    "--pcap", f"{D}/input.pcap",
    "--output", f"{D}/events.jsonl",
    "--flow-output", f"{D}/flows.jsonl",
    "--detection-output", f"{D}/detections.jsonl",
    "--log-file", f"{D}/run_log.txt",
    "--config", f"{D}/config.yaml",
]
with patch.object(matcher, "_match_contents", counting_match_contents):
    code = cli.main(argv)

print("exit code:", code)
for sid in SIDS:
    print(f"sid {sid}: _match_contents gọi {calls[sid]} lần")

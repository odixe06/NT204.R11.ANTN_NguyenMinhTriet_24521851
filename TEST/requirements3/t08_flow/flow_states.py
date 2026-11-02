# T08: chạy lại pcap qua pipeline giống cli.py và in FlowContext của từng packet
# (events.jsonl không có state của flow), kèm sid khớp lấy từ detections.jsonl để đối chiếu
# chạy từ thư mục gốc project: PYTHONPATH=. python TEST/requirements3/t08_flow/flow_states.py

import json

from idscore.capture.pcap import PcapCapture
from idscore.cli import _decode_safely, _preprocess_safely, _process_safely, _track_safely, build_pipeline
from idscore.config import load_config
from idscore.decoder.decoder import Decoder
from idscore.flow.tracker import FlowTracker
from idscore.preprocessor.preprocessor import Preprocessor

D = "TEST/requirements3/t08_flow"

matched: dict[int, list[int]] = {}
for line in open(f"{D}/detections.jsonl", encoding="utf-8"):
    detection = json.loads(line)
    matched.setdefault(detection["packet_id"], []).append(detection["sid"])

config = load_config(f"{D}/config.yaml")
pipeline, decoder = build_pipeline(config), Decoder()
preprocessor, tracker = Preprocessor(config), FlowTracker(config)
capture = PcapCapture(f"{D}/input.pcap")
for packet_id, (packet, timestamp) in enumerate(capture.packets(), start=1):
    event = _process_safely(pipeline, packet, timestamp, packet_id, capture)
    _decode_safely(decoder, event)
    _preprocess_safely(preprocessor, event)
    _track_safely(tracker, event)
    ctx = tracker.context_of(event)
    print(
        f"#{packet_id:<2} {event.tcp_flags:8} payload={event.payload_len:<3} "
        f"direction={ctx.direction:8} from_client={str(ctx.from_client):5} state={ctx.state:11} "
        f"sid={matched.get(packet_id, [])}"
    )

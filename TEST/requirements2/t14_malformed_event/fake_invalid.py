from idscore.config import load_config
from idscore.decoder.decoder import Decoder
from idscore.flow.tracker import FlowTracker
from idscore.models.event import Event
from idscore.preprocessor.preprocessor import Preprocessor

BASE = {
    "source": "fake",
    "source_type": "pcap",
    "ip_version": 4,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 40000,
    "transport_protocol": "TCP",
    "tcp_flags": "PSH-ACK",
}

CASES = [
    ("dst_port ngoài khoảng", Event(packet_id=1, timestamp=1.0, **{**BASE, "dst_port": 70000})),
    ("src_ip không hợp lệ", Event(packet_id=2, timestamp=2.0, **{**BASE, "src_ip": "999.1.1.1", "dst_port": 80})),
    ("timestamp không phải số", Event(packet_id=3, timestamp="abc", **{**BASE, "dst_port": 80})),
    ("transport_protocol lạ", Event(packet_id=4, timestamp=4.0, **{**BASE, "transport_protocol": "SCTP", "dst_port": 80})),
    ("app_protocol lạ", Event(packet_id=5, timestamp=5.0, **{**BASE, "dst_port": 21, "app_protocol": "FTP", "app": {}})),
]

config = load_config("config/default.yaml")
decoder, preprocessor, tracker = Decoder(), Preprocessor(config), FlowTracker(config)

for title, event in CASES:
    decoder.decode(event)
    preprocessor.process(event)
    tracker.process(event)
    print(f"[{event.packet_id}] {title}")
    print(f"    preprocess_status: {event.preprocess_status} | action: {event.processing_action}")
    print(f"    reason : {event.reason}")
    print(f"    errors : {event.errors}")
    print(f"    flow_id: {event.flow_id}")

print("flows:", len(tracker.flush()))

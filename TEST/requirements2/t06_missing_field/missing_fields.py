import json

from idscore.config import load_config
from idscore.decoder.decoder import Decoder
from idscore.flow.tracker import FlowTracker
from idscore.models.event import Event
from idscore.preprocessor.preprocessor import Preprocessor

BASE = {"source": "fake", "source_type": "pcap", "ip_version": 4}
TCP = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "transport_protocol": "TCP",
       "tcp_flags": "PSH-ACK", "src_port": 40000}
UDP = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "transport_protocol": "UDP",
       "src_port": 40001}

CASES = [
    ("HTTP request, không có headers và body", Event(
        packet_id=1, timestamp=1.0, **BASE, **TCP, dst_port=80,
        app_protocol="HTTP", app={"message_type": "request", "method": "GET", "uri": "/"},
        errors=None, reason=None)),
    ("HTTP response, headers là None", Event(
        packet_id=2, timestamp=2.0, **BASE, **TCP, dst_port=80,
        app_protocol="HTTP", app={"message_type": "response", "status_code": 200, "headers": None})),
    ("DNS, answers là None", Event(
        packet_id=3, timestamp=3.0, **BASE, **UDP, dst_port=53,
        app_protocol="DNS", app={"questions": [{"name": "a.com", "qtype": 1}], "answers": None})),
    ("SMTP command, không có commands", Event(
        packet_id=4, timestamp=4.0, **BASE, **TCP, dst_port=25,
        app_protocol="SMTP", app={"message_type": "command"})),
    ("UDP, không có app", Event(
        packet_id=5, timestamp=5.0, **BASE, **UDP, dst_port=9999)),
]

config = load_config("config/default.yaml")
decoder, preprocessor, tracker = Decoder(), Preprocessor(config), FlowTracker(config)

for title, event in CASES:
    decoder.decode(event)
    preprocessor.process(event)
    tracker.process(event)
    out = event.to_dict()
    print(f"[{event.packet_id}] {title}")
    print("    app              :", json.dumps(out.get("app"), ensure_ascii=False))
    print("    errors / reason  :", out.get("errors"), "/", out.get("reason"))
    print("    preprocess_status:", out.get("preprocess_status"), "| action:", out.get("processing_action"))
    print("    flow_id          :", out.get("flow_id"))

print("flows:", len(tracker.flush()))
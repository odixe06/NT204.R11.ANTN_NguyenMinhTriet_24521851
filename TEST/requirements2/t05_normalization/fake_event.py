import json

from idscore.config import load_config
from idscore.models.event import Event
from idscore.preprocessor.preprocessor import Preprocessor

event = Event(
    packet_id=1,
    timestamp="1790604355.5",
    source="fake",
    source_type="pcap",
    src_ip=" 10.0.0.1 ",
    dst_ip="10.0.0.2",
    ip_version=4,
    ip_proto=6,
    src_port=40000,
    dst_port=80,
    transport_protocol=" tcp ",
    tcp_flags="PSH-ACK",
    app_protocol="http",
    app={
        "message_type": "request",
        "method": "GET",
        "uri": "/A/./b/../c//d/?q=1",
        "headers": {"Host": "WWW.Example.COM.:80", "X-Test": "one", "x-TEST": "two"},
    },
)

print("before:", json.dumps(event.to_dict(), ensure_ascii=False))
Preprocessor(load_config("config/default.yaml")).process(event)
print("after :", json.dumps(event.to_dict(), ensure_ascii=False))
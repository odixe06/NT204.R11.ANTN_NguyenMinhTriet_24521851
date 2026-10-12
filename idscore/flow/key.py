# file key dùng để định danh cho flow

import hashlib
import ipaddress
from typing import Any

from idscore.models.event import Event

FLOW_PROTOCOLS = frozenset({"TCP", "UDP"})
FLOW_ID_LEN = 16
FIELD_SEPARATOR = "|"

# endpoint là cặp ip:port
Endpoint = tuple[str, int] 
# flow key là 5 tuple gồm protocol (udp/tcp), ip:port của 2 bên 
FlowKey = tuple[str, Endpoint, Endpoint]

# hàm này nhận event tạo ra 1 flow-key hoặc None    
# sau này khi có packet thì sẽ dựa vào flow key này để tra 
# packet thuộc flow nào
def make_flow_key(event: Event) -> FlowKey | None:

    # chỉ tạo flow key khi đủ 5 tuple 
    protocol = event.transport_protocol
    if not isinstance(protocol, str) or protocol not in FLOW_PROTOCOLS:
        return None

    first = _endpoint(event.src_ip, event.src_port)
    second = _endpoint(event.dst_ip, event.dst_port)
    if first is None or second is None:
        return None

    first, second = sorted((first, second), key=_endpoint_order)
    return protocol, first, second

# có flow key -> băm các giá trị flowkey + timestamp
# -> ra được flow id
def make_flow_id(key: FlowKey, start_time: float) -> str:
    protocol, (first_ip, first_port), (second_ip, second_port) = key
    material = FIELD_SEPARATOR.join(
        (
            protocol,
            first_ip,
            str(first_port),
            second_ip,
            str(second_port),
            repr(float(start_time)),
        )
    )
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:FLOW_ID_LEN]

# định nghĩa endpoint
def _endpoint(ip: Any, port: Any) -> Endpoint | None:
    if not isinstance(ip, str):
        return None
    if not isinstance(port, int) or isinstance(port, bool):
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(address), port

# hàm sắp xếp các endpoint 
def _endpoint_order(endpoint: Endpoint) -> tuple[int, int, int]:
    address = ipaddress.ip_address(endpoint[0])
    return address.version, int(address), endpoint[1]

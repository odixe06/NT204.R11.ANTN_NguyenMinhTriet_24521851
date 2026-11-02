# file này là Detection Event Generator: dựng DetectionEvent từ một rule đã khớp
# hợp đồng của module; hàm công khai duy nhất là generate()
#
# chiều phụ thuộc: generator chỉ dùng idscore.models (Rule, Event, FlowContext, DetectionEvent,
# ContentMatch); không import matcher, repository hay engine
#
# input : Rule, Event, FlowContext | None, list[ContentMatch]
# output: DetectionEvent đầy đủ field mục 4.6, field thiếu giá trị ghi None
#         (timestamp lấy từ Event, không lấy giờ hệ thống; có packet_id để tra về events.jsonl)
#
# generator KHÔNG được:
#   - so khớp rule (việc của matcher)
#   - in, ghi file hay gửi cảnh báo
#   - sửa Rule, Event hay FlowContext

from idscore.models.detection import ContentMatch, DetectionEvent
from idscore.models.event import UNKNOWN_APP_PROTOCOL, Event
from idscore.models.flow import FlowContext
from idscore.models.rule import Rule


# hàm thuần, không trạng thái: engine chỉ cần gọi
def generate(
    rule: Rule, event: Event, ctx: FlowContext | None, matches: list[ContentMatch]
) -> DetectionEvent:
    # rule valid luôn có sid và msg nên thiếu là lỗi lập trình, raise để engine bắt và đếm lỗi
    # thay vì đoán giá trị điền vào
    if rule.sid is None or rule.msg is None:
        raise ValueError(
            f"rule {rule.source_file}:{rule.line_no} has no sid or msg, cannot build a detection event"
        )

    # application_protocol: cảnh báo nói về packet này nên ưu tiên event; SYN/ACK rỗng có
    # app_protocol UNKNOWN nhưng flow đã biết là HTTP/SMTP nên lấy từ flow
    app_protocol = event.app_protocol
    if app_protocol is None or app_protocol == UNKNOWN_APP_PROTOCOL:
        app_protocol = ctx.application_protocol if ctx is not None else None

    return DetectionEvent(
        packet_id=event.packet_id,
        timestamp=event.timestamp, # của event, không phải giờ hệ thống
        sid=rule.sid,
        rev=rule.rev,
        msg=rule.msg,
        priority=rule.priority,
        classtype=rule.classtype,
        # 5-tuple và protocol của packet thật, không lấy từ rule: rule <> khớp cả gói ngược chiều
        # và rule ip cần ghi TCP/UDP thật
        src_ip=event.src_ip,
        src_port=event.src_port,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        protocol=event.transport_protocol,
        application_protocol=app_protocol,
        flow_id=ctx.flow_id if ctx is not None else event.flow_id,
        matches=list(matches), # bản sao, nơi gọi sửa list sau đó không ảnh hưởng
    )

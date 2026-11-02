# file này là Rule Repository / Indexer: lưu các rule valid và chọn rule ứng viên cho một event
# hợp đồng của module; API: RuleRepository(rules), candidates(event), stats(), describe(), rules, len()
#
# chiều phụ thuộc: repository chỉ dùng idscore.models (Rule, Event), không import matcher,
# generator hay engine
#
# input : list[Rule] từ loader (chỉ nhận rule valid); khi tra cứu: một Event
# output: candidates(event) -> list[Rule], tập ứng viên theo protocol (IP, TCP, UDP) và port,
#         giữ thứ tự nạp; đây là tập thừa, matcher mới quyết định match thật
#
# loader không kiểm tra sid trùng giữa các rule nên repository xử lý khi nhận rule valid:
# cảnh báo và giữ rule nạp trước, nếu không một sid sinh hai Detection Event
#
# index dựng một lần trong constructor, chỉ theo protocol và port (không theo IP: phần lớn rule dùng
# any, index CIDR cần prefix tree mà lợi ích không đáng); bucket chỉ lưu số thứ tự nạp của rule
#
# repository KHÔNG được:
#   - so khớp content, flags, dsize hay flow (việc của matcher)
#   - parse rule hoặc đọc file (việc của rule_parser, loader)
#   - sửa Rule sau khi đã index, hay sửa Event

import logging
from dataclasses import dataclass, field

from idscore.models.event import Event
from idscore.models.rule import (
    RULE_PROTO_IP,
    RULE_PROTO_TCP,
    RULE_PROTO_UDP,
    RULE_VALID,
    PortRange,
    Rule,
)

logger = logging.getLogger(__name__)


# index theo port của một protocol; mỗi rule vào đúng một bucket, giá trị là số thứ tự nạp
@dataclass
class _PortIndex:
    exact: dict[int, list[int]] = field(default_factory=dict) # port đơn -> các rule
    ranges: list[tuple[int, int, int]] = field(default_factory=list) # (low, high, rule)
    any: list[int] = field(default_factory=list) # cả hai port đều any


def _is_single(port: PortRange | None) -> bool:
    return port is not None and port[0] == port[1]


class RuleRepository:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules: list[Rule] = [] # rule valid, vị trí trong list là thứ tự nạp
        self._tcp = _PortIndex()
        self._udp = _PortIndex()
        self._ip_rules: list[int] = [] # rule ip khớp cả TCP lẫn UDP, port luôn any
        self.skipped_not_valid = 0
        self.duplicate_sid = 0

        by_sid: dict[int, Rule] = {}
        for rule in rules:
            if rule.status != RULE_VALID:
                # loader đã cảnh báo từng rule hỏng, ở đây chỉ đếm để không log trùng
                self.skipped_not_valid += 1
                logger.debug("Rule %s:%d is %s, not indexed", rule.source_file, rule.line_no, rule.status)
                continue
            first = by_sid.get(rule.sid) if rule.sid is not None else None
            if first is not None:
                # giữ rule nạp trước vì thứ tự rule_files là thứ tự ưu tiên người cấu hình chọn
                # (chưa chắc Snort xử lý sid trùng thế nào; Snort định danh bằng gid:sid, gid chưa hỗ trợ)
                self.duplicate_sid += 1
                logger.warning(
                    "Rule %s:%d has the same sid %d as %s:%d, skipped",
                    rule.source_file, rule.line_no, rule.sid, first.source_file, first.line_no,
                )
                continue
            if rule.protocol not in (RULE_PROTO_TCP, RULE_PROTO_UDP, RULE_PROTO_IP):
                self.skipped_not_valid += 1
                logger.warning(
                    "Rule %s:%d has protocol %r that cannot be indexed, skipped",
                    rule.source_file, rule.line_no, rule.protocol,
                )
                continue
            if rule.sid is not None:
                by_sid[rule.sid] = rule
            self._add(rule)

        stats = self.stats()
        logger.info(
            "Rules indexed: indexed=%d skipped_not_valid=%d duplicate_sid=%d",
            stats["indexed"], stats["skipped_not_valid"], stats["duplicate_sid"],
        )

    # chọn bucket cho rule: port đơn (ưu tiên dst) > range (ưu tiên dst) > any
    # chỉ index theo một bên là đủ vì rule cần cả hai port khớp; bước tra cứu sẽ tra cả
    # src_port lẫn dst_port của event nên rule <> không cần xử lý riêng
    def _add(self, rule: Rule) -> None:
        position = len(self._rules)
        self._rules.append(rule)
        if rule.protocol == RULE_PROTO_IP:
            self._ip_rules.append(position)
            return

        index = self._tcp if rule.protocol == RULE_PROTO_TCP else self._udp
        src, dst = rule.src_port, rule.dst_port
        single = next((p for p in (dst, src) if _is_single(p)), None)
        if single is not None:
            index.exact.setdefault(single[0], []).append(position)
            return
        ranged = next((p for p in (dst, src) if p is not None), None)
        if ranged is not None:
            index.ranges.append((ranged[0], ranged[1], position))
        else:
            index.any.append(position)

    # truy cập chỉ đọc: index dựng một lần, không có hàm thêm hay xóa rule
    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    # tập rule ứng viên cho một event, theo thứ tự nạp; là tập thừa, matcher mới quyết định match thật
    # không xét IP, direction, flow, flags, dsize, content, cũng không xét preprocess_status hay
    # processing_action của event (bỏ qua event bị drop là việc của engine)
    def candidates(self, event: Event) -> list[Rule]:
        if event.transport_protocol == RULE_PROTO_TCP:
            index = self._tcp
        elif event.transport_protocol == RULE_PROTO_UDP:
            index = self._udp
        else:
            # UNKNOWN hoặc malformed không có transport nên không khớp rule nào, kể cả rule ip
            return []

        found = set(self._ip_rules)
        found.update(index.any)
        # tra cả src_port lẫn dst_port để rule <> không bị sót; port None thì bỏ qua phần có port cụ thể
        ports = {p for p in (event.src_port, event.dst_port) if isinstance(p, int)}
        for port in ports:
            found.update(index.exact.get(port, ()))
        for low, high, position in index.ranges:
            if any(low <= port <= high for port in ports):
                found.add(position)
        # list mới mỗi lần gọi để nơi gọi sửa cũng không ảnh hưởng index
        return [self._rules[position] for position in sorted(found)]

    # thống kê tĩnh của index (không đếm số lần gọi candidates, đó là việc của Evaluation Engine)
    # tổng rule ở mọi bucket cộng IP phải bằng indexed
    def stats(self) -> dict:
        def group(index: _PortIndex) -> dict:
            return {
                "exact_ports": len(index.exact),
                "exact_rules": sum(len(v) for v in index.exact.values()),
                "ranges": len(index.ranges),
                "any": len(index.any),
            }

        return {
            "indexed": len(self._rules),
            "skipped_not_valid": self.skipped_not_valid,
            "duplicate_sid": self.duplicate_sid,
            "TCP": group(self._tcp),
            "UDP": group(self._udp),
            "IP": len(self._ip_rules),
        }

    # nội dung bucket dạng sid thay cho số thứ tự nạp, dict/list mới (port exact sắp tăng dần)
    def describe(self) -> dict:
        def sids(positions) -> list[int | None]:
            return [self._rules[position].sid for position in positions]

        def group(index: _PortIndex) -> dict:
            return {
                "exact": {port: sids(index.exact[port]) for port in sorted(index.exact)},
                "ranges": [[low, high, self._rules[pos].sid] for low, high, pos in index.ranges],
                "any": sids(index.any),
            }

        return {"TCP": group(self._tcp), "UDP": group(self._udp), "IP": sids(self._ip_rules)}

# file này là Rule Loader: đọc các file .rules và đưa từng dòng sang rule_parser
# hàm công khai duy nhất là load_rules(config["detection"]) -> list[Rule]; các hàm còn lại là nội bộ
# (_select_rule_files, _read_rule_file, _split_rule_lines, _parse_safely, _warn_rule)
# nơi gọi (cli.py) chỉ cần gọi load_rules một lần lúc khởi động rồi đưa kết quả cho repository
#
# chiều phụ thuộc (một chiều, không import ngược):
#   loader -> rule_parser;  kết quả của loader được nơi gọi đưa vào repository
#   engine -> repository, matcher, generator;  matcher không import generator
#   không module nào trong detection/ import Scapy
#
# input : config["detection"] (rule_files, disabled_files, disabled_sids)
# output: list[Rule] theo thứ tự đọc, mỗi Rule đã có status valid/invalid/unsupported;
#         rule bị disabled_sids không có trong list; kiểu trả về không kèm thống kê,
#         số liệu của lượt nạp nằm ở một dòng log tổng kết cuối load_rules
#
# việc của loader:
#   - mỗi rule nằm trên một dòng; bỏ dòng trống và dòng bắt đầu bằng #
#   - bỏ qua file nằm trong disabled_files, bỏ rule có sid nằm trong disabled_sids
#   - file thiếu hoặc không đọc được: cảnh báo rồi nạp tiếp file khác, không dừng
#   - rule invalid/unsupported: cảnh báo nêu source_file, line_no và reasons, nạp tiếp
#
# loader KHÔNG được:
#   - tự phân tích cú pháp rule (việc của rule_parser)
#   - kiểm tra kiểu config (việc của config.py)
#   - lập index hay so khớp packet (việc của repository, matcher)

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from idscore.detection.rule_parser import parse_rule
from idscore.models.rule import (
    RULE_INVALID,
    RULE_STATUSES,
    RULE_UNSUPPORTED,
    RULE_VALID,
    Rule,
)

logger = logging.getLogger(__name__)

UTF8_BOM = b"\xef\xbb\xbf"
COMMENT_PREFIX = "#"


# chọn danh sách file .rules cần nạp từ config["detection"]
# nhận dict chứ không tự gọi load_config, để testcase truyền được config riêng
# không kiểm tra file có tồn tại, việc mở file và mọi lỗi file gom ở một chỗ khi đọc file
def _select_rule_files(detection_cfg: dict[str, Any]) -> list[str]:
    # normpath để "./rules/a.rules" và "rules/a.rules" được coi là cùng một file
    rule_files = [os.path.normpath(path) for path in detection_cfg["rule_files"]]
    disabled = {os.path.normpath(path) for path in detection_cfg["disabled_files"]}

    # bỏ file trùng nhưng giữ thứ tự xuất hiện đầu tiên, vì thứ tự nạp là thứ tự rule
    unique = list(dict.fromkeys(rule_files))
    if len(unique) < len(rule_files):
        logger.debug("Duplicate entries in detection.rule_files are loaded once")

    # file bị tắt vốn không nằm trong rule_files thường là gõ sai tên
    for path in sorted(disabled - set(unique)):
        logger.warning(
            "File '%s' in detection.disabled_files is not in detection.rule_files", path
        )

    selected = []
    for path in unique:
        if path in disabled:
            logger.info("Rule file '%s' is disabled, skipped", path)
        else:
            selected.append(path)

    if not selected:
        logger.info("No rule file is loaded, detection has no rules")
    return selected


# đọc toàn bộ file dạng bytes, chưa decode: lỗi decode sẽ chỉ ảnh hưởng đúng dòng bị lỗi
# OSError gồm file thiếu, nhầm thư mục, không có quyền; chỉ cảnh báo để nơi gọi nạp file kế tiếp
# không bắt Exception chung: đọc bytes không có lỗi decode, lỗi khác là lỗi lập trình
def _read_rule_file(path: str) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as error:
        logger.warning("Cannot read rule file '%s': %s", path, error)
        return None


# tách bytes của một file thành các dòng rule, giữ đúng thứ tự trong file
# trả về list gồm: (line_no, text) cho dòng cần đưa sang parser,
# và Rule invalid cho dòng không phải UTF-8 hợp lệ (chỉ gắn trạng thái, không phân tích cú pháp)
# chưa gọi parse_rule, việc đó thuộc bước nạp rule
def _split_rule_lines(data: bytes, source_file: str) -> list[tuple[int, str] | Rule]:
    # file soạn trên Windows có thể có BOM, nếu không bỏ thì dòng đầu có \ufeff trước "alert"
    if data.startswith(UTF8_BOM):
        data = data[len(UTF8_BOM):]

    items: list[tuple[int, str] | Rule] = []
    # bytes.splitlines chỉ tách ở \n, \r, \r\n nên line_no khớp số dòng trong editor
    for line_no, raw_line in enumerate(data.splitlines(), start=1):
        stripped = raw_line.strip()
        # dòng trống và comment bỏ qua trước khi decode, để comment có byte lạ không bị tính là lỗi
        if not stripped or stripped.startswith(COMMENT_PREFIX.encode()):
            continue
        try:
            text = stripped.decode("utf-8")
        except UnicodeDecodeError as error:
            # không dùng errors="replace" cho parser: ký tự thay thế có thể lọt vào content
            items.append(
                Rule(
                    source_file=source_file,
                    line_no=line_no,
                    raw=stripped.decode("utf-8", errors="replace"),
                    status=RULE_INVALID,
                    reasons=[f"line is not valid UTF-8: {error}"],
                )
            )
            continue
        text = text.strip()
        # chỉ bỏ dòng bắt đầu bằng #, không cắt # giữa dòng vì content:"#" hay msg:"..#1" là hợp lệ
        if not text or text.startswith(COMMENT_PREFIX):
            continue
        items.append((line_no, text))
    return items


# bộ đếm của một lượt nạp, dùng cho dòng tổng kết
@dataclass
class _LoadStats:
    files_loaded: int = 0
    files_failed: int = 0
    # số rule trả về theo từng status
    rules: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(RULE_STATUSES, 0)
    )
    # rule bị lọc bởi disabled_sids không còn trong kết quả nên phải đếm lúc lọc
    rules_disabled: int = 0


# gọi parse_rule cho một dòng; parser không được raise nhưng đây là ranh giới sang module khác
# với input không tin cậy, nên một dòng lỗi không được làm hỏng việc nạp cả bộ rule
def _parse_safely(text: str, source_file: str, line_no: int) -> Rule:
    try:
        rule = parse_rule(text, source_file, line_no)
        # status ngoài RULE_STATUSES (ví dụ "Valid") sẽ làm bộ đếm KeyError, nên đổi thành invalid;
        # giữ nguyên rule để sid vẫn được disabled_sids lọc
        if not isinstance(rule, Rule):
            raise TypeError(f"parse_rule returned {type(rule).__name__}, expected Rule")
        if rule.status not in RULE_STATUSES:
            rule.reasons.append(f"rule_parser returned unknown status {rule.status!r}")
            rule.status = RULE_INVALID
        return rule
    except Exception as exc:
        logger.error("Rule %s:%d could not be parsed: %r", source_file, line_no, exc)
        logger.info("Traceback of rule %s:%d", source_file, line_no, exc_info=True)
        return Rule(
            source_file=source_file,
            line_no=line_no,
            raw=text,
            status=RULE_INVALID,
            reasons=[f"rule_parser raised {exc!r}"],
        )


# mỗi rule invalid/unsupported một dòng warning, chỉ ra rule nằm ở đâu và vì sao
def _warn_rule(rule: Rule) -> None:
    sid = f" (sid {rule.sid})" if rule.sid is not None else ""
    logger.warning(
        "Rule %s:%d%s is %s: %s",
        rule.source_file,
        rule.line_no,
        sid,
        rule.status,
        "; ".join(rule.reasons) or "no reason given",
    )


# một dòng tổng kết dạng key=value, thứ tự key cố định để grep được trong log
# warning khi có file được chọn mà không còn rule valid nào: IDS vẫn chạy nhưng sẽ không phát hiện gì
# không có file nào được chọn (detection tắt chủ ý) thì giữ info, _select_rule_files đã log rồi
def _log_summary(stats: _LoadStats) -> None:
    message = (
        "Rules loaded: files=%d failed_files=%d valid=%d invalid=%d unsupported=%d disabled=%d"
    )
    args = (
        stats.files_loaded,
        stats.files_failed,
        stats.rules[RULE_VALID],
        stats.rules[RULE_INVALID],
        stats.rules[RULE_UNSUPPORTED],
        stats.rules_disabled,
    )
    files_selected = stats.files_loaded + stats.files_failed
    if files_selected and not stats.rules[RULE_VALID]:
        logger.warning(message, *args)
    else:
        logger.info(message, *args)


# nạp mọi rule từ các file trong config["detection"]
# trả về cả rule invalid và unsupported, giữ thứ tự file rồi thứ tự dòng;
# lọc lấy rule valid là việc của repository
def load_rules(detection_cfg: dict[str, Any]) -> list[Rule]:
    stats = _LoadStats()
    disabled_sids = set(detection_cfg["disabled_sids"])
    matched_sids: set[int] = set()
    loaded: list[Rule] = []

    for path in _select_rule_files(detection_cfg):
        data = _read_rule_file(path)
        if data is None:
            stats.files_failed += 1
            continue
        stats.files_loaded += 1

        for item in _split_rule_lines(data, path):
            # Rule invalid từ bước tách dòng đã có đủ thông tin, không đưa lại cho parser
            if isinstance(item, Rule):
                rule = item
            else:
                line_no, text = item
                rule = _parse_safely(text, path, line_no)

            # lọc cả rule invalid để tắt được rule hỏng; sid None thì không lọc
            if rule.sid is not None and rule.sid in disabled_sids:
                matched_sids.add(rule.sid)
                stats.rules_disabled += 1
                logger.debug(
                    "Rule %s:%d (sid %d) is disabled, skipped",
                    rule.source_file,
                    rule.line_no,
                    rule.sid,
                )
                continue

            if rule.status != RULE_VALID:
                _warn_rule(rule)
            stats.rules[rule.status] += 1
            loaded.append(rule)

    # sid không khớp rule nào thường là gõ sai
    for sid in sorted(disabled_sids - matched_sids):
        logger.warning("sid %d in detection.disabled_sids matches no loaded rule", sid)

    _log_summary(stats)
    return loaded

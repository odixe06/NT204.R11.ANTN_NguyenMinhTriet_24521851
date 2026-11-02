# file này là Rule Loader: đọc các file .rules và đưa từng dòng sang rule_parser
# hợp đồng của module; hiện mới có chọn file (select_rule_files), đọc file và tách dòng
#
# chiều phụ thuộc (một chiều, không import ngược):
#   loader -> rule_parser;  kết quả của loader được nơi gọi đưa vào repository
#   engine -> repository, matcher, generator;  matcher không import generator
#   không module nào trong detection/ import Scapy
#
# input : config["detection"] (rule_files, disabled_files, disabled_sids)
# output: list[Rule] theo thứ tự đọc, mỗi Rule đã có status valid/invalid/unsupported
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
from typing import Any

from idscore.models.rule import RULE_INVALID, Rule

logger = logging.getLogger(__name__)

UTF8_BOM = b"\xef\xbb\xbf"
COMMENT_PREFIX = "#"


# chọn danh sách file .rules cần nạp từ config["detection"]
# nhận dict chứ không tự gọi load_config, để testcase truyền được config riêng
# không kiểm tra file có tồn tại, việc mở file và mọi lỗi file gom ở một chỗ khi đọc file
def select_rule_files(detection_cfg: dict[str, Any]) -> list[str]:
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

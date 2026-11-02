# file này là Rule Loader: đọc các file .rules và đưa từng dòng sang rule_parser
# hợp đồng của module; hiện mới có phần chọn file cần nạp (select_rule_files)
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

logger = logging.getLogger(__name__)


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

# khác với jsonl writer, chỉ dùng để ghi các thông tin chạy của chương trình:
# số gói tin đã bắt, nguồn thu gói tin,...

# k ghi thông tin event
# 2026-09-28 17:30:01 INFO idscore.cli: reading pcap data/pcap/sample.pcap

import logging
import sys
from pathlib import Path

# logger gốc
LOGGER_NAME = "idscore"

# log format: thời gian, mức độ, module phát sinh, nội dung thông báo 
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# khởi tạo log 
def setup_logging(log_path: str, level: int = logging.INFO) -> logging.Logger:
    """Configure the ``idscore`` logger once and return it."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.propagate = False

    # kiểm tra danh sách, tránh bị trùng lặp 
    if logger.handlers:
        return logger

    # đặt ngưỡng lọc cho logger: INFO, WARNING, ERROR

    # info được ghi vô log
    logger.setLevel(level)
    # chuẩn hóa format cho dòng log
    formatter = logging.Formatter(LOG_FORMAT) 

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # hiển thị lên màn hình bằng StreamHandler, chỉ hiển thị Warning và Error
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger

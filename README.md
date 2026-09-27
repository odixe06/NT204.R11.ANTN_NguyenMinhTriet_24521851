# NT204.R11.ANTN_NguyenMinhTriet_24521851

**Bài tập lớn của sinh viên Nguyễn Minh Triết - môn IDPS - lớp  NT204.R11.ANTN.**

## Môi trường:

File requirements.txt là các thư viện cần cài vào môi trường để sử dụng, trong máy local xây dựng dự án là env btids.

```bash
conda activate btids
```

## Mục đích khi sử dụng các công cụ AI:

- Thiết kế cấu trúc thư mục dự án
- Kiểm tra syntax và logic của các đoạn code
- Công cụ: GitHub Copilot + Claude Code
- File có hỗ trợ AI: `idscore/capture/base.py`, `idscore/capture/pcap.py`, `idscore/capture/live.py`, `idscore/cli.py`, `main.py`


## Lưu ý khi làm:

- Output live có packet ARP. Đây là packet không phải IPv4, pipeline ở phase 3 phải gán UNKNOWN cho loại này chứ không được crash khi tìm lớp IP.
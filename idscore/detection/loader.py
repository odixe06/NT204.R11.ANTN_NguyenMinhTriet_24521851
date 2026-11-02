# file này là Rule Loader: đọc các file .rules và đưa từng dòng sang rule_parser
# chưa có code, đây là hợp đồng để các phase sau làm theo
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

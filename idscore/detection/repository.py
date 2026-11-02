# file này là Rule Repository / Indexer: lưu các rule valid và chọn rule ứng viên cho một event
# chưa có code, đây là hợp đồng để các phase sau làm theo
#
# chiều phụ thuộc: repository chỉ dùng idscore.models (Rule, Event), không import matcher,
# generator hay engine
#
# input : list[Rule] từ loader (chỉ nhận rule valid); khi tra cứu: một Event
# output: candidates(event) -> list[Rule], tập ứng viên theo protocol (IP, TCP, UDP) và port,
#         giữ thứ tự nạp; đây là tập thừa, matcher mới quyết định match thật
#
# repository KHÔNG được:
#   - so khớp content, flags, dsize hay flow (việc của matcher)
#   - parse rule hoặc đọc file (việc của rule_parser, loader)
#   - sửa Rule sau khi đã index, hay sửa Event

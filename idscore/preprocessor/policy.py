# file này định nghĩa cách preprocessor gán policy cho 1 event

from idscore.config import POLICY_DROP
from idscore.models.event import (
    ACTION_DROP,
    ACTION_MARK,
    ACTION_PASS,
    PREPROCESS_INVALID,
    PREPROCESS_VALID,
)

# dựa trên 4 giá trị để đưa ra policy: keep/drop/mark
def decide_action(
    status: str | None,
    unsupported: str | None,
    invalid_policy: str,
    unsupported_policy: str,
) -> tuple[str, str | None]:

    # chỉ thêm reason khi drop
    dropped_by = []
    if status == PREPROCESS_INVALID and invalid_policy == POLICY_DROP:
        dropped_by.append("invalid_policy")
    if unsupported and unsupported_policy == POLICY_DROP:
        dropped_by.append("unsupported_policy")

    if dropped_by:
        return ACTION_DROP, f"policy: dropped by {', '.join(dropped_by)}"
    if status != PREPROCESS_VALID or unsupported:
        return ACTION_MARK, None
    return ACTION_PASS, None

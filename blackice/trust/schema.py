from typing import TypedDict, List

class TrustRow(TypedDict):
    ts: str
    subject_type: str
    subject_id: str
    trust_before: int
    trust_after: int
    delta: int
    reasons: List[str]
    decision: str

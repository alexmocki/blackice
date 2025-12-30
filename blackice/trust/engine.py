def apply_decision(trust_before: int, decision: str) -> int:
    if decision == "BLOCK":
        return max(trust_before - 40, 0)
    if decision == "STEP_UP":
        return max(trust_before - 15, 0)
    return min(trust_before + 1, 100)

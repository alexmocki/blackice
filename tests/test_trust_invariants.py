from blackice.trust.engine import apply_decision

def test_trust_bounds():
    assert apply_decision(100, "ALLOW") <= 100
    assert apply_decision(0, "BLOCK") >= 0

def test_trust_monotonic_drop():
    assert apply_decision(80, "BLOCK") < 80
    assert apply_decision(80, "STEP_UP") < 80

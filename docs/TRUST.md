# Trust Model

Trust is a deterministic state machine applied after decisions.

## Properties
- Range: 0–100
- Initial value: 100
- Monotonic: decreases on risk, recovers slowly
- Deterministic: same input → same trust

## Inputs
- Decisions (ALLOW / STEP_UP / BLOCK)
- Rule severity
- Time decay

## Outputs
- trust.jsonl ledger
- enforcement signals

Trust is NOT ML. It is policy.

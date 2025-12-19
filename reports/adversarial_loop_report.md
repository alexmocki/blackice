# BLACKICE — Adversarial Evaluation Report

This report summarizes adversarial episodes and how decisions escalate using **risk scoring + fraud-ring evidence**.

## Results (top episodes)

| ep | attacker_profile | risk | decision | ips | dev | cc |
|---:|---|---:|---|---:|---:|---:|
| 5 | device_hop_multi_country | 0.60 | block | 6 | 6 | 3 |
| 4 | device_hop_same_country | 0.48 | mfa | 6 | 3 | 1 |
| 1 | baseline_normal | 0.28 | allow | 1 | 1 | 1 |
| 2 | baseline_normal | 0.28 | allow | 1 | 1 | 1 |
| 3 | baseline_normal | 0.28 | allow | 1 | 1 | 1 |

## Decision logic (public baseline)

- Decisions escalate using two signals:
  1) **Fraud ring evidence** (collective abuse via entity graph clustering)
  2) **Risk score** (per-episode behavioral features)

Ring escalation takes precedence over per-episode risk.

## Why episodes escalated

- **Episode 5** (`device_hop_multi_country`) → **block** | ring `-` | risk=0.60 (>=0.58 → block)
- **Episode 4** (`device_hop_same_country`) → **mfa** | ring `-` | risk=0.48 (>=0.40 → mfa)
- **Episode 1** (`baseline_normal`) → **allow** | ring `-` | below thresholds
- **Episode 2** (`baseline_normal`) → **allow** | ring `-` | below thresholds
- **Episode 3** (`baseline_normal`) → **allow** | ring `-` | below thresholds

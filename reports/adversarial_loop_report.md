# BLACKICE — Adversarial Loop v2

This report compares attacker strategies under an explicit **impact vs stealth** objective.

## Top strategies

| rank | same_country | device_hop | country_hop | step_s | events | impact | stealth | total | bad_rules |
|---:|:---:|:---:|:---:|---:|---:|---:|---:|---:|---|
| 1 | True | False | False | 60 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 2 | True | False | False | 300 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 3 | True | False | False | 900 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 4 | True | True | False | 60 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 5 | True | True | False | 300 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 6 | True | True | False | 900 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 7 | False | True | False | 60 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 8 | False | True | False | 300 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 9 | False | True | False | 900 | 6 | 1.00 | 0.50 | 0.85 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 10 | True | False | False | 900 | 10 | 1.00 | 0.45 | 0.83 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 11 | True | False | False | 900 | 14 | 1.00 | 0.45 | 0.83 | RULE_TOKEN_REUSE_MULTI_DEVICE |
| 12 | True | True | False | 900 | 10 | 1.00 | 0.45 | 0.83 | RULE_TOKEN_REUSE_MULTI_DEVICE |

## Files
- `reports/adversarial_loop_results.csv`
- `reports/adversarial_loop_report.md`

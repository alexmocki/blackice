# BlackIce Report

Generated from `alerts.jsonl` → `decisions.jsonl`.

## Decisions

| Entity | Overall risk | Action | Alerts | Rules | Top reasons |
|---|---:|---|---:|---|---|
| `token_id=t-abc` | **92** | `block_or_revoke` | 2 | RULE_TOKEN_REUSE_MULTI_COUNTRY, RULE_TOKEN_REUSE_MULTI_DEVICE | token_reuse, geo_inconsistency, possible_session_hijack |
| `token_id=t-u3` | **92** | `block_or_revoke` | 2 | RULE_TOKEN_REUSE_MULTI_COUNTRY, RULE_TOKEN_REUSE_MULTI_DEVICE | token_reuse, geo_inconsistency, possible_session_hijack |
| `user_id=u2` | **85** | `step_up_auth` | 1 | RULE_IMPOSSIBLE_TRAVEL | geo_inconsistency, impossible_travel |
| `user_id=u3` | **85** | `step_up_auth` | 1 | RULE_IMPOSSIBLE_TRAVEL | geo_inconsistency, impossible_travel |
| `src_ip=1.1.1.1` | **70** | `monitor` | 1 | RULE_STUFFING_BURST_IP | login_fail_burst, possible_automation |
| `user_id=u1` | **65** | `monitor` | 1 | RULE_STUFFING_BURST_USER | multiple_failed_logins, possible_password_spraying |

## Evidence (alerts)

Below are the raw alerts grouped by decision entity.

### `token_id=t-abc`

- **RULE_TOKEN_REUSE_MULTI_DEVICE** @ `2025-12-17T21:10:30Z` risk=80 reasons=['token_reuse', 'possible_session_hijack'] evidence={'distinct_devices': ['d2', 'd9'], 'distinct_ips': ['2.2.2.2', '3.3.3.3'], 'window_seconds': 3600}
- **RULE_TOKEN_REUSE_MULTI_COUNTRY** @ `2025-12-17T21:10:30Z` risk=90 reasons=['token_reuse', 'geo_inconsistency'] evidence={'distinct_countries': ['FR', 'US'], 'distinct_ips': ['2.2.2.2', '3.3.3.3'], 'window_seconds': 3600}

### `token_id=t-u3`

- **RULE_TOKEN_REUSE_MULTI_DEVICE** @ `2025-12-17T22:20:00Z` risk=80 reasons=['token_reuse', 'possible_session_hijack'] evidence={'distinct_devices': ['mac-1', 'win-7'], 'distinct_ips': ['4.4.4.4', '5.5.5.5'], 'window_seconds': 3600}
- **RULE_TOKEN_REUSE_MULTI_COUNTRY** @ `2025-12-17T22:20:00Z` risk=90 reasons=['token_reuse', 'geo_inconsistency'] evidence={'distinct_countries': ['JP', 'US'], 'distinct_ips': ['4.4.4.4', '5.5.5.5'], 'window_seconds': 3600}

### `user_id=u2`

- **RULE_IMPOSSIBLE_TRAVEL** @ `2025-12-17T21:10:30Z` risk=85 reasons=['geo_inconsistency', 'impossible_travel'] evidence={'prev_country': 'US', 'current_country': 'FR', 'time_delta_seconds': 30, 'prev_ip': '2.2.2.2', 'current_ip': '3.3.3.3', 'prev_device_id': 'd2', 'current_device_id': 'd9', 'window_seconds': 21600}

### `user_id=u3`

- **RULE_IMPOSSIBLE_TRAVEL** @ `2025-12-17T22:20:00Z` risk=85 reasons=['geo_inconsistency', 'impossible_travel'] evidence={'prev_country': 'US', 'current_country': 'JP', 'time_delta_seconds': 1200, 'prev_ip': '4.4.4.4', 'current_ip': '5.5.5.5', 'prev_device_id': 'mac-1', 'current_device_id': 'win-7', 'window_seconds': 21600}

### `src_ip=1.1.1.1`

- **RULE_STUFFING_BURST_IP** @ `2025-12-17T21:00:10Z` risk=70 reasons=['login_fail_burst', 'possible_automation'] evidence={'failures': 3, 'window_seconds': 60}

### `user_id=u1`

- **RULE_STUFFING_BURST_USER** @ `2025-12-17T21:00:10Z` risk=65 reasons=['multiple_failed_logins', 'possible_password_spraying'] evidence={'failures': 3, 'window_seconds': 60}

🔍 Analyst Interpretation
user_id=u2 — Impossible Travel (High Risk)

What happened:
User activity was observed from US → FR within 30 seconds, which is physically impossible.

Why it matters:
Such a pattern strongly indicates session hijacking or token compromise, especially when paired with IP and device changes.

Decision rationale:

Risk score: 85

Recommended action: step_up_auth

Justification: High confidence anomaly, but limited to a single event — apply friction before hard blocking.

user_id=u3 — Impossible Travel (High Risk)

What happened:
User activity jumped from US → JP within 20 minutes, involving different IPs and devices.

Why it matters:
Cross-continent movement in such a short time window is a classic ATO (Account Takeover) signal.

Decision rationale:

Risk score: 85

Recommended action: step_up_auth

Justification: Strong anomaly, requires identity verification before allowing further access.

src_ip=1.1.1.1 — Credential Stuffing Burst (Medium Risk)

What happened:
Multiple failed login attempts were detected from the same IP within a short window.

Why it matters:
This pattern matches automated credential stuffing or scripted login abuse.

Decision rationale:

Risk score: 70

Recommended action: monitor

Justification: Single IP burst without confirmed compromise — monitor and rate-limit rather than block.

user_id=u1 — Multiple Failed Logins (Medium Risk)

What happened:
Repeated failed login attempts for the same user in a short time frame.

Why it matters:
May indicate password spraying, user error, or early-stage account probing.

Decision rationale:

Risk score: 65

Recommended action: monitor

Justification: Signal alone is insufficient for enforcement; correlation with other signals required.

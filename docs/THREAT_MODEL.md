# BlackIce Threat Model (Auth Abuse / ATO / Token Misuse)

## 1) System Overview
BlackIce is a defensive analytics pipeline that processes authentication/session events (JSONL) and produces:
- **Alerts** (evidence + reason codes)
- **Decisions** (ALLOW / STEP_UP / BLOCK)
- **Offline dashboard** for investigation

Primary use-case: **account takeover (ATO)** and **fraud-like abuse** driven by credential stuffing and session/token misuse.

---

## 2) Assets to Protect
- **User accounts** (identity integrity)
- **Active sessions / tokens** (session integrity)
- **Authentication surface** (login endpoints, token refresh)
- **User trust & business risk** (fraud loss, chargebacks, support load)
- **Telemetry integrity** (signals used for detection: IP/geo/device)

---

## 3) Attacker Types
- **Credential stuffers / bot operators**
- **Account takeover actors** (using leaked creds + automation)
- **Session hijackers** (token replay, cookie/session theft)
- **Fraud rings** (coordinated abuse across accounts/devices/IPs)
- **Opportunistic attackers** (manual attempts + simple VPN use)

---

## 4) Attacker Goals
- **ATO**: gain unauthorized access to user accounts
- **Persistence**: keep access via token/session reuse
- **Fraud**: perform unauthorized actions (payments, data theft, account changes)
- **Scale**: automate attempts while evading rate-limits and detection
- **Stealth**: look like legitimate logins (VPN, device spoofing, low-and-slow)

---

## 5) Abuse Patterns Modeled in BlackIce
### A) Credential Stuffing Bursts
**Pattern:** high-volume login attempts by IP and/or against a single user across a short window.  
**Indicators:** attempt spikes, repeated failures, rapid user switching.

### B) Token Reuse Across Countries / Devices
**Pattern:** same token observed in different countries or multiple devices in a suspicious timeframe.  
**Example mapping:** `RULE_TOKEN_REUSE_MULTI_COUNTRY`, `RULE_TOKEN_REUSE_MULTI_DEVICE`  
**Interpretation:** possible **session hijack** or token theft/replay.

### C) Impossible Travel / Geo-Velocity Anomalies
**Pattern:** user appears to authenticate from distant geolocations with impossible speed.  
**Indicators:** geo distance/time exceeds human travel constraints.  
**Interpretation:** VPN usage, shared credentials, or ATO.

---

## 6) What BlackIce Detects (Current Coverage)
BlackIce currently detects and reports:
- **Credential stuffing** bursts (IP-based and/or user-based)
- **Token replay/misuse** signals:
  - token reuse across **countries**
  - token reuse across **devices**
- **Impossible travel** (geo-velocity anomalies)

Each alert includes **reason codes** and **evidence** to support analyst triage.

---

## 7) Decisions & Response Philosophy
BlackIce outputs a recommended action:
- **ALLOW**: low-risk / weak signal
- **STEP_UP**: require MFA or additional verification when signal is plausible but uncertain
- **BLOCK**: high-confidence abuse or repeated high-risk patterns

Principles:
- Prefer **explainable** decisions (human-reviewable evidence)
- Control false positives with **STEP_UP** where possible
- Escalate repeated suspicious activity to **BLOCK** / revoke actions

---

## 8) Assumptions
- Event stream includes enough fields to correlate:
  - user identifier
  - IP and derived geo
  - device identifier (stable enough)
  - token identifier (or session id)
  - timestamp
- Timestamps are reasonably accurate and ordered (or can be ordered).
- Geo/IP signals are informative (acknowledging VPN/mobile noise).

---

## 9) Blind Spots / Limitations (Known Gaps)
These are expected limitations for a lightweight offline pipeline:

### A) VPN / Mobile Network Noise
- VPNs can trigger false positives for geo-based rules (impossible travel, multi-country).
- Mobile carrier NAT can collapse many users behind few IPs.

### B) Device Identifier Instability
- Device IDs may rotate/reset; cross-device signals may be noisy without fingerprinting.

### C) “Low-and-Slow” Stuffing
- Slow distributed attempts can evade burst thresholds.

### D) Token Semantics & Rotation
- Without knowing token TTL/rotation semantics, some token reuse patterns may be ambiguous.

### E) Lack of Ground Truth Labels
- Offline demo dataset does not include verified labels, so precision/recall is estimated.

### F) Evasion & Adversarial Adaptation
- Attackers can adapt: IP rotation, timing jitter, credential distribution, device spoofing.

---

## 10) Future Enhancements (Roadmap-Level)
- Add **adaptive thresholds** (per user risk baseline)
- Add **graph/link analysis** for fraud rings (shared devices/IPs/tokens)
- Add **rate-limit aware simulation** & attacker replay scenarios
- Add **enrichment** (ASN, proxy/VPN detection, reputation signals)
- Add **evaluation harness** with synthetic labeled scenarios and metrics


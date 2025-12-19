## ✨ What BlackIce Does

**BlackIce models how modern security teams reason under adversarial pressure.**  
It translates attacker behavior into **explicit detection logic**, correlates signals across identities, and produces **explainable security decisions**.

Rather than treating events in isolation, BlackIce operates on **attack narratives**:
tokens, devices, IPs, and geography evolving over time.

---

## 🔍 Detection Capabilities (Blue Team)

BlackIce implements **behavioral and token-centric detections** commonly used in fraud and account takeover (ATO) prevention systems.

### Credential Abuse
- **Credential stuffing bursts**
  - High-velocity authentication attempts by IP or account
  - Time-windowed burst detection

### Token Misuse
- **Token reuse across devices**
  - Same authentication token observed on multiple devices
- **Token reuse across countries**
  - Same token used from different geographies within a short time window

### Geo-Anomalies
- **Impossible travel**
  - Geo-velocity exceeding physical limits
  - Device + IP correlation across locations

Each alert is backed by **explicit evidence, correlation scope, and time context**.

---

## 🧠 Alerting & Decision Logic

BlackIce produces **normalized, explainable alerts**, designed for downstream decision engines.

Each alert includes:
- `reason_codes` — why the alert fired
- `evidence` — what was observed
- `risk_score` — relative severity

### Public Decision Outcomes (Demo Layer)
- `ALLOW` — activity consistent with historical behavior
- `STEP_UP` — require additional verification (MFA, challenge)
- `BLOCK` — high-confidence malicious activity

> Automated enforcement logic is intentionally limited in the public demo.  
> Advanced decision strategies remain private.

---

## 🔁 Adversarial Attack–Defence Loop

BlackIce is built around an **explicit attacker–defender loop**, not static rule matching.

### Attacker (Red)
- Reuses valid authentication tokens
- Hops devices and IP addresses
- Stretches time to evade fixed windows
- Attempts high-impact actions (payments, profile changes)

### Defender (Blue)
- Correlates behavior across:
  - token ↔ user ↔ device ↔ country
- Detects inconsistencies rather than single events
- Produces explainable alerts and response recommendations

### Feedback Loop
- Attacker behavior feeds replay scenarios
- Detection logic is stress-tested against evasion attempts
- Rules and thresholds evolve through iteration

This mirrors **real-world detection engineering workflows** used in mature security teams.

---

## 🧨 Adversarial Attacker Model (Red Team)

BlackIce explicitly models an **adversarial attacker**, rather than assuming random or naive misuse.

The attacker is represented as a **controlled agent** that generates event sequences with two competing objectives.

### Attacker Objectives

**Impact**
- Perform high-value actions using valid credentials:
  - payment APIs
  - profile or security setting changes
  - sensitive data access

**Stealth**
- Avoid triggering simple detection thresholds:
  - stretch activity over time to evade fixed windows
  - reuse tokens within the same country when possible
  - limit device changes to stay below alert thresholds
  - blend malicious actions with benign “cover traffic”

The attacker is assumed to be:
- credential-aware (already has a valid token)
- adaptive (reacts to detection logic)
- cost-constrained (limited devices, IPs, and attempts)

---

## 🎯 Explicit Adversarial Logic

BlackIce generates **intentional attack sequences**, not random noise:

1. **Warm-up phase**
   - Low-risk API calls to establish baseline behavior
2. **Exploitation phase**
   - Token replay or device hop
   - High-impact request (e.g. `/api/v1/payments`)
3. **Cover phase**
   - Benign-looking follow-up traffic
   - Attempts to mask the attack within normal behavior

This forces detection logic to reason about **sequences**, not isolated events.

---

## 🧪 Public Demo Scope

This repository intentionally exposes:
- Detection rules and replay engine
- Token-centric graph analysis
- Synthetic adversarial datasets
- Visual attack summaries

It intentionally does **not** expose:
- Automated enforcement pipelines
- Adaptive trust scoring
- Production response policies

---

## 🧠 Why This Matters

Most security demos answer:
> “Can you detect X?”

BlackIce answers:
> “How does detection behave when the attacker actively adapts?”

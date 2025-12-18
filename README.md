# BlackIce 🧊  
**Auth Abuse & Account Takeover Detection Mini-Platform**

## TL;DR
BlackIce processes authentication and session events (JSONL) to detect account takeover (ATO) and fraud-like behavior, producing **evidence-backed alerts**, **risk-based decisions**, and an **analyst-friendly dashboard**.

**Focus:** Defensive security analytics, detection engineering, and decision logic — no exploitation or bypass tooling.

---

## ✨ What BlackIce Does

BlackIce simulates how modern security teams reason about suspicious account activity by translating attacker behaviors into structured detections and response decisions.

### Detection Capabilities
- **Credential stuffing bursts**
  - High-velocity login attempts by IP or account
- **Token misuse**
  - Token reuse across devices or countries
- **Impossible travel**
  - Geo-velocity anomalies exceeding human limits

### Alerting & Decisions
- Normalized alerts with clear **reason codes and evidence**
- Risk aggregation across multiple signals
- Action recommendations:
  - `ALLOW`
  - `STEP_UP` (MFA / verification)
  - `BLOCK`

### Outputs
- `alerts.jsonl` — structured detection results
- `decisions.jsonl` — explainable security decisions
- `reports/dashboard.html` — offline investigation dashboard
- `REPORT.md` — human-readable incident summary

## Quickstart

Run a full end-to-end demo (events → alerts → decisions → dashboard):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m blackice replay
python -m blackice decide
python -m blackice report
open reports/dashboard.html

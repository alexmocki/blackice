from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple


# ----------------------------
# Time parsing (best effort)
# ----------------------------

def _parse_ts(v: Any) -> Optional[float]:
    """
    Returns epoch seconds (float) or None.
    Accepts:
      - int/float epoch seconds
      - ISO8601 strings (e.g. 2025-12-22T09:01:02Z)
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        # assume epoch seconds
        return float(v)

    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        # numeric string
        try:
            return float(s)
        except Exception:
            pass

        # ISO 8601 (best effort)
        try:
            # handle trailing Z
            if s.endswith("Z"):
                dt = datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None

    return None


def _is_failed_auth(obj: Dict[str, Any]) -> bool:
    """
    Auth failure detection for our JSONL schema.
    Treats event_type=login_fail as failure.
    """
    et = str(obj.get("event_type") or obj.get("type") or obj.get("action") or "").lower().strip()

    # Explicit schema (toy.jsonl)
    if et in {"login_fail", "auth_fail", "signin_fail", "password_fail"}:
        return True
    if et in {"login_success", "auth_success", "signin_success"}:
        return False

    outcome = str(obj.get("outcome") or obj.get("result") or "").lower()
    if outcome in {"fail", "failed", "failure", "invalid"}:
        return True

    success = obj.get("success")
    if success is False:
        return True

    status = obj.get("status") or obj.get("http_status")
    try:
        if int(status) in {401, 403}:
            return True
    except Exception:
        pass

    # If it looks auth-related but unknown outcome, don’t assume failure.
    if any(k in et for k in ["login", "auth", "signin", "password"]):
        if success is True or outcome in {"ok", "success", "succeeded"}:
            return False
        return False

    return False
def _get_user(obj: Dict[str, Any]) -> str:
    return str(obj.get("user_id") or obj.get("user") or obj.get("uid") or "unknown")


def _get_ip(obj: Dict[str, Any]) -> str:
    return str(obj.get('ip') or obj.get('ip_address') or obj.get('src_ip') or obj.get('source_ip') or 'unknown')


def _get_country(obj: Dict[str, Any]) -> str:
    return str(obj.get('country') or obj.get('geo_country') or obj.get('cc') or 'unknown')


    return str(obj.get("ip") or obj.get("ip_address") or obj.get("src_ip") or obj.get("source_ip") or "unknown")


# ----------------------------
# Stuffing burst detector
# ----------------------------

@dataclass
class BurstConf:
    window_s: float = 60.0
    user_fail_threshold: int = 3
    ip_fail_threshold: int = 3
    # Impossible travel
    travel_window_s: float = 3600.0  # 1 hour


def _push_window(q: Deque[Tuple[float, Dict[str, Any]]], ts: float, ev: Dict[str, Any], window_s: float) -> None:
    q.append((ts, ev))
    cutoff = ts - window_s
    while q and q[0][0] < cutoff:
        q.popleft()



def _make_travel_alert(user_id: str, ts: float, prev: Dict[str, Any], cur: Dict[str, Any]) -> Dict[str, Any]:
    prev_country = prev.get("country", "unknown")
    cur_country = cur.get("country", "unknown")
    prev_ts = _parse_ts(prev.get("ts") or prev.get("timestamp") or prev.get("time")) or ts
    dt = max(1.0, ts - prev_ts)

    alert_id = f"RULE_IMPOSSIBLE_TRAVEL:{user_id}:{int(ts)}"
    return {
        "alert_id": alert_id,
        "rule_id": "RULE_IMPOSSIBLE_TRAVEL",
        "user_id": user_id,
        "severity": 9,
        "ts": ts,
        "key": user_id,
        "evidence": {
            "prev": prev,
            "cur": cur,
            "prev_country": prev_country,
            "cur_country": cur_country,
            "dt_seconds": dt,
            "note": "Same user observed in different countries within a short time window.",
        },
    }

def _make_alert(rule_id: str, key: str, ts: float, events: Deque[Tuple[float, Dict[str, Any]]]) -> Dict[str, Any]:
    # compact evidence: show last few events only
    tail = list(events)[-5:]
    evidence_tail = [e for _, e in tail]

    alert_id = f"{rule_id}:{key}:{int(ts)}"
    user_id = "unknown"
    if rule_id.endswith("_USER"):
        user_id = key

    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "user_id": user_id,
        "severity": 7 if "USER" in rule_id else 8,
        "ts": ts,
        "key": key,
        "evidence": {
            "count_in_window": len(events),
            "window_s": 60,
            "tail": evidence_tail,
        },
    }


def run_replay(input_path: str, alerts_path: str) -> Dict[str, Any]:
    """
    Replay now runs a REAL behavioral detector:
      - Credential stuffing bursts (failed auth attempts) by USER and by IP
    Writes alerts.jsonl only when thresholds trigger.

    Input JSONL should ideally include:
      ts, user_id, ip, outcome/success/status
    """
    conf = BurstConf()

    inp = Path(input_path)
    out = Path(alerts_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    user_q: Dict[str, Deque[Tuple[float, Dict[str, Any]]]] = defaultdict(deque)
    ip_q: Dict[str, Deque[Tuple[float, Dict[str, Any]]]] = defaultdict(deque)
    # For impossible travel
    last_event_by_user: Dict[str, Dict[str, Any]] = {}

    # de-dupe: avoid emitting same alert repeatedly each event
    last_emit_user: Dict[str, float] = {}
    last_emit_ip: Dict[str, float] = {}

    n_in = 0
    n_failed = 0
    n_alerts = 0

    with inp.open("r", encoding="utf-8") as f_in, out.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                obj = json.loads(line)
            except Exception:
                continue

            ts = _parse_ts(obj.get("ts") or obj.get("timestamp") or obj.get("time"))
            if ts is None:
                # if no ts, we can't window correctly -> skip
                continue
            failed = _is_failed_auth(obj)

            # ----------------------------
            # Impossible travel (all events)
            # ----------------------------
            user = _get_user(obj)
            country = _get_country(obj)
            prev = last_event_by_user.get(user)
            if user != "unknown" and prev is not None:
                prev_country = _get_country(prev)
                prev_ts = _parse_ts(prev.get("ts") or prev.get("timestamp") or prev.get("time"))
                if (
                    prev_ts is not None
                    and country != "unknown"
                    and prev_country != "unknown"
                    and country != prev_country
                    and (ts - prev_ts) <= conf.travel_window_s
                ):
                    alert = _make_travel_alert(user, ts, prev, obj)
                    f_out.write(json.dumps(alert, ensure_ascii=False) + "\n")
                    n_alerts += 1

            # record current for ALL events (success + fail)
            if user != "unknown":
                last_event_by_user[user] = obj


            # ----------------------------
            # Stuffing burst (failed auth only)
            # ----------------------------
            if not failed:
                continue

            n_failed += 1
            ip = _get_ip(obj)
            # Update sliding windows
            _push_window(user_q[user], ts, obj, conf.window_s)
            _push_window(ip_q[ip], ts, obj, conf.window_s)

            # USER burst
            if user != "unknown" and len(user_q[user]) >= conf.user_fail_threshold:
                prev = last_emit_user.get(user)
                if prev is None or (ts - prev) >= conf.window_s:
                    alert = _make_alert("RULE_STUFFING_BURST_USER", user, ts, user_q[user])
                    f_out.write(json.dumps(alert, ensure_ascii=False) + "\n")
                    n_alerts += 1
                    last_emit_user[user] = ts

            # IP burst
            if ip != "unknown" and len(ip_q[ip]) >= conf.ip_fail_threshold:
                prev = last_emit_ip.get(ip)
                if prev is None or (ts - prev) >= conf.window_s:
                    alert = _make_alert("RULE_STUFFING_BURST_IP", ip, ts, ip_q[ip])
                    f_out.write(json.dumps(alert, ensure_ascii=False) + "\n")
                    n_alerts += 1
                    last_emit_ip[ip] = ts

    return {"input_rows": n_in, "failed_auth_rows": n_failed, "alerts_rows": n_alerts}

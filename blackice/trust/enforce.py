import json
from pathlib import Path
from typing import Dict, Any


def _key(st: str, sid: str) -> str:
    return f"{st}:{sid}"


def _load_latest_enforcement(trust_path: str) -> Dict[str, Dict[str, Any]]:
    p = Path(trust_path)
    latest: Dict[str, Dict[str, Any]] = {}
    if not p.exists():
        return latest

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue

            st = row.get("subject_type")
            sid = row.get("subject_id")
            ea = row.get("enforced_action") or row.get("action")
            if not isinstance(st, str) or not isinstance(sid, str) or not isinstance(ea, str):
                continue

            latest[_key(st, sid)] = {
                "enforced_action": ea,
                "enforcement_reason": row.get("enforcement_reason"),
                "trust_after": row.get("trust_after"),
            }

    return latest


def apply_enforcement_to_decisions(decisions_path: str, trust_path: str) -> Dict[str, Any]:
    dp = Path(decisions_path)
    if not dp.exists():
        return {"decisions_path": decisions_path, "trust_path": trust_path, "total": 0, "overrides": 0}

    latest = _load_latest_enforcement(trust_path)

    out_lines = []
    total = 0
    overrides = 0

    with dp.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1
            try:
                d = json.loads(raw)
            except Exception:
                out_lines.append(raw)
                continue

            st = d.get("subject_type")
            sid = d.get("subject_id")
            action = d.get("action") or d.get("decision")

            if isinstance(st, str) and isinstance(sid, str) and isinstance(action, str):
                info = latest.get(_key(st, sid))
                if info and isinstance(info.get("enforced_action"), str):
                    action_final = info["enforced_action"]
                    enforced = (action_final != action)
                    if enforced:
                        overrides += 1
                    d["action_final"] = action_final
                    d["enforced"] = enforced
                    if info.get("enforcement_reason") is not None:
                        d["enforcement_reason"] = info.get("enforcement_reason")
                    if info.get("trust_after") is not None:
                        d["trust_after"] = info.get("trust_after")
                else:
                    d["action_final"] = action
                    d["enforced"] = False

            out_lines.append(json.dumps(d, ensure_ascii=False))

    dp.write_text("\n".join(out_lines) + ("\n" if out_lines else ""), encoding="utf-8")

    return {
        "decisions_path": decisions_path,
        "trust_path": trust_path,
        "total": total,
        "overrides": overrides,
    }

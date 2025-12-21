import importlib
import json
import os
import pkgutil
from typing import Any, Dict, List, Optional, Tuple


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _to_dict(x: Any) -> Dict[str, Any]:
    if isinstance(x, dict):
        return x
    if hasattr(x, "__dict__"):
        return dict(x.__dict__)
    return {"value": str(x)}


def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _pick_rule_entry(mod) -> Tuple[Optional[str], Optional[Any]]:
    """
    Try common entrypoints in rule modules.
    Returns (kind, callable_or_instance)
    """
    for fn in ("detect", "run", "apply"):
        obj = getattr(mod, fn, None)
        if callable(obj):
            return ("func:" + fn, obj)

    # Class-based rules: Rule().run(events)
    RuleCls = getattr(mod, "Rule", None)
    if RuleCls is not None:
        try:
            inst = RuleCls()
            runm = getattr(inst, "run", None)
            if callable(runm):
                return ("class:Rule.run", inst)
        except Exception:
            pass

    return (None, None)


def run_replay(input_path: str, output_path: str) -> Dict[str, Any]:
    """
    Engine replay: events.jsonl -> alerts.jsonl
    Loads rule modules from blackice.detections.rules and executes them.
    """
    events = _read_jsonl(input_path)
    alerts: List[Dict[str, Any]] = []

    # Discover modules correctly as a package
    rules_pkg = importlib.import_module("blackice.detections.rules")
    discovered = []
    loaded = []
    invoked = []

    for m in pkgutil.iter_modules(rules_pkg.__path__):
        if m.ispkg:
            continue
        modname = f"{rules_pkg.__name__}.{m.name}"
        discovered.append(modname)
        mod = importlib.import_module(modname)

        kind, entry = _pick_rule_entry(mod)
        if entry is None:
            continue

        # Execute
        try:
            if kind and kind.startswith("func:"):
                out = entry(events)
            else:
                # class instance
                out = entry.run(events)  # type: ignore[attr-defined]
        except Exception as e:
            alerts.append({
                "ts": None,
                "rule_id": getattr(mod, "RULE_ID", m.name),
                "severity": "ERROR",
                "error": f"{type(e).__name__}: {e}",
                "module": modname,
            })
            loaded.append(modname)
            invoked.append(kind or "unknown")
            continue

        if out:
            for a in out:
                alerts.append(_to_dict(a))

        loaded.append(modname)
        invoked.append(kind or "unknown")

    _write_jsonl(output_path, alerts)

    return {
        "input_path": input_path,
        "output_path": output_path,
        "total_events": len(events),
        "total_alerts": len(alerts),
        "rules_discovered": len(discovered),
        "rules_loaded": len(loaded),
        "rules_invoked": invoked,
        "rules": loaded,
    }

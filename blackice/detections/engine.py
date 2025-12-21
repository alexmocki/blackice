from __future__ import annotations

import inspect
import pkgutil
import importlib
from dataclasses import is_dataclass, asdict
from typing import Any, Dict, Iterable, List, Tuple


def _alert_to_dict(a: Any) -> Dict[str, Any]:
    # Best-effort conversion of Alert objects to plain dict
    if a is None:
        return {"type": "UNKNOWN", "detail": "None alert"}
    if isinstance(a, dict):
        return a
    if hasattr(a, "to_dict") and callable(getattr(a, "to_dict")):
        return a.to_dict()  # type: ignore
    if is_dataclass(a):
        return asdict(a)
    # fallback: try __dict__
    if hasattr(a, "__dict__"):
        return dict(a.__dict__)
    return {"type": type(a).__name__, "detail": str(a)}


def _discover_rule_classes() -> List[type]:
    """
    Discover rule classes under blackice.detections.rules.* that have a callable detect(self, event)->list.
    """
    import blackice.detections.rules as rules_pkg  # noqa

    classes: List[type] = []
    for m in pkgutil.iter_modules(rules_pkg.__path__, rules_pkg.__name__ + "."):
        mod = importlib.import_module(m.name)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            # Only classes defined in that module (avoid imported classes)
            if obj.__module__ != mod.__name__:
                continue
            if obj.__name__.lower().endswith("test"):
                continue
            if hasattr(obj, "detect") and callable(getattr(obj, "detect")):
                classes.append(obj)
    return classes


def _instantiate_rule(cls: type) -> Tuple[Any | None, str | None]:
    """
    Try to instantiate a rule class. If it needs args and no defaults, skip with reason.
    """
    try:
        sig = inspect.signature(cls)
        params = list(sig.parameters.values())
        # If it can be called with no args (or only optional args), instantiate.
        required = [
            p for p in params
            if p.default is inspect._empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        if len(required) == 0:
            return cls(), None
        return None, f"requires args: {[p.name for p in required]}"
    except Exception as e:
        # Some classes don't have an inspectable signature; try no-arg anyway.
        try:
            return cls(), None
        except Exception as e2:
            return None, f"cannot instantiate: {e2!r} (signature err: {e!r})"


def detect(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Run all discovered rules over all events. Returns dict:
      {
        "alerts": [ ... alert dicts ... ],
        "rules_loaded": int,
        "rules_skipped": {RuleName: reason, ...},
        "rule_hits": {RuleName: count, ...}
      }
    """
    rule_classes = _discover_rule_classes()

    rules: List[Any] = []
    skipped: Dict[str, str] = {}
    for cls in rule_classes:
        inst, reason = _instantiate_rule(cls)
        if inst is None:
            skipped[cls.__name__] = reason or "unknown"
            continue
        rules.append(inst)

    alerts_out: List[Dict[str, Any]] = []
    hits: Dict[str, int] = {}

    for ev in events:
        for r in rules:
            rname = type(r).__name__
            try:
                produced = r.detect(ev)  # expected list[Alert] (or list[dict])
            except Exception as e:
                # A rule crashing shouldn't kill the whole run
                skipped[rname] = f"runtime error: {e!r}"
                continue

            if not produced:
                continue

            hits[rname] = hits.get(rname, 0) + len(produced)
            for a in produced:
                ad = _alert_to_dict(a)
                ad.setdefault("rule_id", rname)
                alerts_out.append(ad)

    return {
        "alerts": alerts_out,
        "rules_loaded": len(rules),
        "rules_discovered": len(rule_classes),
        "rules_skipped": skipped,
        "rule_hits": hits,
    }

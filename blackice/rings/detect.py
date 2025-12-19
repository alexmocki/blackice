from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


class UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def groups(self) -> Dict[str, Set[str]]:
        out: Dict[str, Set[str]] = {}
        for x in self.parent:
            r = self.find(x)
            out.setdefault(r, set()).add(x)
        return out


@dataclass
class Ring:
    ring_id: str
    members: Set[str]
    score: float
    reasons: List[str]


def _ent(prefix: str, value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return f"{prefix}:{value}"


def build_edges(events: Iterable[Dict[str, Any]]) -> List[Tuple[str, str]]:
    edges: List[Tuple[str, str]] = []
    for e in events:
        nodes: List[str] = []
        for n in [
            _ent("tok", e.get("token_id")),
            _ent("usr", e.get("user_id")),
            _ent("dev", e.get("device_id")),
            _ent("ip", e.get("src_ip")),
            _ent("cc", e.get("country")),
        ]:
            if n:
                nodes.append(n)

        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                edges.append((nodes[i], nodes[j]))
    return edges


def detect_rings(
    events: List[Dict[str, Any]],
    min_size: int = 4,
) -> List[Ring]:
    uf = UnionFind()
    for a, b in build_edges(events):
        uf.union(a, b)

    rings: List[Ring] = []
    idx = 0

    for members in uf.groups().values():
        if len(members) < min_size:
            continue

        idx += 1
        ring_id = f"R{idx:03d}"

        devs = [m for m in members if m.startswith("dev:")]
        ccs = [m for m in members if m.startswith("cc:")]

        score = float(len(members))
        score += 2.0 * len(devs)
        score += 3.0 * len(ccs)

        reasons: List[str] = []
        if len(devs) >= 3:
            reasons.append("multi_device")
        if len(ccs) >= 2:
            reasons.append("multi_country")

        rings.append(Ring(ring_id, set(members), score, reasons))

    rings.sort(key=lambda r: r.score, reverse=True)
    return rings

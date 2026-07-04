"""
AMLGraph — graph-based anti-money-laundering pattern detection.

Detects cross-transaction patterns invisible to single-transaction analysis:
- Structuring: multiple sub-threshold transactions from same entity
- Layering: circular fund flows (cycles in the transaction graph)
- Fan-out: burst sending to many beneficiaries
- Common beneficiary: funds converging from many unrelated sources

Requires networkx (installed as a core dependency).

Usage:
    from complychain.detection.graph import AMLGraph
    g = AMLGraph()
    for tx in transactions:
        g.add_transaction(tx)
    patterns = g.detect_patterns()
"""

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import networkx as nx
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "networkx is required for graph AML detection. "
        "Install it with: pip install networkx"
    ) from exc

_CTR_THRESHOLD = 10_000.0
_STRUCTURING_MIN_TX = 3
_FAN_OUT_THRESHOLD = 5
_COMMON_BENEFICIARY_THRESHOLD = 5
_DEFAULT_WINDOW_SECONDS = 86_400  # 24 h


@dataclass
class AMLPattern:
    pattern_type: str
    entities: List[str]
    transaction_ids: List[str]
    confidence: float
    description: str


@dataclass
class _Edge:
    tx_id: str
    originator: str
    beneficiary: str
    amount: float
    timestamp: float


class AMLGraph:
    """Thread-safe directed graph for cross-transaction AML pattern detection."""

    def __init__(self, window_seconds: int = _DEFAULT_WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._graph: nx.DiGraph = nx.DiGraph()
        self._edges: List[_Edge] = []
        self._lock = threading.RLock()

    def add_transaction(
        self,
        tx_data: Dict[str, Any],
        tx_id: Optional[str] = None,
    ) -> None:
        originator = str(tx_data.get("originator", "unknown"))
        beneficiary = str(tx_data.get("beneficiary", "unknown"))
        amount = float(tx_data.get("amount", 0))
        tx_id = tx_id or str(uuid.uuid4())
        ts = float(tx_data.get("timestamp", time.time()))

        edge = _Edge(tx_id, originator, beneficiary, amount, ts)

        with self._lock:
            self._edges.append(edge)
            self._graph.add_node(originator)
            self._graph.add_node(beneficiary)
            self._graph.add_edge(
                originator, beneficiary,
                tx_id=tx_id, amount=amount, timestamp=ts,
            )

    def detect_patterns(self) -> List[AMLPattern]:
        with self._lock:
            cutoff = time.time() - self._window
            recent = [e for e in self._edges if e.timestamp >= cutoff]
            patterns: List[AMLPattern] = []
            patterns.extend(self._detect_structuring(recent))
            patterns.extend(self._detect_layering())
            patterns.extend(self._detect_fan_out(recent))
            patterns.extend(self._detect_common_beneficiary(recent))
        return patterns

    def get_entity_risk(self, entity_id: str) -> float:
        with self._lock:
            if entity_id not in self._graph:
                return 0.0
            patterns = self.detect_patterns()
            score = 0.0
            for p in patterns:
                if entity_id in p.entities:
                    score += p.confidence
            return min(score, 1.0)

    def reset(self, older_than_seconds: Optional[int] = None) -> None:
        with self._lock:
            if older_than_seconds is None:
                self._edges.clear()
                self._graph.clear()
            else:
                cutoff = time.time() - older_than_seconds
                self._edges = [e for e in self._edges if e.timestamp >= cutoff]
                self._graph.clear()
                for edge in self._edges:
                    self._graph.add_node(edge.originator)
                    self._graph.add_node(edge.beneficiary)
                    self._graph.add_edge(
                        edge.originator, edge.beneficiary,
                        tx_id=edge.tx_id, amount=edge.amount, timestamp=edge.timestamp,
                    )

    def export_gexf(self) -> str:
        """Export the transaction graph in GEXF format (Gephi-compatible)."""
        import io
        buf = io.BytesIO()
        with self._lock:
            nx.write_gexf(self._graph, buf)
        return buf.getvalue().decode("utf-8")

    # ------------------------------------------------------------------
    # Private detectors
    # ------------------------------------------------------------------

    def _detect_structuring(self, recent: List[_Edge]) -> List[AMLPattern]:
        from collections import defaultdict
        by_originator: Dict[str, List[_Edge]] = defaultdict(list)
        for e in recent:
            if e.amount < _CTR_THRESHOLD:
                by_originator[e.originator].append(e)

        patterns = []
        for originator, edges in by_originator.items():
            if len(edges) < _STRUCTURING_MIN_TX:
                continue
            total = sum(e.amount for e in edges)
            if total >= _CTR_THRESHOLD:
                confidence = min(0.4 + (len(edges) - _STRUCTURING_MIN_TX) * 0.1, 0.95)
                patterns.append(AMLPattern(
                    pattern_type="STRUCTURING",
                    entities=[originator],
                    transaction_ids=[e.tx_id for e in edges],
                    confidence=confidence,
                    description=(
                        f"{originator} sent {len(edges)} transactions totalling "
                        f"${total:,.2f}, each below the ${_CTR_THRESHOLD:,.0f} "
                        f"CTR threshold — consistent with structuring (31 U.S.C. §5324)."
                    ),
                ))
        return patterns

    def _detect_layering(self) -> List[AMLPattern]:
        patterns = []
        try:
            cycles = list(nx.simple_cycles(self._graph))
        except Exception:
            return patterns

        for cycle in cycles:
            if not (2 <= len(cycle) <= 5):
                continue
            confidence = min(0.5 + (5 - len(cycle)) * 0.1, 0.95)
            tx_ids = []
            for i, node in enumerate(cycle):
                next_node = cycle[(i + 1) % len(cycle)]
                edge_data = self._graph.get_edge_data(node, next_node) or {}
                if "tx_id" in edge_data:
                    tx_ids.append(edge_data["tx_id"])

            patterns.append(AMLPattern(
                pattern_type="LAYERING",
                entities=list(cycle),
                transaction_ids=tx_ids,
                confidence=confidence,
                description=(
                    f"Circular fund flow detected: {' → '.join(cycle)} → {cycle[0]}. "
                    f"Cycle length {len(cycle)} is consistent with layering."
                ),
            ))
        return patterns

    def _detect_fan_out(self, recent: List[_Edge]) -> List[AMLPattern]:
        from collections import defaultdict
        by_originator: Dict[str, List[_Edge]] = defaultdict(list)
        for e in recent:
            by_originator[e.originator].append(e)

        patterns = []
        for originator, edges in by_originator.items():
            unique_beneficiaries = {e.beneficiary for e in edges}
            if len(unique_beneficiaries) >= _FAN_OUT_THRESHOLD:
                confidence = min(0.4 + (len(unique_beneficiaries) - _FAN_OUT_THRESHOLD) * 0.05, 0.9)
                patterns.append(AMLPattern(
                    pattern_type="FAN_OUT",
                    entities=[originator] + list(unique_beneficiaries),
                    transaction_ids=[e.tx_id for e in edges],
                    confidence=confidence,
                    description=(
                        f"{originator} sent funds to {len(unique_beneficiaries)} "
                        f"distinct beneficiaries within the monitoring window — "
                        f"consistent with fan-out layering."
                    ),
                ))
        return patterns

    def _detect_common_beneficiary(self, recent: List[_Edge]) -> List[AMLPattern]:
        from collections import defaultdict
        by_beneficiary: Dict[str, List[_Edge]] = defaultdict(list)
        for e in recent:
            by_beneficiary[e.beneficiary].append(e)

        patterns = []
        for beneficiary, edges in by_beneficiary.items():
            unique_originators = {e.originator for e in edges}
            if len(unique_originators) >= _COMMON_BENEFICIARY_THRESHOLD:
                confidence = min(0.4 + (len(unique_originators) - _COMMON_BENEFICIARY_THRESHOLD) * 0.05, 0.9)
                patterns.append(AMLPattern(
                    pattern_type="COMMON_BENEFICIARY",
                    entities=[beneficiary] + list(unique_originators),
                    transaction_ids=[e.tx_id for e in edges],
                    confidence=confidence,
                    description=(
                        f"{beneficiary} received funds from {len(unique_originators)} "
                        f"distinct originators — consistent with smurfing or aggregation."
                    ),
                ))
        return patterns

"""
VelocityDetector — per-entity rolling-window velocity anomaly detection.

Detects structuring attacks and account-takeover patterns that look normal
in isolation but suspicious over a time window (e.g. 10 small transfers
summing to $49,900 over 24 hours).
"""

import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple


class VelocityWindow:
    """Rolling state for a single entity."""

    __slots__ = ("_timestamps", "_amounts", "_window_seconds")

    def __init__(self, window_seconds: int) -> None:
        self._timestamps: Deque[float] = deque()
        self._amounts: Deque[float] = deque()
        self._window_seconds = window_seconds

    def record(self, timestamp: float, amount: float) -> None:
        self._timestamps.append(timestamp)
        self._amounts.append(amount)
        self._prune(timestamp)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
            self._amounts.popleft()

    @property
    def count(self) -> int:
        return len(self._timestamps)

    @property
    def total_amount(self) -> float:
        return sum(self._amounts)

    @property
    def max_amount(self) -> float:
        return max(self._amounts) if self._amounts else 0.0


class VelocityDetector:
    """
    Thread-safe per-entity velocity scoring.

    Scores range from 0.0 (normal) to 1.0 (maximum suspicion).
    The score is the maximum of a count-based signal and an amount-based signal,
    each linearly scaled against their respective thresholds.
    """

    def __init__(
        self,
        window_seconds: int = 86_400,
        max_count_threshold: int = 10,
        max_total_threshold: float = 50_000.0,
    ) -> None:
        self._window_seconds = window_seconds
        self._max_count_threshold = max_count_threshold
        self._max_total_threshold = max_total_threshold
        self._windows: Dict[str, VelocityWindow] = {}
        self._lock = threading.RLock()

    def observe(
        self, entity_id: str, amount: float, timestamp: Optional[float] = None
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        with self._lock:
            if entity_id not in self._windows:
                self._windows[entity_id] = VelocityWindow(self._window_seconds)
            self._windows[entity_id].record(ts, amount)

    def score(self, entity_id: str) -> float:
        with self._lock:
            win = self._windows.get(entity_id)
        if win is None:
            return 0.0
        count_score = min(win.count / self._max_count_threshold, 1.0)
        amount_score = min(win.total_amount / self._max_total_threshold, 1.0)
        return max(count_score, amount_score)

    def is_suspicious(self, entity_id: str) -> bool:
        return self.score(entity_id) > 0.5

    def reset(self, entity_id: str) -> None:
        with self._lock:
            self._windows.pop(entity_id, None)

    def summary(self, entity_id: str) -> Dict[str, float]:
        with self._lock:
            win = self._windows.get(entity_id)
        if win is None:
            return {"count": 0, "total_amount": 0.0, "score": 0.0}
        return {
            "count": float(win.count),
            "total_amount": win.total_amount,
            "max_amount": win.max_amount,
            "score": self.score(entity_id),
        }

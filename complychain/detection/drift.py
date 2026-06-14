"""
DriftDetector — Page-Hinkley change detection on prediction score distribution.

Monitors the rolling mean of anomaly scores. When cumulative deviation from
the minimum exceeds `threshold`, drift is flagged and the on_drift callback
is called (once, until reset() is called).

Pure stdlib + numpy; no scipy required.
"""

import threading
from collections import deque
from typing import Any, Callable, Dict, Optional


class DriftDetector:
    """
    Page-Hinkley drift detector for ML anomaly score streams.

    When drift_detected transitions from False → True, the on_drift callback
    is invoked exactly once. Call reset() to clear state after retraining.
    Thread-safe.
    """

    def __init__(
        self,
        window_size: int = 500,
        threshold: float = 50.0,
        delta: float = 0.005,
        on_drift: Optional[Callable[["DriftDetector"], None]] = None,
    ) -> None:
        self._window_size = window_size
        self._threshold = threshold
        self._delta = delta
        self._on_drift = on_drift
        self._scores: deque = deque(maxlen=window_size)
        self._cumsum: float = 0.0
        self._min_cumsum: float = 0.0
        self._n_seen: int = 0
        self._drift_detected: bool = False
        self._lock = threading.Lock()

    def observe(self, score: float) -> bool:
        """
        Record one prediction score.
        Returns True if this call triggered drift detection for the first time.
        """
        with self._lock:
            if self._drift_detected:
                return False

            self._scores.append(score)
            self._n_seen += 1
            mean = sum(self._scores) / len(self._scores)
            self._cumsum += score - mean - self._delta
            if self._cumsum < self._min_cumsum:
                self._min_cumsum = self._cumsum

            ph_statistic = self._cumsum - self._min_cumsum
            if ph_statistic > self._threshold:
                self._drift_detected = True
                if self._on_drift is not None:
                    try:
                        self._on_drift(self)
                    except Exception:
                        pass
                return True
        return False

    def reset(self) -> None:
        with self._lock:
            self._scores.clear()
            self._cumsum = 0.0
            self._min_cumsum = 0.0
            self._drift_detected = False

    @property
    def drift_detected(self) -> bool:
        return self._drift_detected

    @property
    def n_seen(self) -> int:
        return self._n_seen

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            scores = list(self._scores)
        n = len(scores)
        return {
            "n_seen": self._n_seen,
            "drift_detected": self._drift_detected,
            "cumsum": self._cumsum,
            "window_mean": sum(scores) / n if n else 0.0,
            "window_std": float(
                (sum((s - sum(scores) / n) ** 2 for s in scores) / n) ** 0.5
            ) if n > 1 else 0.0,
        }

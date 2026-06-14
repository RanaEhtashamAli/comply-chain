"""
EnsembleDetector — IsolationForest + LocalOutlierFactor + Z-score majority vote.

Improves precision over single IsolationForest and reduces false positives.
Uses only sklearn + numpy (already in requirements); no new dependencies.
"""

import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


class EnsembleDetector:
    """
    Three-model ensemble anomaly detector.

    is_anomaly = True when majority (≥2 of 3) sub-models flag the sample.
    ensemble_score is the mean of three normalized anomaly signals in [0, 1].

    LocalOutlierFactor is trained with novelty=True so .predict() works on
    new samples. If the training set has fewer samples than lof_n_neighbors,
    LOF is skipped and a 2-model fallback (IF + Z-score) is used instead.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        random_state: int = 42,
        lof_n_neighbors: int = 20,
    ) -> None:
        self._contamination = contamination
        self._random_state = random_state
        self._lof_n_neighbors = lof_n_neighbors
        self._lock = threading.RLock()
        self._if: Optional[IsolationForest] = None
        self._lof: Optional[LocalOutlierFactor] = None
        self._scaler: Optional[StandardScaler] = None
        self._means: Optional[np.ndarray] = None
        self._stds: Optional[np.ndarray] = None
        self._lof_enabled = False
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(self, X: np.ndarray) -> "EnsembleDetector":
        """Fit all sub-models on a raw feature matrix (n_samples, n_features)."""
        with self._lock:
            self._scaler = StandardScaler()
            Xs = self._scaler.fit_transform(X)

            self._if = IsolationForest(
                contamination=self._contamination,
                random_state=self._random_state,
            )
            self._if.fit(Xs)

            self._lof_enabled = len(X) >= self._lof_n_neighbors
            if self._lof_enabled:
                self._lof = LocalOutlierFactor(
                    n_neighbors=self._lof_n_neighbors, novelty=True
                )
                self._lof.fit(Xs)

            self._means = Xs.mean(axis=0)
            self._stds = np.where(Xs.std(axis=0) == 0, 1.0, Xs.std(axis=0))
            self._is_fitted = True
        return self

    def predict(self, x: np.ndarray) -> Tuple[bool, float]:
        """
        Returns (is_anomaly, ensemble_score) for a single sample.
        is_anomaly = True when ≥2 of 3 sub-models flag anomaly.
        ensemble_score is in [0, 1]; higher = more anomalous.
        """
        with self._lock:
            if not self._is_fitted:
                raise RuntimeError("EnsembleDetector must be fitted before predict().")

            xs = self._scaler.transform(x.reshape(1, -1))

            if_score_raw = -self._if.score_samples(xs)[0]
            if_score = float(np.clip(if_score_raw, 0, 1))
            if_anomaly = self._if.predict(xs)[0] == -1

            z_max = float(np.max(np.abs((xs[0] - self._means) / self._stds)))
            z_threshold = 3.0
            z_score = min(z_max / z_threshold, 1.0)
            z_anomaly = z_max > z_threshold

            if self._lof_enabled and self._lof is not None:
                lof_score_raw = -self._lof.score_samples(xs)[0]
                lof_score = float(np.clip(lof_score_raw, 0, 1))
                lof_anomaly = self._lof.predict(xs)[0] == -1
                ensemble_score = (if_score + lof_score + z_score) / 3.0
                votes = sum([if_anomaly, lof_anomaly, z_anomaly])
            else:
                ensemble_score = (if_score + z_score) / 2.0
                votes = sum([if_anomaly, z_anomaly])
                # 2-model fallback: majority = ≥1 (since only 2 models)
                return votes >= 1, ensemble_score

        return votes >= 2, ensemble_score

    def fit_from_transactions(
        self,
        transactions: List[Dict[str, Any]],
        feature_extractor: Callable[[Dict[str, Any]], np.ndarray],
    ) -> "EnsembleDetector":
        """Convenience: build feature matrix from transactions then call fit()."""
        rows = [feature_extractor(tx).flatten() for tx in transactions]
        X = np.array(rows)
        return self.fit(X)

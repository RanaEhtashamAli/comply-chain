"""Tests for EnsembleDetector — 3-model majority-vote anomaly detection."""

import threading

import numpy as np
import pytest

from complychain.detection.ensemble import EnsembleDetector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def normal_data():
    """100 samples of 2-feature normal data centred at origin."""
    rng = np.random.default_rng(0)
    return rng.normal(loc=0.0, scale=1.0, size=(100, 2))


@pytest.fixture()
def fitted(normal_data):
    det = EnsembleDetector(contamination=0.1, random_state=42, lof_n_neighbors=20)
    det.fit(normal_data)
    return det


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_not_fitted_initially():
    det = EnsembleDetector()
    assert not det.is_fitted


def test_fitted_after_fit(fitted):
    assert fitted.is_fitted


def test_predict_raises_when_not_fitted():
    det = EnsembleDetector()
    with pytest.raises(RuntimeError, match="must be fitted"):
        det.predict(np.array([0.0, 0.0]))


# ---------------------------------------------------------------------------
# LOF-enabled path (≥20 samples)
# ---------------------------------------------------------------------------

def test_normal_sample_not_anomaly(fitted):
    is_anom, score = fitted.predict(np.array([0.0, 0.0]))
    assert is_anom == False
    assert 0.0 <= score <= 1.0


def test_extreme_outlier_is_anomaly(fitted):
    is_anom, score = fitted.predict(np.array([100.0, 100.0]))
    assert is_anom
    assert score > 0.5


def test_score_range(fitted, normal_data):
    for row in normal_data[:10]:
        _, score = fitted.predict(row)
        assert 0.0 <= score <= 1.0


def test_returns_tuple(fitted):
    result = fitted.predict(np.array([1.0, 1.0]))
    assert isinstance(result, tuple) and len(result) == 2
    assert result[0] in (True, False)
    assert isinstance(result[1], (float, np.floating))


# ---------------------------------------------------------------------------
# LOF-skipped path (< lof_n_neighbors samples)
# ---------------------------------------------------------------------------

def test_lof_skipped_when_small_training():
    rng = np.random.default_rng(1)
    small_data = rng.normal(size=(5, 2))
    det = EnsembleDetector(contamination=0.1, lof_n_neighbors=20)
    det.fit(small_data)
    assert not det._lof_enabled
    # should still produce a result
    is_anom, score = det.predict(np.array([0.0, 0.0]))
    assert is_anom in (True, False)
    assert 0.0 <= score <= 1.0


def test_small_training_extreme_outlier():
    """In 2-model fallback, extreme outlier should be flagged."""
    rng = np.random.default_rng(2)
    small_data = rng.normal(size=(10, 2))
    det = EnsembleDetector(contamination=0.1, lof_n_neighbors=20)
    det.fit(small_data)
    is_anom, score = det.predict(np.array([100.0, 100.0]))
    assert is_anom == True


# ---------------------------------------------------------------------------
# fit_from_transactions convenience API
# ---------------------------------------------------------------------------

def test_fit_from_transactions():
    transactions = [{"amount": float(i), "count": float(i % 5)} for i in range(50)]
    extractor = lambda tx: np.array([tx["amount"], tx["count"]])
    det = EnsembleDetector(lof_n_neighbors=20)
    det.fit_from_transactions(transactions, extractor)
    assert det.is_fitted
    is_anom, score = det.predict(np.array([25.0, 2.0]))
    assert 0.0 <= score <= 1.0


def test_fit_from_transactions_extreme():
    transactions = [{"amount": float(i)} for i in range(50)]
    extractor = lambda tx: np.array([tx["amount"]])
    det = EnsembleDetector()
    det.fit_from_transactions(transactions, extractor)
    is_anom, score = det.predict(np.array([1_000_000.0]))
    assert is_anom == True


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_thread_safe_predict(fitted):
    errors = []

    def worker():
        try:
            for _ in range(10):
                fitted.predict(np.array([0.1, 0.1]))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []

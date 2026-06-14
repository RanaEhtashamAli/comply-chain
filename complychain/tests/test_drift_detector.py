"""Tests for DriftDetector — Page-Hinkley change detection."""

import threading

import pytest

from complychain.detection.drift import DriftDetector


# ---------------------------------------------------------------------------
# Basic state
# ---------------------------------------------------------------------------

def test_initial_state():
    det = DriftDetector()
    assert not det.drift_detected
    assert det.n_seen == 0


def test_observe_increments_n_seen():
    det = DriftDetector()
    det.observe(0.1)
    det.observe(0.2)
    assert det.n_seen == 2


def test_stable_scores_no_drift():
    det = DriftDetector(threshold=50.0, delta=0.005)
    for _ in range(200):
        det.observe(0.5)
    assert not det.drift_detected


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

def test_drift_triggers_on_large_shift():
    """Scores that suddenly jump high should eventually trigger drift."""
    det = DriftDetector(threshold=5.0, delta=0.005, window_size=50)
    for _ in range(20):
        det.observe(0.0)
    drift_triggered = False
    for _ in range(200):
        if det.observe(1.0):
            drift_triggered = True
            break
    assert drift_triggered
    assert det.drift_detected


def test_observe_returns_true_exactly_once():
    det = DriftDetector(threshold=5.0, delta=0.005, window_size=50)
    for _ in range(20):
        det.observe(0.0)
    results = []
    for _ in range(200):
        results.append(det.observe(1.0))
        if det.drift_detected:
            break
    # Only one True should occur
    assert results.count(True) == 1


def test_observe_returns_false_after_drift():
    det = DriftDetector(threshold=5.0, delta=0.005, window_size=50)
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        det.observe(1.0)
        if det.drift_detected:
            break
    # Once drift is set, all subsequent observe() calls return False
    assert det.observe(1.0) is False


# ---------------------------------------------------------------------------
# on_drift callback
# ---------------------------------------------------------------------------

def test_on_drift_callback_called():
    called = []
    det = DriftDetector(
        threshold=5.0, delta=0.005, window_size=50,
        on_drift=lambda d: called.append(d)
    )
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        det.observe(1.0)
        if det.drift_detected:
            break
    assert len(called) == 1
    assert called[0] is det


def test_on_drift_callback_exception_is_swallowed():
    """Exceptions in on_drift must not propagate."""
    def bad_cb(d):
        raise RuntimeError("boom")

    det = DriftDetector(threshold=5.0, delta=0.005, on_drift=bad_cb)
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        try:
            det.observe(1.0)
        except Exception:
            pytest.fail("on_drift exception escaped")
        if det.drift_detected:
            break


def test_on_drift_called_only_once():
    call_count = []
    det = DriftDetector(
        threshold=5.0, delta=0.005,
        on_drift=lambda d: call_count.append(1)
    )
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        det.observe(1.0)
    assert sum(call_count) == 1


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------

def test_reset_clears_drift():
    det = DriftDetector(threshold=5.0, delta=0.005, window_size=50)
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        det.observe(1.0)
        if det.drift_detected:
            break
    assert det.drift_detected
    det.reset()
    assert not det.drift_detected


def test_reset_allows_redetection():
    det = DriftDetector(threshold=5.0, delta=0.005, window_size=50)
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        det.observe(1.0)
        if det.drift_detected:
            break
    det.reset()
    # After reset, drift can be triggered again
    for _ in range(20):
        det.observe(0.0)
    for _ in range(200):
        det.observe(1.0)
        if det.drift_detected:
            break
    assert det.drift_detected


# ---------------------------------------------------------------------------
# summary()
# ---------------------------------------------------------------------------

def test_summary_keys():
    det = DriftDetector()
    det.observe(0.3)
    s = det.summary()
    assert set(s) >= {"n_seen", "drift_detected", "cumsum", "window_mean", "window_std"}


def test_summary_empty_window():
    det = DriftDetector()
    s = det.summary()
    assert s["window_mean"] == 0.0
    assert s["window_std"] == 0.0


def test_summary_window_std_single_sample():
    det = DriftDetector()
    det.observe(0.5)
    s = det.summary()
    assert s["window_std"] == 0.0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_thread_safe_observe():
    det = DriftDetector(threshold=1000.0)
    errors = []

    def worker():
        try:
            for _ in range(50):
                det.observe(0.1)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert det.n_seen == 200

"""Tests for VelocityDetector and VelocityWindow."""

import threading
import time

import pytest

from complychain.detection.velocity import VelocityDetector, VelocityWindow


# ---------------------------------------------------------------------------
# VelocityWindow
# ---------------------------------------------------------------------------

def test_window_counts_and_total():
    win = VelocityWindow(window_seconds=3600)
    now = time.time()
    win.record(now, 100.0)
    win.record(now + 1, 200.0)
    assert win.count == 2
    assert win.total_amount == pytest.approx(300.0)


def test_window_max_amount():
    win = VelocityWindow(window_seconds=3600)
    now = time.time()
    win.record(now, 50.0)
    win.record(now + 1, 200.0)
    assert win.max_amount == pytest.approx(200.0)


def test_window_max_amount_empty():
    win = VelocityWindow(window_seconds=3600)
    assert win.max_amount == 0.0


def test_window_prunes_old_events():
    win = VelocityWindow(window_seconds=10)
    old_ts = time.time() - 100
    now = time.time()
    win.record(old_ts, 999.0)
    win.record(now, 50.0)
    # after recording now, prune is called and old_ts should be removed
    assert win.count == 1
    assert win.total_amount == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# VelocityDetector basics
# ---------------------------------------------------------------------------

def test_score_zero_for_unknown_entity():
    vd = VelocityDetector()
    assert vd.score("alice") == 0.0


def test_not_suspicious_when_no_activity():
    vd = VelocityDetector()
    assert vd.is_suspicious("alice") is False


def test_score_increases_with_observations():
    vd = VelocityDetector(max_count_threshold=5, max_total_threshold=500.0)
    now = time.time()
    for i in range(5):
        vd.observe("alice", 100.0, timestamp=now + i)
    assert vd.score("alice") == pytest.approx(1.0)


def test_suspicious_threshold():
    vd = VelocityDetector(max_count_threshold=10, max_total_threshold=100_000.0)
    now = time.time()
    # Put 6 out of 10 = 0.6 score → suspicious
    for i in range(6):
        vd.observe("bob", 1.0, timestamp=now + i)
    assert vd.is_suspicious("bob") is True


def test_not_suspicious_below_threshold():
    vd = VelocityDetector(max_count_threshold=10, max_total_threshold=100_000.0)
    now = time.time()
    for i in range(4):
        vd.observe("carol", 1.0, timestamp=now + i)
    assert vd.is_suspicious("carol") is False


def test_amount_based_score():
    vd = VelocityDetector(max_count_threshold=100, max_total_threshold=1000.0)
    vd.observe("dave", 600.0)
    score = vd.score("dave")
    assert score == pytest.approx(0.6)


def test_reset_clears_entity():
    vd = VelocityDetector()
    vd.observe("eve", 999.0)
    vd.reset("eve")
    assert vd.score("eve") == 0.0


def test_reset_nonexistent_entity_no_error():
    vd = VelocityDetector()
    vd.reset("nobody")  # should not raise


def test_summary_returns_dict():
    vd = VelocityDetector()
    vd.observe("frank", 100.0)
    s = vd.summary("frank")
    assert s["count"] == 1.0
    assert s["total_amount"] == pytest.approx(100.0)
    assert "score" in s
    assert "max_amount" in s


def test_summary_unknown_entity():
    vd = VelocityDetector()
    s = vd.summary("ghost")
    assert s == {"count": 0, "total_amount": 0.0, "score": 0.0}


def test_score_capped_at_one():
    vd = VelocityDetector(max_count_threshold=5, max_total_threshold=500.0)
    now = time.time()
    for i in range(20):
        vd.observe("heavy", 1000.0, timestamp=now + i)
    assert vd.score("heavy") <= 1.0


def test_thread_safety():
    vd = VelocityDetector(max_count_threshold=1000)
    errors = []

    def worker(entity, n):
        try:
            for _ in range(n):
                vd.observe(entity, 1.0)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(f"e{i}", 50)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_observe_uses_current_time_when_no_timestamp():
    """observe() without timestamp falls back to time.time()."""
    vd = VelocityDetector()
    vd.observe("auto", 100.0)  # no timestamp kwarg
    assert vd.score("auto") > 0.0

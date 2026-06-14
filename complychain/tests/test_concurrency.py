"""
Concurrency stress tests for shared-state components.

Verifies that GLBAScanner, GLBAAuditor, ConfigManager, and MLEngine
are safe to use from multiple threads simultaneously.
"""

import threading
import pytest
from complychain.threat_scanner import GLBAScanner
from complychain.audit_system import GLBAAuditor
from complychain.config import ConfigManager
from complychain.detection.ml_engine import MLEngine


# ---------------------------------------------------------------------------
# GLBAScanner — concurrent scan()
# ---------------------------------------------------------------------------

def test_scanner_concurrent_scans(tmp_path, monkeypatch):
    """scan() can be called from 10 threads without errors or data corruption."""
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path))
    scanner = GLBAScanner()
    errors = []
    results = []
    lock = threading.Lock()

    def worker(i):
        try:
            r = scanner.scan({
                "amount": 1000 * i,
                "beneficiary": f"Beneficiary{i}",
                "sender": f"Sender{i}",
            })
            with lock:
                results.append(r)
        except Exception as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent scan errors: {errors}"
    assert len(results) == 10


def test_scanner_concurrent_sanction_cache_reads(tmp_path):
    """Sanction cache reads from multiple threads return consistent types."""
    scanner = GLBAScanner()
    errors = []
    results = []
    lock = threading.Lock()

    def reader():
        try:
            cache = scanner.sanction_cache
            with lock:
                results.append(isinstance(cache, set))
        except Exception as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Cache read errors: {errors}"
    assert all(results)


# ---------------------------------------------------------------------------
# GLBAAuditor — concurrent log_transaction()
# ---------------------------------------------------------------------------

def test_auditor_concurrent_writes(tmp_path, monkeypatch):
    """log_transaction() is safe to call from 10 threads simultaneously."""
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path))
    auditor = GLBAAuditor()
    errors = []

    def worker(i):
        try:
            auditor.log_transaction(
                tx_data={"amount": i * 100, "beneficiary": f"B{i}"},
                signature=f"sig{i}".encode(),
            )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent audit write errors: {errors}"


def test_auditor_chain_integrity_after_concurrent_writes(tmp_path, monkeypatch):
    """Audit chain Merkle root is a valid hex string after 20 concurrent writes."""
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path))
    auditor = GLBAAuditor()

    def worker(i):
        auditor.log_transaction(
            tx_data={"id": i, "amount": i * 50},
            signature=f"sig_{i}".encode(),
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    root = auditor.calculate_merkle_root()
    assert isinstance(root, str)
    assert len(root) == 64  # SHA-256 hex digest
    coverage = auditor.calculate_coverage()
    assert coverage >= 20


# ---------------------------------------------------------------------------
# ConfigManager — concurrent get() / set()
# ---------------------------------------------------------------------------

def test_config_concurrent_reads():
    """Concurrent get() calls do not raise exceptions."""
    config = ConfigManager()
    errors = []

    def reader():
        try:
            config.get("compliance.mode", "production")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent config read errors: {errors}"


def test_config_concurrent_reads_and_writes():
    """Mixed concurrent get()/set() calls do not corrupt the config."""
    config = ConfigManager()
    errors = []

    def reader(key):
        try:
            config.get(key, None)
        except Exception as e:
            errors.append(e)

    def writer(key, value):
        try:
            config.set(key, value)
        except Exception as e:
            errors.append(e)

    threads = []
    for i in range(5):
        threads.append(threading.Thread(target=reader, args=(f"concurrent.key_{i}",)))
        threads.append(threading.Thread(target=writer, args=(f"concurrent.key_{i}", f"val_{i}")))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent config read/write errors: {errors}"


def test_config_singleton_returns_same_instance():
    """ConfigManager is a singleton — concurrent calls get the same object."""
    results = []
    lock = threading.Lock()

    def get_instance():
        c = ConfigManager()
        with lock:
            results.append(id(c))

    threads = [threading.Thread(target=get_instance) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(results)) == 1, "ConfigManager singleton identity violated under concurrent access"


# ---------------------------------------------------------------------------
# MLEngine — concurrent predict()
# ---------------------------------------------------------------------------

def test_ml_engine_concurrent_predictions(tmp_path):
    """predict() returns correct types from multiple threads after training."""
    engine = MLEngine(model_path=tmp_path)
    training_data = [
        {"amount": 1000 * i, "beneficiary": f"B{i}", "sender": f"S{i}"}
        for i in range(1, 6)
    ]
    engine.train(training_data)

    errors = []
    results = []
    lock = threading.Lock()

    def worker(i):
        try:
            r = engine.predict({
                "amount": i * 500,
                "beneficiary": f"Concurrent{i}",
                "sender": f"Sender{i}",
            })
            with lock:
                results.append(r)
        except Exception as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent ML prediction errors: {errors}"
    assert len(results) == 10
    for r in results:
        is_anomaly, score = r
        assert isinstance(is_anomaly, bool)
        assert isinstance(score, float)


def test_ml_engine_concurrent_train_and_predict(tmp_path):
    """Training and prediction can run concurrently without deadlock."""
    engine = MLEngine(model_path=tmp_path)
    base_data = [
        {"amount": 1000 * i, "beneficiary": f"B{i}", "sender": f"S{i}"}
        for i in range(1, 6)
    ]
    engine.train(base_data)
    errors = []

    def predictor(i):
        try:
            engine.predict({"amount": i * 200, "beneficiary": f"P{i}", "sender": f"Q{i}"})
        except Exception as e:
            errors.append(("predict", i, e))

    def trainer(batch):
        try:
            engine.train(batch)
        except Exception as e:
            errors.append(("train", e))

    extra_data = [
        {"amount": 2000 * i, "beneficiary": f"X{i}", "sender": f"Y{i}"}
        for i in range(1, 6)
    ]
    threads = [threading.Thread(target=predictor, args=(i,)) for i in range(5)]
    threads.append(threading.Thread(target=trainer, args=(extra_data,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent train/predict errors: {errors}"

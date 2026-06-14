import pytest
from complychain.threat_scanner import GLBAScanner, SanctionsVerificationStatus, SecurityError


# ---------------------------------------------------------------------------
# Basic scan
# ---------------------------------------------------------------------------

def test_scan_basic():
    scanner = GLBAScanner()
    tx_data = {"amount": 1000, "currency": "USD", "sender": "A", "receiver": "B"}
    result = scanner.scan(tx_data)
    assert "risk_score" in result
    assert "threat_flags" in result


def test_scan_returns_sanctions_status():
    scanner = GLBAScanner()
    result = scanner.scan({"amount": 500, "beneficiary": "safe", "sender": "safe"})
    assert "sanctions_data_verified" in result
    assert "sanctions_status" in result


def test_scan_high_value_transaction():
    scanner = GLBAScanner()
    result = scanner.scan({"amount": 15000, "beneficiary": "Alice", "sender": "Bob"})
    assert "HIGH_VALUE_TRANSACTION" in result["threat_flags"]


def test_scan_cross_border_flag():
    scanner = GLBAScanner()
    result = scanner.scan({"amount": 500, "cross_border": True})
    assert "CROSS_BORDER_TRANSFER" in result["threat_flags"]


def test_scan_missing_device_fingerprint():
    scanner = GLBAScanner()
    result = scanner.scan({"amount": 500})
    assert "MISSING_DEVICE_ID" in result["threat_flags"]


def test_scan_wire_transfer_flag():
    scanner = GLBAScanner()
    result = scanner.scan({"amount": 5000})
    assert "WIRE_TRANSFER_MONITORING" in result["threat_flags"]


def test_scan_cash_currency_transaction():
    scanner = GLBAScanner()
    result = scanner.scan({"amount": 15000, "currency_type": "CASH"})
    assert "CURRENCY_TRANSACTION_REPORTING" in result["threat_flags"]


def test_scan_structuring_suspected():
    scanner = GLBAScanner()
    result = scanner.scan({
        "amount": 5000,
        "transaction_count": 5,
    })
    assert "STRUCTURING_SUSPECTED" in result["threat_flags"]


def test_scan_risk_score_capped_at_100():
    scanner = GLBAScanner()
    result = scanner.scan({
        "amount": 15000,
        "cross_border": True,
        "currency_type": "CASH",
        "transaction_count": 5,
    })
    assert result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# sanction_cache property
# ---------------------------------------------------------------------------

def test_sanction_cache_getter():
    scanner = GLBAScanner()
    cache = scanner.sanction_cache
    assert isinstance(cache, set)


def test_sanction_cache_setter():
    scanner = GLBAScanner()
    scanner.sanction_cache = {"TEST_ENTITY"}
    assert "TEST_ENTITY" in scanner.sanction_cache


# ---------------------------------------------------------------------------
# FinCEN compliance checks
# ---------------------------------------------------------------------------

def test_check_fincen_compliance_cash_ctr():
    scanner = GLBAScanner()
    result = scanner.check_fincen_compliance({
        "amount": 12000,
        "currency_type": "CASH",
    })
    assert result["ctr_required"] is True


def test_check_fincen_compliance_sar():
    scanner = GLBAScanner()
    result = scanner.check_fincen_compliance({
        "amount": 6000,
        "risk_flags": ["STRUCTURING_SUSPECTED"],
    })
    assert result["sar_required"] is True


def test_check_fincen_compliance_wire_monitoring():
    scanner = GLBAScanner()
    result = scanner.check_fincen_compliance({
        "amount": 5000,
        "transfer_type": "WIRE",
    })
    assert result["wire_monitoring"] is True


def test_check_fincen_compliance_structuring_detected():
    scanner = GLBAScanner()
    result = scanner.check_fincen_compliance({
        "amount": 5000,
        "transaction_count": 5,
        "time_period_hours": 12,
    })
    assert result["structuring_detected"] is True


def test_check_fincen_compliance_clean():
    scanner = GLBAScanner()
    result = scanner.check_fincen_compliance({"amount": 100})
    assert result["ctr_required"] is False
    assert result["sar_required"] is False
    assert result["wire_monitoring"] is False


# ---------------------------------------------------------------------------
# validate_training_source
# ---------------------------------------------------------------------------

def test_validate_training_source_valid():
    scanner = GLBAScanner()
    samples = [
        {"amount": 1000, "beneficiary": "Alice", "sender": "Bob"},
        {"amount": 2000, "beneficiary": "Carol", "sender": "Dave"},
    ]
    assert scanner.validate_training_source(samples) is True


def test_validate_training_source_missing_keys():
    scanner = GLBAScanner()
    samples = [{"amount": 1000}]
    assert scanner.validate_training_source(samples) is False


def test_validate_training_source_sanctioned_entity():
    scanner = GLBAScanner()
    samples = [
        {"amount": 1000, "beneficiary": "AL-QAIDA FRONT", "sender": "Bob"},
    ]
    assert scanner.validate_training_source(samples) is False


def test_validate_training_source_extreme_ratio():
    scanner = GLBAScanner()
    samples = [
        {"amount": 1, "beneficiary": "Alice", "sender": "Bob"},
        {"amount": 2_000_000, "beneficiary": "Carol", "sender": "Dave"},
    ]
    assert scanner.validate_training_source(samples) is False


def test_validate_training_source_zero_min_amount():
    scanner = GLBAScanner()
    samples = [
        {"amount": 0, "beneficiary": "Alice", "sender": "Bob"},
        {"amount": 1000, "beneficiary": "Carol", "sender": "Dave"},
    ]
    assert scanner.validate_training_source(samples) is True


# ---------------------------------------------------------------------------
# train_model — basic IsolationForest path
# ---------------------------------------------------------------------------

def test_train_model_basic_path(monkeypatch):
    scanner = GLBAScanner()
    monkeypatch.setattr(scanner, "_ml_engine", None)
    monkeypatch.setattr(scanner, "_use_advanced_ml", False)
    samples = [
        {"amount": 1000, "beneficiary": "Alice", "sender": "Bob", "cross_border": False},
        {"amount": 2000, "beneficiary": "Carol", "sender": "Dave", "cross_border": True},
        {"amount": 3000, "beneficiary": "Eve",   "sender": "Frank", "cross_border": False},
    ]
    scanner.train_model(samples)
    assert scanner._basic_trained is True


def test_train_model_empty_samples_is_noop(monkeypatch):
    scanner = GLBAScanner()
    monkeypatch.setattr(scanner, "_ml_engine", None)
    scanner.train_model([])
    assert scanner._basic_trained is False


def test_train_model_rejects_untrusted_source():
    scanner = GLBAScanner()
    bad_samples = [{"amount": 1000}]
    with pytest.raises(SecurityError):
        scanner.train_model(bad_samples)


# ---------------------------------------------------------------------------
# _run_ml_detection with basic trained model
# ---------------------------------------------------------------------------

def test_run_ml_detection_basic_model(monkeypatch):
    scanner = GLBAScanner()
    monkeypatch.setattr(scanner, "_ml_engine", None)
    monkeypatch.setattr(scanner, "_use_advanced_ml", False)
    samples = [
        {"amount": 1000 * i, "beneficiary": f"B{i}", "sender": f"S{i}", "cross_border": False}
        for i in range(1, 6)
    ]
    scanner.train_model(samples)
    result = scanner._run_ml_detection({"amount": 5000})
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Fallback data methods
# ---------------------------------------------------------------------------

def test_get_ofac_fallback_data():
    scanner = GLBAScanner()
    data = scanner._get_ofac_fallback_data()
    assert isinstance(data, set)
    assert "AL-QAIDA" in data


def test_get_fincen_fallback_data():
    scanner = GLBAScanner()
    data = scanner._get_fincen_fallback_data()
    assert isinstance(data, set)
    assert len(data) > 0


def test_get_unsc_fallback_data():
    scanner = GLBAScanner()
    data = scanner._get_unsc_fallback_data()
    assert isinstance(data, set)


def test_get_uk_fallback_data():
    scanner = GLBAScanner()
    data = scanner._get_uk_fallback_data()
    assert isinstance(data, set)


# ---------------------------------------------------------------------------
# _get_compliance_requirements
# ---------------------------------------------------------------------------

def test_compliance_requirements_high_value():
    scanner = GLBAScanner()
    reqs = scanner._get_compliance_requirements({"amount": 15000})
    assert "GLBA_314_4_c_8_HIGH_VALUE_MONITORING" in reqs


def test_compliance_requirements_device_fingerprint():
    scanner = GLBAScanner()
    reqs = scanner._get_compliance_requirements({
        "amount": 100, "device_fingerprint": "fp123"
    })
    assert "GLBA_314_4_c_1_DEVICE_ACCESS_CONTROL" in reqs


def test_compliance_requirements_wire():
    scanner = GLBAScanner()
    reqs = scanner._get_compliance_requirements({
        "amount": 5000, "transfer_type": "WIRE"
    })
    assert "FINCEN_WIRE_MONITORING" in reqs


def test_compliance_requirements_ctr():
    scanner = GLBAScanner()
    reqs = scanner._get_compliance_requirements({
        "amount": 12000, "currency_type": "CASH"
    })
    assert "FINCEN_CTR_REQUIRED" in reqs


def test_compliance_requirements_sanctions_match():
    scanner = GLBAScanner()
    reqs = scanner._get_compliance_requirements({
        "amount": 100, "beneficiary": "AL-QAIDA ENTITY"
    })
    assert "OFAC_SANCTIONS_SCREENING" in reqs


# ---------------------------------------------------------------------------
# _check_sanctions_match
# ---------------------------------------------------------------------------

def test_sanctions_match_known_entity():
    scanner = GLBAScanner()
    assert scanner._check_sanctions_match({"beneficiary": "AL-QAIDA NETWORK", "sender": "clean"})


def test_sanctions_no_match():
    scanner = GLBAScanner()
    assert not scanner._check_sanctions_match({"beneficiary": "John Smith", "sender": "Jane Doe"})


# ---------------------------------------------------------------------------
# ML anomaly path in scan() — lines 187-188
# ---------------------------------------------------------------------------

def test_scan_ml_anomaly_detected_flag(monkeypatch):
    """Lines 187-188: ML_ANOMALY_DETECTED flag added when _run_ml_detection returns True."""
    scanner = GLBAScanner()
    monkeypatch.setattr(scanner, "_run_ml_detection", lambda tx: True)
    result = scanner.scan({"amount": 100, "beneficiary": "Safe", "sender": "Legit"})
    assert "ML_ANOMALY_DETECTED" in result["threat_flags"]
    assert result["risk_score"] >= 30


# ---------------------------------------------------------------------------
# _run_ml_detection error and untrained paths — lines 212-213, 232
# ---------------------------------------------------------------------------

def test_run_ml_detection_advanced_ml_exception(monkeypatch):
    """Lines 212-213: exception from MLEngine.predict() is silently caught; falls through."""
    from unittest.mock import MagicMock
    scanner = GLBAScanner()
    broken_ml = MagicMock()
    broken_ml.predict.side_effect = RuntimeError("predict failed")
    monkeypatch.setattr(scanner, "_ml_engine", broken_ml)
    monkeypatch.setattr(scanner, "_use_advanced_ml", True)
    monkeypatch.setattr(scanner, "_basic_trained", False)
    result = scanner._run_ml_detection({"amount": 100, "beneficiary": "B", "sender": "S"})
    assert result is False


def test_run_ml_detection_no_model_returns_false(monkeypatch):
    """Line 232: returns False when no model is trained."""
    scanner = GLBAScanner()
    monkeypatch.setattr(scanner, "_ml_engine", None)
    monkeypatch.setattr(scanner, "_use_advanced_ml", False)
    monkeypatch.setattr(scanner, "_basic_trained", False)
    result = scanner._run_ml_detection({"amount": 100})
    assert result is False


# ---------------------------------------------------------------------------
# validate_training_source test_mode empty-cache path — lines 491-493
# ---------------------------------------------------------------------------

def test_validate_training_source_test_mode_empty_cache():
    """Lines 491-493: test_mode=True with empty cache loads OFAC fallback in-place."""
    scanner = GLBAScanner()
    scanner.test_mode = True
    scanner._sanction_cache = set()  # force empty so the test_mode branch runs
    samples = [
        {"amount": 1000, "beneficiary": "SafeParty", "sender": "LegitCorp"},
    ]
    result = scanner.validate_training_source(samples)
    assert isinstance(result, bool)
    assert len(scanner._sanction_cache) > 0
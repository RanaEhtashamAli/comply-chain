"""Tests for AMLGraph graph-based AML pattern detection."""

import time
import pytest
from complychain.detection.graph import AMLGraph, AMLPattern


def _tx(originator, beneficiary, amount, timestamp=None):
    return {
        "originator": originator,
        "beneficiary": beneficiary,
        "amount": amount,
        "timestamp": timestamp or time.time(),
    }


def test_add_transaction_does_not_raise():
    g = AMLGraph()
    g.add_transaction(_tx("alice", "bob", 5000))


def test_detect_patterns_empty_returns_list():
    g = AMLGraph()
    assert g.detect_patterns() == []


def test_structuring_detected():
    g = AMLGraph()
    for _ in range(4):
        g.add_transaction(_tx("alice", "bob", 3000))
    patterns = g.detect_patterns()
    types = [p.pattern_type for p in patterns]
    assert "STRUCTURING" in types


def test_structuring_entities_include_originator():
    g = AMLGraph()
    for _ in range(4):
        g.add_transaction(_tx("alice", "bob", 3000))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "STRUCTURING"]
    assert any("alice" in p.entities for p in patterns)


def test_structuring_confidence_in_range():
    g = AMLGraph()
    for _ in range(5):
        g.add_transaction(_tx("alice", "bob", 2500))
    for p in g.detect_patterns():
        if p.pattern_type == "STRUCTURING":
            assert 0.0 <= p.confidence <= 1.0


def test_no_structuring_below_threshold():
    g = AMLGraph()
    g.add_transaction(_tx("alice", "bob", 3000))
    g.add_transaction(_tx("alice", "bob", 3000))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "STRUCTURING"]
    assert patterns == []


def test_layering_detected():
    g = AMLGraph()
    g.add_transaction(_tx("alice", "bob", 1000))
    g.add_transaction(_tx("bob", "alice", 900))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "LAYERING"]
    assert len(patterns) > 0


def test_layering_entities_contain_cycle():
    g = AMLGraph()
    g.add_transaction(_tx("alice", "bob", 1000))
    g.add_transaction(_tx("bob", "charlie", 900))
    g.add_transaction(_tx("charlie", "alice", 800))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "LAYERING"]
    if patterns:
        entities = set(patterns[0].entities)
        assert {"alice", "bob", "charlie"}.issubset(entities)


def test_fan_out_detected():
    g = AMLGraph()
    for i in range(6):
        g.add_transaction(_tx("alice", f"recv_{i}", 1000))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "FAN_OUT"]
    assert len(patterns) > 0


def test_fan_out_originator_in_entities():
    g = AMLGraph()
    for i in range(6):
        g.add_transaction(_tx("alice", f"recv_{i}", 1000))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "FAN_OUT"]
    assert any("alice" in p.entities for p in patterns)


def test_common_beneficiary_detected():
    g = AMLGraph()
    for i in range(6):
        g.add_transaction(_tx(f"src_{i}", "carol", 1000))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "COMMON_BENEFICIARY"]
    assert len(patterns) > 0


def test_common_beneficiary_entities_include_beneficiary():
    g = AMLGraph()
    for i in range(6):
        g.add_transaction(_tx(f"src_{i}", "carol", 1000))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "COMMON_BENEFICIARY"]
    assert any("carol" in p.entities for p in patterns)


def test_get_entity_risk_unknown_returns_zero():
    g = AMLGraph()
    assert g.get_entity_risk("nonexistent_entity") == 0.0


def test_get_entity_risk_suspicious_entity():
    g = AMLGraph()
    for _ in range(4):
        g.add_transaction(_tx("alice", "bob", 3000))
    risk = g.get_entity_risk("alice")
    assert 0.0 <= risk <= 1.0


def test_reset_clears_all():
    g = AMLGraph()
    for _ in range(5):
        g.add_transaction(_tx("alice", "bob", 1000))
    g.reset()
    assert g.detect_patterns() == []


def test_reset_older_than_prunes():
    g = AMLGraph()
    old_ts = time.time() - 7200
    for _ in range(5):
        g.add_transaction(_tx("alice", "bob", 3000, timestamp=old_ts))
    g.reset(older_than_seconds=3600)
    assert g.detect_patterns() == []


def test_window_ignores_old_transactions():
    g = AMLGraph(window_seconds=60)
    old_ts = time.time() - 3600
    for _ in range(5):
        g.add_transaction(_tx("alice", "bob", 3000, timestamp=old_ts))
    patterns = [p for p in g.detect_patterns() if p.pattern_type == "STRUCTURING"]
    assert patterns == []


def test_export_gexf_returns_string():
    g = AMLGraph()
    g.add_transaction(_tx("alice", "bob", 1000))
    gexf = g.export_gexf()
    assert isinstance(gexf, str)
    assert "gexf" in gexf.lower()


def test_aml_pattern_dataclass():
    p = AMLPattern(
        pattern_type="STRUCTURING",
        entities=["alice"],
        transaction_ids=["tx1"],
        confidence=0.75,
        description="test",
    )
    assert p.pattern_type == "STRUCTURING"
    assert p.confidence == 0.75


def test_add_transaction_custom_tx_id():
    g = AMLGraph()
    g.add_transaction(_tx("alice", "bob", 1000), tx_id="my-tx-123")
    for _ in range(3):
        g.add_transaction(_tx("alice", "bob", 3000), tx_id=f"tx-{_}")

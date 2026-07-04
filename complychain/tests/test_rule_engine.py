"""Tests for RuleEngine."""

import pytest
from pathlib import Path

from complychain.rules.engine import RuleEngine, RuleResult, Rule


def _write_rules(tmp_path, content: str) -> Path:
    f = tmp_path / "rules.yaml"
    f.write_text(content)
    return f


_SIMPLE_YAML = """
rules:
  - name: high_wire
    condition: "amount > 7500 and transaction_type == 'wire'"
    risk_weight: 40
    flag: HIGH_WIRE
    severity: HIGH
    description: "Wire above threshold"
    enabled: true
  - name: cross_border
    condition: "destination_country != 'US'"
    risk_weight: 20
    flag: CROSS_BORDER
    severity: MEDIUM
    description: "Non-US destination"
    enabled: true
  - name: disabled_rule
    condition: "amount > 0"
    risk_weight: 99
    flag: DISABLED_FLAG
    severity: LOW
    description: "Always matches but disabled"
    enabled: false
"""


def test_load_returns_engine(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    assert isinstance(engine, RuleEngine)


def test_load_counts_rules(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    assert len(engine._rules) == 3


def test_evaluate_matches_wire(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 8000, "transaction_type": "wire", "destination_country": "US"})
    assert isinstance(result, RuleResult)
    assert "HIGH_WIRE" in result.extra_flags


def test_evaluate_adds_risk(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 8000, "transaction_type": "wire", "destination_country": "US"})
    assert result.added_risk == 40


def test_evaluate_no_match(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 100, "transaction_type": "ach", "destination_country": "US"})
    assert result.added_risk == 0
    assert result.extra_flags == []


def test_disabled_rule_skipped(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 1, "transaction_type": "ach", "destination_country": "US"})
    assert "DISABLED_FLAG" not in result.extra_flags


def test_evaluate_multiple_matches(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 8000, "transaction_type": "wire", "destination_country": "MX"})
    assert "HIGH_WIRE" in result.extra_flags
    assert "CROSS_BORDER" in result.extra_flags
    assert result.added_risk == 60


def test_matched_rules_list(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 8000, "transaction_type": "wire", "destination_country": "US"})
    assert len(result.matched_rules) == 1
    assert result.matched_rules[0].name == "high_wire"


def test_validate_valid_rules(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    errors = engine.validate()
    assert errors == []


def test_validate_invalid_severity(tmp_path):
    yaml_content = """
rules:
  - name: bad
    condition: "amount > 0"
    risk_weight: 10
    flag: BAD
    severity: INVALID_SEV
    description: test
    enabled: true
"""
    path = _write_rules(tmp_path, yaml_content)
    engine = RuleEngine.load(path)
    errors = engine.validate()
    assert any("severity" in e.lower() for e in errors)


def test_validate_invalid_severity_and_empty_name(tmp_path):
    yaml_content = """
rules:
  - name: ""
    condition: "amount > 0"
    risk_weight: 10
    flag: BAD
    severity: NOTVALID
    description: test
    enabled: true
"""
    path = _write_rules(tmp_path, yaml_content)
    engine = RuleEngine.load(path)
    errors = engine.validate()
    assert len(errors) >= 1
    assert any("name" in e.lower() or "severity" in e.lower() for e in errors)


def test_to_dict_result():
    result = RuleResult(
        matched_rules=[Rule("test", "amount > 0", 10, "TEST", "HIGH", "desc")],
        added_risk=10,
        extra_flags=["TEST"],
    )
    d = result.to_dict()
    assert d["added_risk"] == 10
    assert "TEST" in d["extra_flags"]
    assert d["matched_rules"][0]["name"] == "test"


def test_safe_eval_exception_returns_false(tmp_path):
    yaml_content = """
rules:
  - name: divzero
    condition: "1/0"
    risk_weight: 10
    flag: DIV
    severity: HIGH
    description: test
    enabled: true
"""
    path = _write_rules(tmp_path, yaml_content)
    engine = RuleEngine.load(path)
    result = engine.evaluate({"amount": 1})
    assert "DIV" not in result.extra_flags


def test_empty_rules_file(tmp_path):
    path = _write_rules(tmp_path, "rules: []")
    engine = RuleEngine.load(path)
    assert engine._rules == []
    result = engine.evaluate({"amount": 100})
    assert result.added_risk == 0


def test_rule_engine_emits_event(tmp_path):
    path = _write_rules(tmp_path, _SIMPLE_YAML)
    engine = RuleEngine.load(path)
    events = []
    from complychain.events import default_bus, EventType
    handler = lambda e: events.append(e)
    default_bus.subscribe(EventType.RULE_TRIGGERED, handler)
    try:
        engine.evaluate({"amount": 8000, "transaction_type": "wire", "destination_country": "US"})
        assert any(e.event_type == EventType.RULE_TRIGGERED for e in events)
    finally:
        default_bus.unsubscribe(EventType.RULE_TRIGGERED, handler)

"""Tests for ExplanationEngine and related dataclasses."""

import pytest
from complychain.reporting.explainability import ExplanationEngine, Explanation, ExplanationFactor


_SCAN_RESULT = {
    "risk_score": 75,
    "threat_flags": ["HIGH_VALUE_TRANSACTION", "CROSS_BORDER_TRANSFER"],
    "fincen_compliance": {"ctr_required": True, "sar_required": False},
}

_TX_DATA = {
    "amount": 15000.0,
    "transaction_type": "wire",
    "beneficiary": "ACME Corp",
    "destination_country": "MX",
}


def test_explain_returns_explanation():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert isinstance(exp, Explanation)


def test_risk_score_matches():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert exp.risk_score == 75


def test_ranked_factors_non_empty():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert len(exp.ranked_factors) == 2


def test_factors_are_explanation_factor_instances():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    for f in exp.ranked_factors:
        assert isinstance(f, ExplanationFactor)


def test_contributions_sum_to_one():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    total = sum(f.contribution for f in exp.ranked_factors)
    assert abs(total - 1.0) < 1e-6


def test_primary_driver_is_highest_contribution():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert exp.ranked_factors[0].flag == exp.ranked_factors[0].flag
    assert exp.primary_driver == exp.ranked_factors[0].factor_name


def test_ranked_descending():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    contribs = [f.contribution for f in exp.ranked_factors]
    assert contribs == sorted(contribs, reverse=True)


def test_narrative_non_empty():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert len(exp.narrative) > 20


def test_narrative_mentions_risk_score():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert "75" in exp.narrative


def test_remediation_is_list():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    assert isinstance(exp.remediation, list)
    assert len(exp.remediation) > 0


def test_to_dict_keys():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    d = exp.to_dict()
    for key in ("risk_score", "primary_driver", "narrative", "remediation", "ranked_factors"):
        assert key in d


def test_to_dict_ranked_factors_structure():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    for factor in exp.to_dict()["ranked_factors"]:
        for key in ("factor_name", "flag", "contribution", "description", "evidence", "remediation"):
            assert key in factor


def test_sanctions_augmented_from_fincen():
    scan = {
        "risk_score": 100,
        "threat_flags": [],
        "fincen_compliance": {"sanctions_match": True},
    }
    exp = ExplanationEngine().explain(scan, _TX_DATA)
    flags = [f.flag for f in exp.ranked_factors]
    assert "SANCTIONS_MATCH" in flags


def test_no_flags_empty_factors():
    scan = {"risk_score": 0, "threat_flags": [], "fincen_compliance": {}}
    exp = ExplanationEngine().explain(scan, {})
    assert exp.ranked_factors == []
    assert exp.primary_driver == "none"


def test_no_flags_narrative_mentions_score():
    scan = {"risk_score": 0, "threat_flags": [], "fincen_compliance": {}}
    exp = ExplanationEngine().explain(scan, {})
    assert "0" in exp.narrative


def test_evidence_has_amount():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    for f in exp.ranked_factors:
        assert "amount" in f.evidence


def test_evidence_sanctions_has_beneficiary():
    scan = {"risk_score": 100, "threat_flags": ["SANCTIONS_MATCH"], "fincen_compliance": {}}
    exp = ExplanationEngine().explain(scan, {"amount": 100, "beneficiary": "Evil Corp"})
    sanctions_factor = next(f for f in exp.ranked_factors if f.flag == "SANCTIONS_MATCH")
    assert "beneficiary" in sanctions_factor.evidence


def test_cross_border_evidence_has_destination():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    cb = next((f for f in exp.ranked_factors if f.flag == "CROSS_BORDER_TRANSFER"), None)
    if cb:
        assert "destination_country" in cb.evidence


def test_remediation_deduped():
    scan = {
        "risk_score": 80,
        "threat_flags": ["HIGH_VALUE_TRANSACTION", "CURRENCY_TRANSACTION_REPORTING"],
        "fincen_compliance": {},
    }
    exp = ExplanationEngine().explain(scan, {"amount": 12000})
    assert len(exp.remediation) == len(set(exp.remediation))


def test_contribution_precision():
    exp = ExplanationEngine().explain(_SCAN_RESULT, _TX_DATA)
    d = exp.to_dict()
    for factor in d["ranked_factors"]:
        val = factor["contribution"]
        assert 0.0 <= val <= 1.0
        assert len(str(round(val, 3))) <= 8

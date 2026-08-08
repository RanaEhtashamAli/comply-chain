"""
RuleEngine — evaluate configurable compliance rules against transaction data.

Rules are defined in YAML and evaluated with simpleeval (safe, sandboxed eval).
The engine integrates with GLBAScanner.scan() via the `rule_engine` parameter.

YAML schema:
    version: "1"
    rules:
      - name: internal_high_value_wire
        condition: "amount > 7500 and transaction_type == 'wire'"
        risk_weight: 40
        flag: INTERNAL_HIGH_VALUE_WIRE
        severity: HIGH
        description: "Wire transfer exceeds internal threshold"
        enabled: true

Usage:
    engine = RuleEngine.load(Path("rules.yaml"))
    result = engine.evaluate({"amount": 9000, "transaction_type": "wire"})
    print(result.added_risk, result.extra_flags)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    from simpleeval import EvalWithCompoundTypes, InvalidExpression
    _SIMPLEEVAL_AVAILABLE = True
except ImportError:
    _SIMPLEEVAL_AVAILABLE = False

_VALID_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass
class Rule:
    name: str
    condition: str
    risk_weight: int
    flag: str
    severity: str
    description: str
    enabled: bool = True


@dataclass
class RuleResult:
    matched_rules: List[Rule] = field(default_factory=list)
    added_risk: int = 0
    extra_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added_risk": self.added_risk,
            "extra_flags": self.extra_flags,
            "matched_rules": [
                {
                    "name": r.name,
                    "flag": r.flag,
                    "severity": r.severity,
                    "risk_weight": r.risk_weight,
                    "description": r.description,
                }
                for r in self.matched_rules
            ],
        }


class RuleEngine:
    """Evaluates YAML-defined compliance rules against transaction data."""

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self._rules: List[Rule] = rules or []

    @classmethod
    def load(cls, path: Path) -> "RuleEngine":
        """Load rules from a YAML file."""
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)

        raw_rules = doc.get("rules", []) if isinstance(doc, dict) else []
        rules = []
        for entry in raw_rules:
            rules.append(Rule(
                name=str(entry.get("name", "")),
                condition=str(entry.get("condition", "False")),
                risk_weight=int(entry.get("risk_weight", 0)),
                flag=str(entry.get("flag", entry.get("name", "UNKNOWN").upper())),
                severity=str(entry.get("severity", "MEDIUM")).upper(),
                description=str(entry.get("description", "")),
                enabled=bool(entry.get("enabled", True)),
            ))
        return cls(rules)

    def evaluate(self, tx_data: dict) -> RuleResult:
        result = RuleResult()
        for rule in self._rules:
            if not rule.enabled:
                continue
            if self._safe_eval(rule.condition, tx_data):
                result.matched_rules.append(rule)
                result.added_risk += rule.risk_weight
                if rule.flag not in result.extra_flags:
                    result.extra_flags.append(rule.flag)

                try:
                    from ..events import default_bus, Event, EventType
                    default_bus.emit(Event(EventType.RULE_TRIGGERED, {
                        "rule_name": rule.name,
                        "flag": rule.flag,
                        "severity": rule.severity,
                        "risk_weight": rule.risk_weight,
                    }))
                except Exception:
                    pass

        return result

    def validate(self) -> List[str]:
        """Return a list of syntax/validation errors (empty list = valid)."""
        errors: List[str] = []
        if not _SIMPLEEVAL_AVAILABLE:
            errors.append(
                "simpleeval is not installed — rule conditions cannot be validated. "
                "Install with: pip install simpleeval"
            )
            return errors

        # Validation vocabulary. This must track the transaction schema the
        # scanner and the ML feature extractor actually accept — a six-field
        # subset rejected legitimate rules written against documented fields
        # such as is_cross_border, which the scanner reads and _extract_features
        # turns into a model feature.
        dummy = {
            # Core
            "amount": 0.0, "transaction_type": "", "currency": "",
            "currency_type": "", "destination_country": "",
            # Parties (both naming conventions in use across the codebase)
            "beneficiary": "", "originator": "", "sender": "", "receiver": "",
            # Temporal / geo
            "timestamp": 0, "time_period_hours": 0,
            "latitude": 0.0, "longitude": 0.0,
            # Account history
            "account_age_days": 0, "transaction_count": 0,
            "avg_transaction_amount": 0.0,
            # Risk indicators (all consumed by MLEngine._extract_features)
            "is_high_value": False, "is_cross_border": False,
            "is_wire_transfer": False, "is_new_recipient": False,
            "is_after_hours": False,
            # Misc
            "device_id": "", "risk_flags": [],
        }
        for rule in self._rules:
            if not rule.name:
                errors.append("Rule missing 'name' field.")
            if not rule.condition:
                errors.append(f"Rule '{rule.name}': empty condition.")
            if rule.severity not in _VALID_SEVERITIES:
                errors.append(
                    f"Rule '{rule.name}': invalid severity '{rule.severity}'. "
                    f"Must be one of {sorted(_VALID_SEVERITIES)}."
                )
            try:
                EvalWithCompoundTypes(names=dummy).eval(rule.condition)
            except InvalidExpression as exc:
                errors.append(f"Rule '{rule.name}': invalid condition — {exc}")
            except Exception as exc:
                # Previously `pass`, which let a rule that blew up during
                # evaluation be reported as valid. Anything unexpected here is
                # still a reason not to trust the rule.
                errors.append(
                    f"Rule '{rule.name}': condition could not be evaluated — "
                    f"{type(exc).__name__}: {exc}"
                )
        return errors

    def _safe_eval(self, condition: str, context: dict) -> bool:
        if not _SIMPLEEVAL_AVAILABLE:
            raise ImportError(
                "simpleeval is required for rule evaluation. "
                "Install with: pip install simpleeval"
            )
        try:
            result = EvalWithCompoundTypes(names=context).eval(condition)
            return bool(result)
        except Exception:
            return False

"""
ExplanationEngine — translates a GLBAScanner risk score into ranked,
human-readable factors and remediation steps.

Uses RISK_WEIGHTS from constants to back-calculate each flag's contribution,
so the explanation is always consistent with the actual scoring logic.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..constants import RISK_WEIGHTS

_FLAG_META: Dict[str, Dict[str, str]] = {
    "HIGH_VALUE_TRANSACTION": {
        "description": "Transaction amount exceeds the $10,000 CTR threshold.",
        "remediation": "Ensure a Currency Transaction Report (CTR) is filed with FinCEN within 15 days.",
    },
    "CROSS_BORDER_TRANSFER": {
        "description": "Transaction crosses an international border, increasing exposure to foreign sanctions.",
        "remediation": "Verify the destination country is not subject to OFAC sanctions or FATF grey-listing.",
    },
    "MISSING_DEVICE_ID": {
        "description": "No device fingerprint was provided, impairing device-based access controls (GLBA §314.4(c)(1)).",
        "remediation": "Implement device fingerprinting in the transaction origination flow.",
    },
    "WIRE_TRANSFER_MONITORING": {
        "description": "Wire transfer amount triggers FinCEN monitoring requirements (>$3,000).",
        "remediation": "Collect and retain originator/beneficiary information per BSA travel rule.",
    },
    "STRUCTURING_SUSPECTED": {
        "description": "Multiple transactions just below reporting thresholds suggest deliberate structuring.",
        "remediation": "File a Suspicious Activity Report (SAR) and escalate to the BSA Officer.",
    },
    "CURRENCY_TRANSACTION_REPORTING": {
        "description": "Cash transaction above $10,000 requires mandatory CTR filing.",
        "remediation": "File FinCEN Form 112 (CTR) within 15 days of the transaction.",
    },
    "ML_ANOMALY_DETECTED": {
        "description": "The transaction's feature profile is statistically anomalous relative to the trained baseline.",
        "remediation": "Manually review the transaction; consider additional customer due diligence (CDD).",
    },
    "SANCTIONS_MATCH": {
        "description": "A party in this transaction matches an OFAC SDN or FinCEN watchlist entry.",
        "remediation": "Block the transaction immediately and file a SAR. Notify your compliance officer.",
    },
    "PEP_EXPOSURE": {
        "description": "A politically exposed person (PEP) is involved, requiring enhanced due diligence.",
        "remediation": "Apply Enhanced Due Diligence (EDD) procedures per GLBA §314.4(b).",
    },
}

_FLAG_TO_WEIGHT_KEY: Dict[str, str] = {
    "HIGH_VALUE_TRANSACTION":       "high_value_tx",
    "CROSS_BORDER_TRANSFER":        "cross_border",
    "WIRE_TRANSFER_MONITORING":     "wire_transfer",
    "STRUCTURING_SUSPECTED":        "structuring",
    "CURRENCY_TRANSACTION_REPORTING":"currency_transaction",
    "ML_ANOMALY_DETECTED":          "high_value_tx",  # no dedicated key; approximate
    "SANCTIONS_MATCH":              "sanctioned_entities",
    "PEP_EXPOSURE":                 "pep_exposure",
    "MISSING_DEVICE_ID":            "cross_border",   # approximate
}


@dataclass
class ExplanationFactor:
    factor_name: str
    flag: str
    contribution: float      # 0.0–1.0 share of total raw weight
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass
class Explanation:
    risk_score: int
    primary_driver: str
    ranked_factors: List[ExplanationFactor]
    narrative: str
    remediation: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "primary_driver": self.primary_driver,
            "narrative": self.narrative,
            "remediation": self.remediation,
            "ranked_factors": [
                {
                    "factor_name": f.factor_name,
                    "flag": f.flag,
                    "contribution": round(f.contribution, 3),
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in self.ranked_factors
            ],
        }


class ExplanationEngine:
    """Converts a scan result dict into a ranked, human-readable explanation."""

    def explain(self, scan_result: dict, tx_data: dict) -> Explanation:
        flags: List[str] = scan_result.get("threat_flags", [])
        risk_score: int = scan_result.get("risk_score", 0)
        fincen: dict = scan_result.get("fincen_compliance", {})

        # Augment flags with fincen signals not already in threat_flags
        if fincen.get("sanctions_match") and "SANCTIONS_MATCH" not in flags:
            flags = list(flags) + ["SANCTIONS_MATCH"]

        factors = self._compute_contributions(flags, tx_data, fincen)
        narrative = self._build_narrative(factors, risk_score, tx_data)
        remediation = self._build_remediation(factors)
        primary = factors[0].factor_name if factors else "none"

        return Explanation(
            risk_score=risk_score,
            primary_driver=primary,
            ranked_factors=factors,
            narrative=narrative,
            remediation=remediation,
        )

    def _compute_contributions(
        self, flags: List[str], tx_data: dict, fincen: dict
    ) -> List[ExplanationFactor]:
        factors: List[ExplanationFactor] = []
        total_raw = 0.0

        for flag in flags:
            weight_key = _FLAG_TO_WEIGHT_KEY.get(flag)
            raw_weight = float(RISK_WEIGHTS.get(weight_key, 10)) if weight_key else 10.0
            total_raw += raw_weight

            meta = self._flag_meta(flag, fincen)
            evidence = self._extract_evidence(flag, tx_data, fincen)

            factors.append(ExplanationFactor(
                factor_name=flag.replace("_", " ").title(),
                flag=flag,
                contribution=raw_weight,  # normalise after totalling
                description=meta.get("description", f"Flag: {flag}"),
                evidence=evidence,
                remediation=meta.get("remediation", ""),
            ))

        # Normalise contributions to 0–1
        if total_raw > 0:
            for f in factors:
                f.contribution = f.contribution / total_raw

        # Sort descending by contribution
        factors.sort(key=lambda f: f.contribution, reverse=True)
        return factors

    # A CTR (FinCEN Form 112) is a *currency* report: it is due on cash
    # transactions over $10,000, not on wires or book transfers. The scanner
    # already decides this correctly via fincen["ctr_required"], so the
    # explanation must not instruct an officer to file one when the scanner
    # said none is due — previously a $50,000 wire produced "ensure a CTR is
    # filed" alongside "ctr_required: false" in the same payload.
    _HIGH_VALUE_NON_CASH = {
        "description": (
            "Transaction amount exceeds $10,000, the threshold at which currency "
            "transactions become reportable. No Currency Transaction Report is due "
            "here, as this is not a cash transaction."
        ),
        "remediation": (
            "Review under your enhanced due-diligence policy for large transfers. "
            "No CTR filing is required for non-cash activity."
        ),
    }

    def _flag_meta(self, flag: str, fincen: dict) -> Dict[str, str]:
        """Flag copy, adjusted for context where static text would be wrong."""
        if flag == "HIGH_VALUE_TRANSACTION" and not fincen.get("ctr_required", False):
            return self._HIGH_VALUE_NON_CASH
        return _FLAG_META.get(flag, {})

    def _extract_evidence(self, flag: str, tx_data: dict, fincen: dict) -> Dict[str, Any]:
        amount = tx_data.get("amount", 0)
        evidence: Dict[str, Any] = {"amount": amount}
        if flag == "HIGH_VALUE_TRANSACTION":
            evidence["ctr_required"] = fincen.get("ctr_required", False)
        elif flag == "STRUCTURING_SUSPECTED":
            evidence["transaction_count"] = tx_data.get("transaction_count", "unknown")
            evidence["sar_required"] = fincen.get("sar_required", False)
        elif flag == "SANCTIONS_MATCH":
            evidence["beneficiary"] = tx_data.get("beneficiary", "unknown")
            evidence["originator"] = tx_data.get("originator", "unknown")
        elif flag == "CROSS_BORDER_TRANSFER":
            evidence["destination_country"] = tx_data.get("destination_country", "unknown")
        return evidence

    def _build_narrative(
        self, factors: List[ExplanationFactor], risk_score: int, tx_data: dict
    ) -> str:
        if not factors:
            return f"Risk score of {risk_score} — no specific threat flags were raised."

        primary = factors[0]
        amount = tx_data.get("amount", 0)
        tx_type = tx_data.get("transaction_type", "transaction")

        lines = [
            f"Risk score of {risk_score}/100. "
            f"Primary driver: {primary.factor_name} "
            f"({primary.contribution * 100:.0f}% of flagged weight). "
            f"{primary.description}"
        ]

        if len(factors) > 1:
            secondary = ", ".join(f.factor_name for f in factors[1:3])
            lines.append(f"Additional contributing factors: {secondary}.")

        if amount:
            lines.append(
                f"Transaction amount: ${amount:,.2f} ({tx_type})."
            )

        return " ".join(lines)

    def _build_remediation(self, factors: List[ExplanationFactor]) -> List[str]:
        seen: set = set()
        steps: List[str] = []
        for f in factors:
            if f.remediation and f.remediation not in seen:
                steps.append(f.remediation)
                seen.add(f.remediation)
        return steps

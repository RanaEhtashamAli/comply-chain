"""
GLBA §314.4(f) — Vendor Management and Oversight

Tracks service providers, their security assessments, and contractual
security requirements. Required by 16 CFR §314.4(f): financial institutions
must select, retain, and oversee service providers that maintain appropriate
safeguards for customer information.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ASSESSMENT_VALID_DAYS = 365  # Annual re-assessment required


@dataclass
class VendorRecord:
    vendor_id: str
    name: str
    service_type: str           # e.g. 'cloud_storage', 'payment_processing'
    contact_email: str
    risk_level: str             # 'high' | 'medium' | 'low'
    registered_at: str
    last_assessed_at: Optional[str] = None
    contract_expiry: Optional[str] = None
    contract_requirements: List[str] = field(default_factory=list)
    assessment_findings: List[str] = field(default_factory=list)
    status: str = 'pending'     # 'approved' | 'pending' | 'suspended'

    def is_assessment_overdue(self) -> bool:
        if not self.last_assessed_at:
            return True
        last = datetime.fromisoformat(self.last_assessed_at)
        return datetime.now() > last + timedelta(days=ASSESSMENT_VALID_DAYS)

    def is_contract_expired(self) -> bool:
        if not self.contract_expiry:
            return False
        return datetime.now() > datetime.fromisoformat(self.contract_expiry)

    def to_dict(self) -> dict:
        return {
            'vendor_id': self.vendor_id,
            'name': self.name,
            'service_type': self.service_type,
            'contact_email': self.contact_email,
            'risk_level': self.risk_level,
            'registered_at': self.registered_at,
            'last_assessed_at': self.last_assessed_at,
            'contract_expiry': self.contract_expiry,
            'contract_requirements': self.contract_requirements,
            'assessment_findings': self.assessment_findings,
            'status': self.status,
        }


class VendorManager:
    """
    Implements GLBA §314.4(f): Vendor Management and Oversight.

    Registers third-party service providers, records annual security
    assessments, tracks contractual security requirements, and reports
    on overall vendor compliance status.

    Args:
        auditor: Optional GLBAAuditor for tamper-evident audit trail.
        store_dir: Directory for the vendor JSON store.
    """

    STORE_FILENAME = 'vendors.json'

    def __init__(self, auditor=None, store_dir: Optional[Path] = None):
        self._auditor = auditor
        _env = os.environ.get('COMPLYCHAIN_VENDOR_DIR')
        default_dir = Path(_env) if _env else Path.home() / '.complychain' / 'vendors'
        self._store_dir = Path(store_dir) if store_dir else default_dir
        self._store_file = self._store_dir / self.STORE_FILENAME
        self._vendors: Dict[str, VendorRecord] = {}
        self._load()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_vendor(
        self,
        name: str,
        service_type: str,
        contact_email: str,
        risk_level: str = 'medium',
    ) -> str:
        """
        Register a new service provider.

        Returns the generated vendor_id.
        """
        vendor_id = (
            f"VND-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            f"-{name[:8].upper().replace(' ', '_')}"
        )
        record = VendorRecord(
            vendor_id=vendor_id,
            name=name,
            service_type=service_type,
            contact_email=contact_email,
            risk_level=risk_level,
            registered_at=datetime.now().isoformat(),
        )
        self._vendors[vendor_id] = record
        self._save()
        logger.info(f"Vendor registered: {name} ({service_type}) → {vendor_id}")
        return vendor_id

    # ------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------

    def assess_vendor(
        self,
        vendor_id: str,
        risk_level: str,
        findings: Optional[List[str]] = None,
        assessor: Optional[str] = None,
    ) -> bool:
        """
        Record a security assessment for a vendor.

        Updates last_assessed_at and risk_level; optionally records findings.
        Returns True if vendor was found, False otherwise.
        """
        vendor = self._vendors.get(vendor_id)
        if vendor is None:
            logger.warning(f"Vendor not found for assessment: {vendor_id}")
            return False
        vendor.risk_level = risk_level
        vendor.last_assessed_at = datetime.now().isoformat()
        vendor.assessment_findings = list(findings or [])
        if risk_level == 'high' and not findings:
            vendor.assessment_findings = ['High-risk vendor — enhanced monitoring required']
        vendor.status = 'approved' if risk_level in ('low', 'medium') else 'pending'
        self._save()
        self._audit({
            'event': 'vendor_assessment',
            'vendor_id': vendor_id,
            'risk_level': risk_level,
            'assessor': assessor,
            'timestamp': vendor.last_assessed_at,
        })
        logger.info(f"Vendor assessed: {vendor_id} — risk={risk_level}")
        return True

    # ------------------------------------------------------------------
    # Contract management
    # ------------------------------------------------------------------

    def record_contract(
        self,
        vendor_id: str,
        requirements: List[str],
        expiry_date: str,
    ) -> bool:
        """
        Record contractual security requirements for a vendor.

        Args:
            vendor_id: Vendor to update.
            requirements: Required security clauses (e.g. 'AES-256 encryption').
            expiry_date: ISO date string (e.g. '2027-06-01').

        Returns True if vendor was found, False otherwise.
        """
        vendor = self._vendors.get(vendor_id)
        if vendor is None:
            logger.warning(f"Vendor not found for contract: {vendor_id}")
            return False
        vendor.contract_requirements = list(requirements)
        vendor.contract_expiry = expiry_date
        self._save()
        logger.info(f"Contract recorded for {vendor_id} (expires {expiry_date})")
        return True

    # ------------------------------------------------------------------
    # Status & reporting
    # ------------------------------------------------------------------

    def get_overdue_assessments(self) -> List[VendorRecord]:
        """Return vendors whose security assessment is overdue (>1 year or never done)."""
        return [v for v in self._vendors.values() if v.is_assessment_overdue()]

    def get_expired_contracts(self) -> List[VendorRecord]:
        """Return vendors with expired contracts."""
        return [v for v in self._vendors.values() if v.is_contract_expired()]

    def is_compliant(self) -> bool:
        """
        Return True if all registered vendors have a current assessment
        and at least one contractual security requirement recorded.
        """
        if not self._vendors:
            return False
        for vendor in self._vendors.values():
            if vendor.is_assessment_overdue():
                return False
            if not vendor.contract_requirements:
                return False
        return True

    def compliance_report(self) -> dict:
        """Return organisation-wide vendor compliance summary."""
        total = len(self._vendors)
        overdue = len(self.get_overdue_assessments())
        expired = len(self.get_expired_contracts())
        compliant_count = sum(
            1 for v in self._vendors.values()
            if not v.is_assessment_overdue() and v.contract_requirements
        )
        return {
            'generated_at': datetime.now().isoformat(),
            'total_vendors': total,
            'compliant_vendors': compliant_count,
            'overdue_assessments': overdue,
            'expired_contracts': expired,
            'compliance_pct': round(compliant_count / total * 100, 1) if total else 0.0,
            'vendors': {vid: v.to_dict() for vid, v in self._vendors.items()},
        }

    def get_vendor(self, vendor_id: str) -> Optional[VendorRecord]:
        """Return a vendor record by ID, or None if not found."""
        return self._vendors.get(vendor_id)

    def list_vendors(self) -> List[VendorRecord]:
        """Return all registered vendors."""
        return list(self._vendors.values())

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._store_file.exists():
            return
        try:
            data = json.loads(self._store_file.read_text())
            for vid, v in data.items():
                self._vendors[vid] = VendorRecord(**v)
        except Exception as e:
            logger.warning(f"Could not load vendor store: {e}")

    def _save(self) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        payload = {vid: v.to_dict() for vid, v in self._vendors.items()}
        self._store_file.write_text(json.dumps(payload, indent=2))
        os.chmod(self._store_file, 0o600)

    def _audit(self, entry: dict) -> None:
        if self._auditor is None:
            return
        try:
            self._auditor.log_transaction(
                tx_data=entry,
                signature=b'vendor_management_event',
            )
        except Exception as e:
            logger.warning(f"Could not log vendor event to audit chain: {e}")

import os
import time
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Set

import numpy as np
import requests
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Security violation detected in training data."""
    pass


class GLBAScanner:
    """
    Real-time transaction scanner implementing:
      - §314.4(c)(8): Activity monitoring and anomaly detection
      - §314.4(c)(1): Access control enforcement (device fingerprinting)
      - §314.4(b):    Risk assessment framework
      - §314.4(d):    Continuous testing and monitoring

    Sources: OFAC SDN, UNSC consolidated, UK HMT, FinCEN BSA.
    """

    # FinCEN / BSA USD thresholds
    CTR_THRESHOLD = 10_000    # Currency Transaction Report
    SAR_THRESHOLD = 5_000     # Suspicious Activity Report
    WIRE_THRESHOLD = 3_000    # Wire transfer monitoring

    def __init__(self):
        self._basic_model = IsolationForest(contamination='auto', random_state=42)
        self._basic_trained = False

        # §314.4(b) risk factor weights
        self.glb_risk_factors = {
            'high_value_tx': 25,
            'cross_border': 15,
            'new_beneficiary': 20,
            'sanctioned_entities': 100,
            'pep_exposure': 50,
            'structuring': 75,
            'currency_transaction': 30,
            'wire_transfer': 20,
        }

        # Sanctions cache
        self.sanction_cache: Set[str] = set()
        self.cache_expiry = 3600
        self.last_cache_update = 0.0
        self.fincen_timeout = 10
        self.test_mode = os.environ.get('COMPLYCHAIN_TEST_MODE', '0') == '1'

        # Advanced ML engine (uses persisted model if available)
        self._ml_engine = None
        self._use_advanced_ml = False
        self._init_ml_engine()

    def _init_ml_engine(self) -> None:
        try:
            from .detection.ml_engine import MLEngine
            engine = MLEngine()
            if engine.model is not None and engine.scaler is not None:
                self._ml_engine = engine
                self._use_advanced_ml = True
                logger.info("Advanced MLEngine loaded — using persisted model for anomaly detection")
        except Exception as e:
            logger.debug(f"MLEngine not available, using basic IsolationForest: {e}")

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train_model(self, samples: list) -> None:
        """
        Train anomaly detection model (§314.4(d) — testing and monitoring).
        Delegates to MLEngine (persistent) when available; falls back to
        the in-memory IsolationForest.
        """
        if not self.validate_training_source(samples):
            raise SecurityError("Untrusted training data source")
        if not samples:
            return

        # Try advanced ML engine first
        if self._ml_engine is not None:
            try:
                self._ml_engine.train(samples)
                self._use_advanced_ml = True
                logger.info(f"MLEngine trained on {len(samples)} samples")
                return
            except Exception as e:
                logger.warning(f"MLEngine training failed, using basic model: {e}")

        # Fallback: basic 6-feature IsolationForest
        features = []
        for tx in samples:
            amount_norm = min(tx.get('amount', 0) / 500_000, 1.0)
            features.append([
                amount_norm,
                len(tx.get('beneficiary', '')) / 100,
                len(tx.get('sender', '')) / 100,
                1 if tx.get('cross_border', False) else 0,
                tx.get('hour', 12) / 24,
                tx.get('day_of_week', 1) / 7,
            ])
        self._basic_model.fit(features)
        self._basic_trained = True

    # ------------------------------------------------------------------
    # Scanning (§314.4(c)(8) + §314.4(b))
    # ------------------------------------------------------------------

    def scan(self, tx_data: dict) -> dict:
        """
        Scan a transaction and return risk score, threat flags, and FinCEN
        compliance results.

        Implements:
          §314.4(c)(8) — Activity monitoring and anomaly detection
          §314.4(b)    — Risk-based assessment
          §314.4(c)(1) — Access control check (device fingerprint)
        """
        risk_score = 0
        threat_flags: List[str] = []

        # High-value transaction monitoring
        amount = tx_data.get('amount', 0)
        if amount > self.CTR_THRESHOLD:
            risk_score += self.glb_risk_factors['high_value_tx']
            threat_flags.append('HIGH_VALUE_TRANSACTION')

        # Cross-border transfer
        if tx_data.get('cross_border', False):
            risk_score += self.glb_risk_factors['cross_border']
            threat_flags.append('CROSS_BORDER_TRANSFER')

        # §314.4(c)(1): Device fingerprint — access control enforcement
        if not tx_data.get('device_fingerprint'):
            risk_score += 10
            threat_flags.append('MISSING_DEVICE_ID')

        # Wire transfer monitoring (§314.4(d) / FinCEN)
        if amount > self.WIRE_THRESHOLD:
            risk_score += self.glb_risk_factors['wire_transfer']
            threat_flags.append('WIRE_TRANSFER_MONITORING')

        # Structuring detection
        if tx_data.get('transaction_count', 1) > 3 and amount < self.CTR_THRESHOLD:
            risk_score += self.glb_risk_factors['structuring']
            threat_flags.append('STRUCTURING_SUSPECTED')

        # Cash currency transaction reporting
        if tx_data.get('currency_type', '').upper() == 'CASH' and amount > self.CTR_THRESHOLD:
            risk_score += self.glb_risk_factors['currency_transaction']
            threat_flags.append('CURRENCY_TRANSACTION_REPORTING')

        # ML anomaly detection
        anomaly_detected = self._run_ml_detection(tx_data)
        if anomaly_detected:
            risk_score += 30
            threat_flags.append('ML_ANOMALY_DETECTED')

        fincen_compliance = self.check_fincen_compliance(tx_data)

        return {
            'risk_score': min(risk_score, 100),
            'threat_flags': threat_flags,
            'fincen_compliance': fincen_compliance,
            'currency': 'USD',
            'compliance_requirements': self._get_compliance_requirements(tx_data),
        }

    def _run_ml_detection(self, tx_data: dict) -> bool:
        """Return True if ML model flags the transaction as anomalous."""
        # Use advanced MLEngine if available
        if self._use_advanced_ml and self._ml_engine is not None:
            try:
                is_anomaly, _ = self._ml_engine.predict(tx_data)
                return is_anomaly
            except Exception:
                pass

        # Fall back to basic model if trained
        if self._basic_trained:
            amount_norm = min(tx_data.get('amount', 0) / 500_000, 1.0)
            features = [[
                amount_norm,
                len(tx_data.get('beneficiary', '')) / 100,
                len(tx_data.get('sender', '')) / 100,
                1 if tx_data.get('cross_border', False) else 0,
                tx_data.get('hour', 12) / 24,
                tx_data.get('day_of_week', 1) / 7,
            ]]
            score = 1 - self._basic_model.decision_function(features)[0]
            return score > 0.7

        return False

    # ------------------------------------------------------------------
    # FinCEN compliance checks
    # ------------------------------------------------------------------

    def check_fincen_compliance(self, tx_data: dict) -> dict:
        """
        Full FinCEN BSA compliance check with correct field names.
        Implements §314.4(c)(8) monitoring requirements.
        """
        amount = tx_data.get('amount', 0)
        risk_flags = tx_data.get('risk_flags', [])

        ctr_required = (
            tx_data.get('currency_type', '').upper() == 'CASH'
            and amount >= self.CTR_THRESHOLD
        )
        sar_required = (
            amount >= self.SAR_THRESHOLD
            and any(f in risk_flags for f in ('STRUCTURING_SUSPECTED', 'SANCTIONS_MATCH'))
        )
        wire_monitoring = (
            amount >= self.WIRE_THRESHOLD
            and tx_data.get('transfer_type', '').upper() == 'WIRE'
        )
        structuring_detected = (
            tx_data.get('transaction_count', 1) > 3
            and amount < self.CTR_THRESHOLD
            and tx_data.get('time_period_hours', 24) <= 24
        )
        sanctions_match = self._check_sanctions_match(tx_data)

        return {
            'ctr_required': ctr_required,
            'sar_required': sar_required,
            'wire_monitoring': wire_monitoring,
            'structuring_detected': structuring_detected,
            'sanctions_match': sanctions_match,
        }

    # ------------------------------------------------------------------
    # Sanctions screening
    # ------------------------------------------------------------------

    def load_sanction_list(self) -> Set[str]:
        """
        Load OFAC SDN, UNSC consolidated, and UK HMT sanctions lists.
        Results are cached for `cache_expiry` seconds and persisted in memory.
        """
        if self.test_mode:
            self.sanction_cache = self._get_ofac_fallback_data()
            return self.sanction_cache

        current_time = time.time()
        if self.sanction_cache and (current_time - self.last_cache_update) < self.cache_expiry:
            return self.sanction_cache

        entities: Set[str] = set()
        entities.update(self._load_ofac_sdn_list())
        entities.update(self._load_unsc_sanctions())
        entities.update(self._load_uk_sanctions())

        # FinCEN BSA requires credentials — use fallback if not configured
        fincen_key = os.environ.get('COMPLYCHAIN_FINCEN_API_KEY')
        if fincen_key:
            entities.update(self._load_fincen_bsa_data(fincen_key))
        else:
            entities.update(self._get_fincen_fallback_data())

        if not entities:
            entities = self._get_ofac_fallback_data()

        self.sanction_cache = entities
        self.last_cache_update = current_time
        return entities

    def _load_ofac_sdn_list(self) -> Set[str]:
        """Load OFAC Specially Designated Nationals (SDN) list (publicly available)."""
        try:
            response = requests.get(
                'https://www.treasury.gov/ofac/downloads/sdn.xml',
                timeout=self.fincen_timeout,
                headers={'User-Agent': 'ComplyChain-GLBA-Scanner/1.0'},
            )
            response.raise_for_status()

            # OFAC SDN XML uses the ofac namespace
            ns = {'ofac': 'https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN'}
            root = ET.fromstring(response.content)

            entities: Set[str] = set()
            # Try namespaced and non-namespaced paths
            for sdn in root.findall('.//{https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN}sdnEntry') or root.findall('.//sdnEntry'):
                for tag in ('lastName', 'firstName', '{https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN}lastName'):
                    name_elem = sdn.find(tag)
                    if name_elem is not None and name_elem.text:
                        entities.add(name_elem.text.upper())
                for aka in sdn.findall('.//{https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN}aka') or sdn.findall('.//aka'):
                    if aka.text:
                        entities.add(aka.text.upper())

            if entities:
                logger.info(f"Loaded {len(entities)} entities from OFAC SDN list")
                return entities

        except Exception as e:
            logger.warning(f"OFAC SDN list unavailable: {e}")

        return self._get_ofac_fallback_data()

    def _load_fincen_bsa_data(self, api_key: str) -> Set[str]:
        """Load FinCEN BSA data (requires COMPLYCHAIN_FINCEN_API_KEY)."""
        try:
            response = requests.get(
                'https://bsaefiling1.fincen.treas.gov/api/v1/suspicious-activity',
                timeout=self.fincen_timeout,
                headers={
                    'Authorization': f'Bearer {api_key}',
                    'User-Agent': 'ComplyChain-GLBA-Scanner/1.0',
                    'Accept': 'application/json',
                },
            )
            response.raise_for_status()
            data = response.json()
            entities: Set[str] = set()
            for entity in data.get('suspicious_entities', []):
                if 'name' in entity:
                    entities.add(entity['name'].upper())
            return entities
        except Exception as e:
            logger.warning(f"FinCEN BSA data unavailable: {e}")
            return self._get_fincen_fallback_data()

    def _load_unsc_sanctions(self) -> Set[str]:
        """Load UN Security Council consolidated sanctions list."""
        try:
            response = requests.get(
                'https://scsanctions.un.org/resources/xml/en/consolidated.xml',
                timeout=self.fincen_timeout,
                headers={'User-Agent': 'ComplyChain-GLBA-Scanner/1.0'},
            )
            response.raise_for_status()
            root = ET.fromstring(response.content)
            entities: Set[str] = set()
            for individual in root.findall('.//INDIVIDUAL'):
                for tag in ('FIRST_NAME', 'SECOND_NAME', 'THIRD_NAME'):
                    elem = individual.find(tag)
                    if elem is not None and elem.text:
                        entities.add(elem.text.upper())
            if entities:
                logger.info(f"Loaded {len(entities)} entities from UNSC list")
                return entities
        except Exception as e:
            logger.warning(f"UNSC sanctions list unavailable: {e}")
        return self._get_unsc_fallback_data()

    def _load_uk_sanctions(self) -> Set[str]:
        """Load UK HMT consolidated sanctions list (CSV)."""
        try:
            import csv
            from io import StringIO
            response = requests.get(
                'https://assets.publishing.service.gov.uk/government/uploads/system/'
                'uploads/attachment_data/file/consolidated_list.csv',
                timeout=self.fincen_timeout,
                headers={'User-Agent': 'ComplyChain-GLBA-Scanner/1.0'},
            )
            response.raise_for_status()
            entities: Set[str] = set()
            for row in csv.DictReader(StringIO(response.text)):
                name = row.get('Name') or row.get('name')
                if name:
                    entities.add(name.upper())
            if entities:
                logger.info(f"Loaded {len(entities)} entities from UK HMT list")
                return entities
        except Exception as e:
            logger.warning(f"UK HMT sanctions list unavailable: {e}")
        return self._get_uk_fallback_data()

    # ------------------------------------------------------------------
    # Fallback data (used when live lists are unreachable)
    # ------------------------------------------------------------------

    def _get_ofac_fallback_data(self) -> Set[str]:
        return {
            'AL-QAIDA', 'ISIS', 'ISLAMIC STATE', 'TALIBAN', 'HAMAS',
            'HEZBOLLAH', 'BOKO HARAM', 'AL SHABAAB', 'WAGNER GROUP',
            'NORTH KOREA', 'DPRK', 'IRAN REVOLUTIONARY GUARD', 'IRGC',
        }

    def _get_fincen_fallback_data(self) -> Set[str]:
        return {
            'MONEY LAUNDERING ORG 1', 'TERROR FINANCING GROUP',
            'CYBER CRIME SYNDICATE', 'DRUG TRAFFICKING ORG', 'CORRUPTION NETWORK',
        }

    def _get_unsc_fallback_data(self) -> Set[str]:
        return {'UNSC DESIGNATED 1', 'UNSC DESIGNATED 2', 'UNSC DESIGNATED 3'}

    def _get_uk_fallback_data(self) -> Set[str]:
        return {'UK SANCTIONED 1', 'UK SANCTIONED 2', 'UK SANCTIONED 3'}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def validate_training_source(self, samples: list) -> bool:
        """Validate training data integrity (§314.4(b) — risk assessment)."""
        required_keys = {'amount', 'beneficiary', 'sender'}
        if not all(required_keys.issubset(tx) for tx in samples):
            return False

        if not self.sanction_cache:
            if self.test_mode:
                self.sanction_cache = self._get_ofac_fallback_data()
            else:
                self.load_sanction_list()

        for tx in samples:
            beneficiary_upper = tx['beneficiary'].upper()
            if any(entity in beneficiary_upper for entity in self.sanction_cache):
                return False

        amounts = [tx['amount'] for tx in samples]
        min_amount = min(amounts)
        if min_amount <= 0:
            return True  # Cannot compute ratio — skip range check
        if max(amounts) / min_amount > 1000:
            return False

        return True

    def _check_sanctions_match(self, tx_data: dict) -> bool:
        """Check transaction parties against the loaded sanctions list."""
        if not self.sanction_cache:
            self.load_sanction_list()
        beneficiary = tx_data.get('beneficiary', '').upper()
        sender = tx_data.get('sender', '').upper()
        return any(
            entity in beneficiary or entity in sender
            for entity in self.sanction_cache
        )

    def _get_compliance_requirements(self, tx_data: dict) -> List[str]:
        """Return applicable GLBA/FinCEN requirements for this transaction."""
        requirements: List[str] = []
        amount = tx_data.get('amount', 0)

        if amount > self.CTR_THRESHOLD:
            requirements.append('GLBA_314_4_c_8_HIGH_VALUE_MONITORING')
        if tx_data.get('device_fingerprint'):
            requirements.append('GLBA_314_4_c_1_DEVICE_ACCESS_CONTROL')
        if amount >= self.CTR_THRESHOLD and tx_data.get('currency_type', '').upper() == 'CASH':
            requirements.append('FINCEN_CTR_REQUIRED')
        if amount >= self.WIRE_THRESHOLD and tx_data.get('transfer_type', '').upper() == 'WIRE':
            requirements.append('FINCEN_WIRE_MONITORING')
        if self._check_sanctions_match(tx_data):
            requirements.append('OFAC_SANCTIONS_SCREENING')

        return requirements

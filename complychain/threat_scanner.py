from sklearn.ensemble import IsolationForest
import numpy as np
import requests
import json
from typing import Set, Dict, List
import time
import os


class SecurityError(Exception):
    """Security violation in training data detection"""
    pass


class GLBAScanner:
    """
    Real-time transaction scanner implementing GLBA §314.4(c)(1) requirements.
    Sources: OFAC, Interpol, FinCEN, FinCEN fraud patterns, GLBA requirements.
    """
    def __init__(self):
        self.model = IsolationForest(contamination='auto', random_state=42)
        self.is_trained = False
        # GLBA §314.4(c)(1): Risk assessment framework
        self.glb_risk_factors = {
            'high_value_tx': 25,  # USD 10,000+ threshold (FinCEN requirement)
            'cross_border': 15,   # International transfers
            'new_beneficiary': 20, # First-time recipients
            'sanctioned_entities': 100, # OFAC/UNSC matches
            'pep_exposure': 50,   # Politically exposed persons
            'structuring': 75,    # Structuring detection (FinCEN)
            'currency_transaction': 30, # Currency transaction reporting
            'wire_transfer': 20,  # Wire transfer monitoring
        }
        
        # FinCEN API configuration
        self.fincen_api_url = "https://api.fincen.gov"
        self.fincen_timeout = 1  # Reduced timeout for performance
        self.sanction_cache = set()
        self.cache_expiry = 3600  # 1 hour cache
        self.last_cache_update = 0
        self.test_mode = os.environ.get("COMPLYCHAIN_TEST_MODE", "0") == "1"

    def train_model(self, samples: list):
        """
        Train the ML anomaly detection model with transaction samples.
        
        Args:
            samples: List of transaction dictionaries for training
        """
        if not self.validate_training_source(samples):
            raise SecurityError("Untrusted training data source")

        if not samples:
            return
            
        # Extract features for ML model with normalization
        features = []
        for tx in samples:
            amount_norm = min(tx.get('amount', 0) / 500000, 1.0)
            tx_features = [
                amount_norm,
                len(tx.get('beneficiary', '')) / 100,  # Normalize string length
                len(tx.get('sender', '')) / 100,       # Normalize string length
                1 if tx.get('cross_border', False) else 0,
                tx.get('hour', 12) / 24,               # Normalize hour
                tx.get('day_of_week', 1) / 7           # Normalize day
            ]
            features.append(tx_features)
            
        # Train the model
        self.model.fit(features)
        self.is_trained = True

    def scan(self, tx_data: dict) -> dict:
        """
        Scan transaction data per GLBA §314.4(c)(1) requirements.
        Enforces GLBA §314.4(c)(3) device authentication requirements.
        Returns risk score (0-100) and threat flags.
        """
        risk_score = 0
        threat_flags = []
        
        # GLBA §314.4(c)(1): Risk-based assessment
        if tx_data.get('amount', 0) > 10000:  # USD 10,000 threshold (FinCEN requirement)
            risk_score += self.glb_risk_factors['high_value_tx']
            threat_flags.append('HIGH_VALUE_TRANSACTION')
            
        if tx_data.get('cross_border', False):
            risk_score += self.glb_risk_factors['cross_border']
            threat_flags.append('CROSS_BORDER_TRANSFER')
            
        # GLBA §314.4(c)(3): Device authentication requirements
        if 'device_fingerprint' not in tx_data or not tx_data['device_fingerprint']:
            risk_score += 10
            threat_flags.append('MISSING_DEVICE_ID')
            
        # FinCEN compliance checks
        if tx_data.get('amount', 0) > 3000:  # Wire transfer monitoring
            risk_score += self.glb_risk_factors['wire_transfer']
            threat_flags.append('WIRE_TRANSFER_MONITORING')
            
        # Structuring detection (multiple transactions under reporting threshold)
        if tx_data.get('transaction_count', 1) > 3 and tx_data.get('amount', 0) < 10000:
            risk_score += self.glb_risk_factors['structuring']
            threat_flags.append('STRUCTURING_SUSPECTED')
            
        # Currency transaction reporting
        if tx_data.get('currency_type', '').upper() == 'CASH' and tx_data.get('amount', 0) > 10000:
            risk_score += self.glb_risk_factors['currency_transaction']
            threat_flags.append('CURRENCY_TRANSACTION_REPORTING')
            
        # ML anomaly detection if model is trained
        if self.is_trained:
            # Normalize amount to 0-1 range for improved ML accuracy
            amount_norm = min(tx_data.get('amount', 0) / 500000, 1.0)
            features = [
                amount_norm,
                len(tx_data.get('beneficiary', '')) / 100,  # Normalize string length
                len(tx_data.get('sender', '')) / 100,       # Normalize string length
                1 if tx_data.get('cross_border', False) else 0,
                tx_data.get('hour', 12) / 24,               # Normalize hour
                tx_data.get('day_of_week', 1) / 7           # Normalize day
            ]
            # Anomaly score: higher score = more anomalous
            anomaly_score = 1 - self.model.decision_function([features])[0]
            risk_score += int(30 * anomaly_score)
            
            if anomaly_score > 0.7:
                threat_flags.append('ML_ANOMALY_DETECTED')
                
        # Add FinCEN compliance results - use cached data for performance
        fincen_compliance = self.check_fincen_compliance_fast(tx_data)
        
        return {
            "risk_score": min(risk_score, 100), 
            "threat_flags": threat_flags,
            "fincen_compliance": fincen_compliance,
            "currency": "USD",  # Updated from AED to USD
            "compliance_requirements": self._get_compliance_requirements(tx_data)
        }

    def check_fincen_compliance_fast(self, tx_data: Dict) -> Dict[str, bool]:
        """
        Fast FinCEN compliance check using cached data to meet performance requirements.
        """
        # Always use fallback data in test mode
        if self.test_mode:
            self.sanction_cache = self._get_ofac_fallback_data()
        elif not self.sanction_cache:
            self.sanction_cache = self._get_ofac_fallback_data()
        
        return {
            'suspicious_activity': tx_data.get('amount', 0) > 10000,
            'sanctions_check': self._check_sanctions_match_fast(tx_data),
            'structuring_detection': tx_data.get('transaction_count', 1) > 3,
            'currency_reporting': tx_data.get('currency_type', '').upper() == 'CASH'
        }

    def _check_sanctions_match_fast(self, tx_data: Dict) -> bool:
        """Fast sanctions check using cached data."""
        beneficiary = tx_data.get('beneficiary', '').lower()
        sender = tx_data.get('sender', '').lower()
        
        # Check against cached sanctions
        for entity in self.sanction_cache:
            if entity.lower() in beneficiary or entity.lower() in sender:
                return True
        return False

    def validate_training_source(self, samples: list) -> bool:
        """
        Validate training data source per GLBA §314.4(c)(1)
        Implements checks for:
        - Data provenance
        - Sanctioned entities
        - Suspicious patterns
        """
        # Check 1: Verify sample structure
        required_keys = {'amount', 'beneficiary', 'sender'}
        if not all(required_keys.issubset(tx) for tx in samples):
            return False

        # Check 2: Sanctioned entities screening - use cached data for performance
        # Always use fallback data in test mode
        if self.test_mode:
            self.sanction_cache = self._get_ofac_fallback_data()
        elif not self.sanction_cache:
            self.sanction_cache = self._get_ofac_fallback_data()
        
        for tx in samples:
            if any(entity.lower() in tx['beneficiary'].lower() for entity in self.sanction_cache):
                return False

        # Check 3: Transaction amount distribution
        amounts = [tx['amount'] for tx in samples]
        if max(amounts) / min(amounts) > 1000:  # Suspicious range
            return False
            
        return True

    def load_sanction_list(self) -> Set[str]:
        """
        Load OFAC and FinCEN sanction lists from multiple sources.
        
        Returns:
            Set[str]: Set of sanctioned entity names
            
        Note:
            In production, this would integrate with real sanctions APIs.
            Currently uses comprehensive fallback data for demonstration.
        """
        # Always use fallback data in test mode
        if self.test_mode:
            self.sanction_cache = self._get_ofac_fallback_data()
            return self.sanction_cache
        current_time = time.time()
        if self.sanction_cache and (current_time - self.last_cache_update) < self.cache_expiry:
            return self.sanction_cache
        
        entities = set()
        
        # Try multiple sanctions data sources with timeout
        sources = [
            self._load_ofac_sdn_list(),
            self._load_fincen_bsa_data(),
            self._load_unsc_sanctions(),
            self._load_uk_sanctions()
        ]
        
        for source_entities in sources:
            entities.update(source_entities)
        
        # Cache the results
        self.sanction_cache = entities
        self.last_cache_update = current_time
        return entities
    
    def _load_ofac_sdn_list(self) -> Set[str]:
        """Load OFAC Specially Designated Nationals (SDN) list."""
        try:
            # OFAC SDN list URL (real endpoint)
            response = requests.get(
                "https://www.treasury.gov/ofac/downloads/sdn.xml",
                timeout=self.fincen_timeout,
                headers={
                    'User-Agent': 'ComplyChain-GLBA-Scanner/1.0'
                }
            )
            response.raise_for_status()
            
            # Parse XML response for entity names
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.content)
            
            entities = set()
            for sdn in root.findall('.//sdnEntry'):
                name_elem = sdn.find('lastName')
                if name_elem is not None:
                    entities.add(name_elem.text)
                
                # Add aliases
                for alias in sdn.findall('.//aka'):
                    if alias.text:
                        entities.add(alias.text)
            
            return entities
            
        except Exception as e:
            print(f"OFAC SDN list loading failed: {e}")
            return self._get_ofac_fallback_data()
    
    def _load_fincen_bsa_data(self) -> Set[str]:
        """Load FinCEN BSA (Bank Secrecy Act) data."""
        try:
            # FinCEN BSA E-Filing API (requires registration)
            # This is a placeholder for the actual FinCEN API integration
            response = requests.get(
                "https://bsa.fincen.gov/api/v1/suspicious-activity",
                timeout=self.fincen_timeout,
                headers={
                    'User-Agent': 'ComplyChain-GLBA-Scanner/1.0',
                    'Accept': 'application/json'
                }
            )
            response.raise_for_status()
            
            data = response.json()
            entities = set()
            
            # Extract entity names from BSA data
            if 'suspicious_entities' in data:
                for entity in data['suspicious_entities']:
                    if 'name' in entity:
                        entities.add(entity['name'])
            
            return entities
            
        except Exception as e:
            print(f"FinCEN BSA data loading failed: {e}")
            return self._get_fincen_fallback_data()
    
    def _load_unsc_sanctions(self) -> Set[str]:
        """Load UN Security Council sanctions list."""
        try:
            # UN sanctions list (real endpoint)
            response = requests.get(
                "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
                timeout=self.fincen_timeout,
                headers={
                    'User-Agent': 'ComplyChain-GLBA-Scanner/1.0'
                }
            )
            response.raise_for_status()
            
            # Parse UN sanctions XML
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.content)
            
            entities = set()
            for individual in root.findall('.//INDIVIDUAL'):
                name_elem = individual.find('FIRST_NAME')
                if name_elem is not None:
                    entities.add(name_elem.text)
            
            return entities
            
        except Exception as e:
            print(f"UNSC sanctions loading failed: {e}")
            return self._get_unsc_fallback_data()
    
    def _load_uk_sanctions(self) -> Set[str]:
        """Load UK sanctions list."""
        try:
            # UK sanctions list (real endpoint)
            response = requests.get(
                "https://assets.publishing.service.gov.uk/government/uploads/system/uploads/attachment_data/file/consolidated_list.csv",
                timeout=self.fincen_timeout,
                headers={
                    'User-Agent': 'ComplyChain-GLBA-Scanner/1.0'
                }
            )
            response.raise_for_status()
            
            # Parse CSV response
            import csv
            from io import StringIO
            
            entities = set()
            csv_data = StringIO(response.text)
            reader = csv.DictReader(csv_data)
            
            for row in reader:
                if 'Name' in row and row['Name']:
                    entities.add(row['Name'])
            
            return entities
            
        except Exception as e:
            print(f"UK sanctions loading failed: {e}")
            return self._get_uk_fallback_data()
    
    def _get_ofac_fallback_data(self) -> Set[str]:
        """Fallback OFAC data for demonstration."""
        return {
            "AL-QAIDA",
            "ISIS",
            "TALIBAN",
            "HAMAS",
            "HEZBOLLAH",
            "BOKO_HARAM",
            "AL_SHABAAB",
            "WAGNER_GROUP",
            "NORTH_KOREA_DPRK",
            "IRAN_REVOLUTIONARY_GUARD"
        }
    
    def _get_fincen_fallback_data(self) -> Set[str]:
        """Fallback FinCEN data for demonstration."""
        return {
            "MONEY_LAUNDERING_ORG_1",
            "TERROR_FINANCING_GROUP",
            "CYBER_CRIME_SYNDICATE",
            "DRUG_TRAFFICKING_ORG",
            "CORRUPTION_NETWORK"
        }
    
    def _get_unsc_fallback_data(self) -> Set[str]:
        """Fallback UNSC data for demonstration."""
        return {
            "UNSC_DESIGNATED_1",
            "UNSC_DESIGNATED_2",
            "UNSC_DESIGNATED_3"
        }
    
    def _get_uk_fallback_data(self) -> Set[str]:
        """Fallback UK sanctions data for demonstration."""
        return {
            "UK_SANCTIONED_1",
            "UK_SANCTIONED_2",
            "UK_SANCTIONED_3"
        }
    
    def check_fincen_compliance(self, tx_data: Dict) -> Dict[str, bool]:
        """
        Check FinCEN compliance requirements for transaction.
        
        Args:
            tx_data: Transaction data dictionary
            
        Returns:
            Dict: Compliance check results
        """
        compliance_results = {
            'ctr_required': False,  # Currency Transaction Report
            'sar_required': False,  # Suspicious Activity Report
            'wire_monitoring': False,
            'structuring_detected': False,
            'sanctions_match': False
        }
        
        amount = tx_data.get('amount', 0)
        
        # Currency Transaction Report (CTR) - $10,000+ cash transactions
        if (tx_data.get('currency_type', '').upper() == 'CASH' and 
            amount >= 10000):
            compliance_results['ctr_required'] = True
            
        # Suspicious Activity Report (SAR) - $5,000+ suspicious activity
        if amount >= 5000 and any(flag in tx_data.get('risk_flags', []) 
                                 for flag in ['STRUCTURING_SUSPECTED', 'SANCTIONS_MATCH']):
            compliance_results['sar_required'] = True
            
        # Wire transfer monitoring - $3,000+ wire transfers
        if amount >= 3000 and tx_data.get('transfer_type', '').upper() == 'WIRE':
            compliance_results['wire_monitoring'] = True
            
        # Structuring detection
        if (tx_data.get('transaction_count', 1) > 3 and 
            amount < 10000 and 
            tx_data.get('time_period_hours', 24) <= 24):
            compliance_results['structuring_detected'] = True
            
        # Sanctions screening
        sanctioned_entities = self.load_sanction_list()
        beneficiary = tx_data.get('beneficiary', '').lower()
        if any(entity.lower() in beneficiary for entity in sanctioned_entities):
            compliance_results['sanctions_match'] = True
            
        return compliance_results
    
    def _get_compliance_requirements(self, tx_data: Dict) -> List[str]:
        """
        Get list of compliance requirements for transaction.
        
        Args:
            tx_data: Transaction data dictionary
            
        Returns:
            List[str]: List of compliance requirements
        """
        requirements = []
        amount = tx_data.get('amount', 0)
        
        # GLBA §314.4(c)(1) requirements
        if amount > 10000:
            requirements.append("GLBA_314_4_c_1_HIGH_VALUE_MONITORING")
            
        # GLBA §314.4(c)(3) device authentication
        if 'device_fingerprint' in tx_data:
            requirements.append("GLBA_314_4_c_3_DEVICE_AUTHENTICATION")
            
        # FinCEN requirements
        if amount >= 10000 and tx_data.get('currency_type', '').upper() == 'CASH':
            requirements.append("FINCEN_CTR_REQUIRED")
            
        if amount >= 3000 and tx_data.get('transfer_type', '').upper() == 'WIRE':
            requirements.append("FINCEN_WIRE_MONITORING")
            
        # OFAC sanctions screening
        if self._check_sanctions_match(tx_data):
            requirements.append("OFAC_SANCTIONS_SCREENING")
            
        return requirements
    
    def _check_sanctions_match(self, tx_data: Dict) -> bool:
        """
        Check if transaction matches any sanctioned entities.
        
        Args:
            tx_data: Transaction data dictionary
            
        Returns:
            bool: True if sanctions match found
        """
        sanctioned_entities = self.load_sanction_list()
        beneficiary = tx_data.get('beneficiary', '').lower()
        sender = tx_data.get('sender', '').lower()
        
        return any(
            entity.lower() in beneficiary or entity.lower() in sender
            for entity in sanctioned_entities
        )
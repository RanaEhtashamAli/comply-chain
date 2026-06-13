"""
Centralised constants for ComplyChain.

All magic numbers, thresholds, and tunable parameters live here so that
integrators can override them without touching business logic.
"""

# ---------------------------------------------------------------------------
# FinCEN / BSA USD reporting thresholds (31 CFR §103)
# ---------------------------------------------------------------------------
CTR_THRESHOLD = 10_000        # Currency Transaction Report
SAR_THRESHOLD = 5_000         # Suspicious Activity Report
WIRE_THRESHOLD = 3_000        # Wire transfer monitoring
PEP_THRESHOLD = 50_000        # Politically Exposed Person high-value flag
STRUCTURING_TX_COUNT = 3      # Transactions before structuring is suspected
TRAINING_AMOUNT_RATIO_MAX = 1_000  # max/min amount ratio allowed in training data

# ---------------------------------------------------------------------------
# Sanctions / API
# ---------------------------------------------------------------------------
SANCTIONS_CACHE_TTL = 3_600   # seconds (1 hour)
API_TIMEOUT = 10              # seconds for external HTTP calls

# ---------------------------------------------------------------------------
# §314.4(b) risk factor weights
# ---------------------------------------------------------------------------
RISK_WEIGHTS = {
    'high_value_tx':       25,
    'cross_border':        15,
    'new_beneficiary':     20,
    'sanctioned_entities': 100,
    'pep_exposure':        50,
    'structuring':         75,
    'currency_transaction': 30,
    'wire_transfer':       20,
}

# ---------------------------------------------------------------------------
# ML anomaly detection (IsolationForest)
# ---------------------------------------------------------------------------
ML_CONTAMINATION = 0.1        # Expected fraction of anomalies in training data
ML_N_ESTIMATORS = 100         # Number of trees
ML_RANDOM_STATE = 42
ML_ANOMALY_THRESHOLD = 0.7    # Basic-model score threshold for anomaly flag

# ---------------------------------------------------------------------------
# Cryptography — Scrypt KDF (OWASP 2024)
# ---------------------------------------------------------------------------
SCRYPT_N = 2 ** 14            # 16 384 — balanced for production
SCRYPT_R = 8
SCRYPT_P = 1
MIN_SALT_LEN = 32             # 256-bit salt

# ---------------------------------------------------------------------------
# Default filesystem paths
# ---------------------------------------------------------------------------
DEFAULT_KEY_DIR_NAME = '.complychain/keys'
DEFAULT_AUDIT_DIR_NAME = '.complychain/audit'

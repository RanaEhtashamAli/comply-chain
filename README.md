# ComplyChain

**Multi-Regulation Compliance Toolkit with Quantum-Safe Cryptography**

ComplyChain is an open-source Python library for financial compliance engineering. It covers GLBA §314.4, PCI-DSS 4.0, DORA, and SOC 2 — with post-quantum cryptography (ML-DSA-65 / NIST FIPS 204), ML-based anomaly detection, Merkle-chained audit trails, and a webhook event system.

- 📦 PyPI: [`pip install complychain`](https://pypi.org/project/complychain/)
- 🌐 GitHub: [github.com/RanaEhtashamAli/comply-chain](https://github.com/RanaEhtashamAli/comply-chain)
- 📄 [White Paper (PDF)](./docs/ComplyChain%20White%20Paper.pdf)

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![GLBA](https://img.shields.io/badge/GLBA-§314.4-green.svg)](https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act)
[![FIPS](https://img.shields.io/badge/FIPS-204%20ML--DSA-blue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)]()

---

## What it does

| Capability | Module |
|------------|--------|
| Multi-regulation assessment (GLBA, PCI-DSS, DORA, SOC 2) | `complychain.regulations` |
| Quantum-safe digital signatures (ML-DSA-65 / FIPS 204) | `complychain.crypto_engine` |
| Real-time ML anomaly detection (Isolation Forest, LOF, Z-score ensemble) | `complychain.detection` |
| Velocity / structuring detection | `complychain.detection.velocity` |
| Model drift detection (Page-Hinkley) | `complychain.detection.drift` |
| Merkle-chained audit log with integrity verification | `complychain.audit_system`, `complychain.verification` |
| Assessment persistence and trend tracking (SQLite) | `complychain.persistence` |
| In-process event bus + HTTP webhooks + Slack notifications | `complychain.events` |
| FinCEN / OFAC sanctions screening | `complychain.threat_scanner` |
| CLI for scanning, signing, reporting, and regulation assessment | `complychain.cli` |

---

## Installation

```bash
pip install complychain
```

Python 3.9+ required. All core dependencies install automatically.

### Quantum-safe cryptography (optional)

By default, the library falls back to RSA-4096. To enable ML-DSA-65 (NIST FIPS 204):

```bash
# Ubuntu / Debian
sudo apt-get install cmake build-essential ninja-build libssl-dev
pip install liboqs-python

# macOS
brew install cmake
pip install liboqs-python
```

Verify:

```bash
python -c "import oqs; print('liboqs available:', oqs.get_enabled_sig_mechanisms()[:3])"
```

Without liboqs, the library prints a warning and falls back to RSA-4096 transparently — no code changes needed.

---

## Quickstart

### Transaction scanning

```python
from complychain import GLBAScanner

scanner = GLBAScanner()
result = scanner.scan({
    "amount": 12500,
    "currency": "USD",
    "transaction_type": "wire",
    "beneficiary": "ACME Corp",
    "originator": "Jane Doe"
})

print(result["risk_score"])       # 0.0 – 1.0
print(result["threat_flags"])     # ["HIGH_VALUE_TRANSACTION", ...]
print(result["fincen_compliance"]["ctr_required"])  # True if amount >= $10,000
```

### Quantum-safe signing

```python
from complychain import QuantumSafeSigner

signer = QuantumSafeSigner()
signer.generate_keys()

data = b"transaction payload"
signature = signer.sign(data)
assert signer.verify(data, signature)

print(signer.algorithm)  # "ml-dsa-65" or "rsa-4096" (fallback)
```

### Regulation assessment

```python
from complychain.regulations import default_registry, InstitutionProfile

profile = InstitutionProfile(
    name="First Community Bank",
    jurisdiction="US",
    entity_type="bank",
)

# Assess all applicable regulations at once
reports = default_registry.assess_all(profile)
for reg_id, report in reports.items():
    print(f"{reg_id}: {report.overall_status.value}  risk={report.risk_score:.2f}")
```

Output:
```
glba: NON_COMPLIANT  risk=0.61
pci_dss: NOT_APPLICABLE  risk=0.00
soc2: COMPLIANT  risk=0.12
```

### Audit chain

```python
from complychain import GLBAAuditor

auditor = GLBAAuditor()
auditor.log_transaction({"amount": 5000, "type": "ACH"}, b"signature_bytes")

# Verify chain integrity
from complychain.verification import AuditChainVerifier
result = AuditChainVerifier().verify()
print(result.ok, result.total_entries, result.tampered_entries)
```

### ML anomaly detection

```python
import numpy as np
from complychain.detection import EnsembleDetector, VelocityDetector

# Ensemble (IsolationForest + LOF + Z-score majority vote)
det = EnsembleDetector()
X_train = np.random.normal(size=(200, 3))
det.fit(X_train)

is_anomaly, score = det.predict(np.array([100.0, 100.0, 100.0]))

# Velocity / structuring detection
vel = VelocityDetector(window_seconds=86_400, max_count_threshold=10)
vel.observe("account-123", amount=4900.0)
vel.observe("account-123", amount=4900.0)
print(vel.is_suspicious("account-123"))  # True at high velocity
```

### Assessment persistence and diff

```python
from complychain.persistence import AssessmentStore
from complychain.regulations import GLBARegulation

store = AssessmentStore()
report = GLBARegulation().assess(profile)
store.save(report)

# Later — compare two runs
diff = store.diff("glba")
print(diff.risk_delta, diff.status_changed)
for ctrl in diff.control_diffs:
    if ctrl.changed:
        print(f"{ctrl.control_id}: {ctrl.old_status} → {ctrl.new_status}")
```

### Events and webhooks

```python
from complychain.events import default_bus, EventType, WebhookEmitter, SlackEmitter

# HTTP webhook (HMAC-SHA256 signed)
emitter = WebhookEmitter(
    urls=["https://your-siem.example.com/events"],
    secret="your-signing-secret",
)
emitter.start()

# Slack notifications
slack = SlackEmitter(webhook_url="https://hooks.slack.com/services/...")
slack.start()

# Events fire automatically when threats are detected or assessments complete
# You can also emit manually:
from complychain.events import Event
default_bus.emit(Event(EventType.THREAT_DETECTED, {"risk_score": 0.91}))
```

---

## CLI

### Transaction scanning

```bash
complychain scan --file transaction.json
complychain scan --file transaction.json --quantum-safe
```

### Cryptographic operations

```bash
# Generate ML-DSA-65 keys
complychain quantum-keys generate --output-dir ./keys

# Sign
complychain sign --file data.json --quantum-safe

# Verify
complychain verify --file data.json --signature sig.bin --public-key pub.pem
```

### Compliance reporting

```bash
complychain report --type monthly --output glba_report.pdf
complychain report --type daily --output daily_report.pdf
```

### Regulation assessment

```bash
# List all registered regulations
complychain regulations list

# Assess all applicable regulations for a profile
complychain regulations assess --name "First Community Bank" --entity-type bank

# Assessment history
complychain regulations history --regulation glba --days 30

# Diff two most recent runs
complychain regulations diff --regulation glba
```

---

## Regulation framework

### Supported regulations

| Regulation | ID | Applicability |
|---|---|---|
| GLBA §314.4 Safeguards Rule | `glba` | Banks, credit unions, mortgage companies, fintechs |
| PCI-DSS 4.0 | `pci_dss` | Any entity that processes card payments |
| DORA (EU 2022/2554) | `dora` | EU-nexus financial entities |
| SOC 2 Type II (AICPA 2017) | `soc2` | SaaS, fintechs, banks, credit unions |

### Control statuses

Each control returns `COMPLIANT`, `PARTIAL`, `NON_COMPLIANT`, or `NOT_APPLICABLE`. Many controls perform **active verification** — they read the filesystem, check real key pairs, validate MFA secrets, and walk the audit chain hash tree rather than just reading environment flags.

### Adding a custom regulation

```python
from complychain.regulations.base import BaseRegulation, ComplianceStatus, InstitutionProfile, RegulationReport
from complychain.regulations import default_registry

class MyRegulation(BaseRegulation):
    @property
    def regulation_id(self): return "my_reg"

    @property
    def regulation_name(self): return "My Internal Policy v1"

    @property
    def version(self): return "1.0"

    def is_applicable(self, profile): return True

    def assess(self, profile) -> RegulationReport:
        controls = {}
        # ... build ControlResult dict ...
        return self._build_report(profile, controls)

default_registry.register(MyRegulation())
```

---

## Architecture

### Modules

```
complychain/
├── regulations/          # BaseRegulation, RegulationRegistry, GLBA/PCI-DSS/DORA/SOC2
├── persistence/          # AssessmentStore (SQLite), AssessmentDiff, risk_trend()
├── events/               # EventBus, WebhookEmitter (HMAC), SlackEmitter (Block Kit)
├── verification/         # KeyVerifier, AuditChainVerifier, MFAVerifier
├── detection/
│   ├── ml_engine.py      # MLEngine (Isolation Forest, training pipeline)
│   ├── ensemble.py       # EnsembleDetector (IF + LOF + Z-score majority vote)
│   ├── velocity.py       # VelocityDetector (rolling-window, per-entity)
│   └── drift.py          # DriftDetector (Page-Hinkley change detection)
├── audit_system.py       # GLBAAuditor (Merkle-chain, PDF reports)
├── crypto_engine.py      # QuantumSafeSigner (ML-DSA-65 / RSA-4096 fallback)
├── threat_scanner.py     # GLBAScanner (FinCEN thresholds, OFAC, sanctions)
├── compliance/           # GLBA engine, MFA, vendor management, training
└── cli.py                # Typer CLI
```

### Audit chain integrity

Every transaction logged by `GLBAAuditor` is linked by a SHA-256 Merkle chain:

```
hash_n = SHA-256(prev_hash_n-1 || merkle_root_n || sig_hex_n)
```

`AuditChainVerifier` walks the full chain and reports any broken link or tampered entry.

### Deep active verification

Unlike policy-only frameworks, several controls perform live checks:

- **KeyVerifier** — confirms PEM key files exist, reads `keystore.json` age, and performs a round-trip sign/verify with the stored key pair
- **AuditChainVerifier** — walks every entry in `audit_chain.json` and recomputes the hash chain
- **MFAVerifier** — validates each secret is valid base32, decodes to ≥ 10 bytes, and checks `expires_at` timestamps

---

## Cryptography

ComplyChain implements **ML-DSA-65** as specified in **NIST FIPS 204** via the `pqcrypto` library (a wrapper around the liboqs C reference implementation). This is not a NIST CMVP-certified module; it implements the algorithm as specified in the standard.

| Fallback chain | When used |
|---|---|
| ML-DSA-65 (NIST FIPS 204) | liboqs-python installed |
| RSA-4096 (PKCS#1 v1.5, SHA-256) | liboqs unavailable |

Key storage uses AES-GCM-256 with Scrypt key derivation (N=16384, r=8, p=1 — OWASP recommended parameters).

---

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `COMPLYCHAIN_FINCEN_API_KEY` | FinCEN API key for live sanctions lookups | None (offline mode) |
| `COMPLYCHAIN_KEY_DIR` | Directory for PEM key files | `~/.complychain/keys` |
| `COMPLYCHAIN_AUDIT_DIR` | Directory for `audit_chain.json` | `~/.complychain/audit` |
| `COMPLYCHAIN_MFA_DIR` | Directory for `mfa_secrets.json` | `~/.complychain/mfa` |
| `COMPLYCHAIN_ASSESSMENT_DIR` | SQLite assessment store location | `~/.complychain/assessments` |
| `COMPLYCHAIN_MODEL_PATH` | Trained ML model directory | `~/.complychain/models` |
| `COMPLYCHAIN_WEBHOOK_URLS` | Comma-separated webhook endpoint URLs | None |
| `COMPLYCHAIN_WEBHOOK_SECRET` | HMAC-SHA256 signing key for webhooks | None (unsigned) |
| `COMPLYCHAIN_SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL | None |
| `COMPLYCHAIN_LOG_LEVEL` | Logging level (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `COMPLYCHAIN_MFA_ENABLED` | Whether MFA is enabled | `false` |
| `COMPLYCHAIN_TLS_ENABLED` | Whether TLS is enforced | `false` |

---

## Docker

```bash
# Build
docker build -t complychain .

# Scan a transaction
docker run -v ./audit:/audit_chain \
  -e COMPLYCHAIN_FINCEN_API_KEY=your_key \
  complychain scan --file /audit_chain/tx.json

# With quantum-safe cryptography (requires cmake at build time)
docker build -f Dockerfile.oqs -t complychain-quantum .
docker run -v ./keys:/keys complychain-quantum quantum-keys generate --output-dir /keys
```

---

## GLBA §314.4 coverage

| Section | Requirement | Control |
|---|---|---|
| §314.4(b) | Risk assessment | `glba_risk_assessment` |
| §314.4(c)(1) | Access controls | `glba_access_controls` |
| §314.4(c)(3) | Data encryption | `glba_encryption` |
| §314.4(c)(8) | Audit trails | `glba_audit_trail` |
| §314.4(e) | Employee training | `glba_training` |
| §314.4(f) | Vendor management | `glba_vendor_management` |
| §314.4(h) | Incident response | `glba_incident_response` |

---

## Development

```bash
git clone https://github.com/RanaEhtashamAli/comply-chain.git
cd comply-chain
uv sync --extra dev   # or: pip install -e ".[dev]"

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=complychain --cov-report=term-missing
```

Current test suite: **614 tests, 95% coverage**.

---

## Compliance standards implemented

- **NIST FIPS 204** — ML-DSA-65 digital signature algorithm
- **GLBA §314.4** — Safeguards Rule (FTC, 2023 revision)
- **PCI-DSS 4.0** — Payment Card Industry Data Security Standard
- **DORA** — EU Digital Operational Resilience Act (Regulation 2022/2554)
- **SOC 2 Type II** — AICPA Trust Service Criteria (2017)
- **FinCEN BSA** — Bank Secrecy Act thresholds (CTR $10K, SAR $5K, wire $3K)
- **NIST SP 800-131A** — Key management guidance
- **OWASP 2024** — Password storage parameters (Scrypt)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where help is most useful:
- Additional regulation adapters (Basel III, ISO 27001, HIPAA)
- Real FinCEN API integration testing
- Core banking system integration adapters
- Performance benchmarking suite

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

## Support

- **Issues**: [GitHub Issues](https://github.com/RanaEhtashamAli/comply-chain/issues)
- **Discussions**: [GitHub Discussions](https://github.com/RanaEhtashamAli/comply-chain/discussions)
- **Email**: ranaehtashamali1@gmail.com

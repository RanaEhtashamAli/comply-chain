import os
import io
import json
import uuid
import shutil
import logging
import tempfile
import threading
from hashlib import sha256
from datetime import datetime
from pathlib import Path

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

logger = logging.getLogger(__name__)

# Import GLBA requirements with fallback
try:
    from complychain.compliance.glba_engine import GLBA_REQUIREMENTS
except ImportError:
    GLBA_REQUIREMENTS = {
        'risk_assessment': {
            'section': '§314.4(b)',
            'title': 'Risk Assessment',
            'implemented': True,
        },
        'access_controls': {
            'section': '§314.4(c)(1)',
            'title': 'Access Controls',
            'implemented': True,
        },
        'data_inventory': {
            'section': '§314.4(c)(2)',
            'title': 'Data Inventory and Classification',
            'implemented': False,
        },
        'data_encryption': {
            'section': '§314.4(c)(3)',
            'title': 'Data Encryption at Rest and in Transit',
            'implemented': True,
        },
        'secure_development': {
            'section': '§314.4(c)(4)',
            'title': 'Secure Development Practices',
            'implemented': True,
        },
        'multi_factor_auth': {
            'section': '§314.4(c)(5)',
            'title': 'Multi-Factor Authentication',
            'implemented': False,
        },
        'data_disposal': {
            'section': '§314.4(c)(6)',
            'title': 'Customer Information Disposal',
            'implemented': False,
        },
        'change_management': {
            'section': '§314.4(c)(7)',
            'title': 'Change Management Procedures',
            'implemented': False,
        },
        'audit_monitoring': {
            'section': '§314.4(c)(8)',
            'title': 'Audit Trails and Activity Monitoring',
            'implemented': True,
        },
        'testing_monitoring': {
            'section': '§314.4(d)',
            'title': 'Testing and Monitoring',
            'implemented': True,
        },
        'employee_training': {
            'section': '§314.4(e)',
            'title': 'Employee Security Training',
            'implemented': False,
        },
        'vendor_management': {
            'section': '§314.4(f)',
            'title': 'Vendor Management and Oversight',
            'implemented': False,
        },
        'incident_response': {
            'section': '§314.4(h)',
            'title': 'Incident Response Plan',
            'implemented': True,
        },
    }


class SimpleMerkleTree:
    """Simple Merkle tree implementation for audit chain integrity."""

    def __init__(self, hashfunc=sha256):
        self.hashfunc = hashfunc
        self.leaves = []
        self.merkle_root = hashfunc(b"empty").hexdigest()

    def append(self, data: bytes) -> None:
        self.leaves.append(data)
        self._update_root()

    def _update_root(self) -> None:
        if not self.leaves:
            self.merkle_root = self.hashfunc(b"empty").hexdigest()
            return
        hashes = [self.hashfunc(leaf).digest() for leaf in self.leaves]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            hashes = [
                self.hashfunc(hashes[i] + hashes[i + 1]).digest()
                for i in range(0, len(hashes), 2)
            ]
        self.merkle_root = hashes[0].hex()


class GLBAAuditor:
    """
    GLBA §314.4(c)(8) — Audit Trails and Activity Monitoring.

    Provides a Merkle-chained audit log with optional disk persistence.
    The chain_dir parameter sets where the audit JSON file is stored.
    Default: ~/.complychain/audit/ (overridable via COMPLYCHAIN_AUDIT_DIR).
    """

    def __init__(self, chain_dir: Path = None):
        self._lock = threading.Lock()
        self.audit_log = []
        self.merkle_tree = SimpleMerkleTree(hashfunc=sha256)
        self.chain_hash = "0" * 64  # Genesis hash

        # Resolve persistence directory
        default_dir = Path(
            os.environ.get('COMPLYCHAIN_AUDIT_DIR', '')
        ) or Path.home() / '.complychain' / 'audit'
        self.chain_dir = Path(chain_dir) if chain_dir else default_dir
        self.chain_file = self.chain_dir / 'audit_chain.json'

        self._load_chain()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_chain(self) -> None:
        """Load existing audit chain from disk if present."""
        if not self.chain_file.exists():
            return
        try:
            data = json.loads(self.chain_file.read_text())
            self.chain_hash = data.get('chain_hash', '0' * 64)
            for entry in data.get('entries', []):
                # Restore bytes signature stored as hex
                if isinstance(entry.get('sig'), str):
                    try:
                        entry['sig'] = bytes.fromhex(entry['sig'])
                    except ValueError:
                        entry['sig'] = entry['sig'].encode()
                self.audit_log.append(entry)
                tx_bytes = json.dumps(entry['tx'], sort_keys=True).encode()
                self.merkle_tree.append(tx_bytes)
            logger.info(
                f"Loaded audit chain: {len(self.audit_log)} entries from {self.chain_file}"
            )
        except Exception as e:
            logger.warning(f"Could not load audit chain from {self.chain_file}: {e}")

    def _save_chain(self) -> None:
        """Atomically persist audit chain to disk."""
        try:
            self.chain_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                'chain_hash': self.chain_hash,
                'merkle_root': self.merkle_tree.merkle_root,
                'entries': [
                    {
                        **{k: v for k, v in e.items() if k != 'sig'},
                        'sig': e['sig'].hex() if isinstance(e['sig'], bytes) else e['sig'],
                    }
                    for e in self.audit_log
                ],
            }
            with tempfile.NamedTemporaryFile(
                mode='w', dir=self.chain_dir, delete=False, suffix='.tmp'
            ) as f:
                json.dump(payload, f, indent=2, default=str)
                tmp_path = f.name
            shutil.move(tmp_path, self.chain_file)
            # Restrict file permissions: owner read/write only
            os.chmod(self.chain_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to persist audit chain: {e}")

    # ------------------------------------------------------------------
    # Core audit operations
    # ------------------------------------------------------------------

    def log_transaction(self, tx_data: dict, signature: bytes) -> str:
        """
        Append a transaction to the Merkle-chained audit log (§314.4(c)(8)).
        Returns the audit entry ID.  Thread-safe.
        """
        with self._lock:
            tx_bytes = json.dumps(tx_data, sort_keys=True).encode()
            self.merkle_tree.append(tx_bytes)

            audit_id = str(uuid.uuid4())
            sig_hex = signature.hex() if isinstance(signature, bytes) else signature
            new_hash = sha256(
                f"{self.chain_hash}{self.merkle_tree.merkle_root}{sig_hex}".encode()
            ).hexdigest()

            entry = {
                "id": audit_id,
                "tx": tx_data,
                "sig": signature,
                "prev_hash": self.chain_hash,
                "merkle_root": self.merkle_tree.merkle_root,
                "hash": new_hash,
                "timestamp": datetime.now().isoformat(),
            }
            self.audit_log.append(entry)
            self.chain_hash = new_hash

        self._save_chain()
        return audit_id

    def calculate_merkle_root(self) -> str:
        return self.merkle_tree.merkle_root

    def calculate_coverage(self) -> int:
        """Return the percentage of GLBA controls marked as implemented."""
        total = len(GLBA_REQUIREMENTS)
        if total == 0:
            return 100
        implemented = sum(
            1 for v in GLBA_REQUIREMENTS.values() if v.get('implemented', False)
        )
        return int((implemented / total) * 100)

    # ------------------------------------------------------------------
    # Report generation (§314.4(c)(8) / §314.4(h))
    # ------------------------------------------------------------------

    def generate_report(self, report_type: str) -> bytes:
        """
        Generate a GLBA compliance PDF report.

        report_type: 'daily' | 'monthly' | 'incident'
        """
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        width, height = letter

        titles = {
            'daily': 'GLBA Daily Report',
            'monthly': 'GLBA Monthly Report',
            'incident': 'GLBA Incident Report',
        }
        title_text = titles.get(report_type, f'GLBA {report_type.title()} Report')

        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, title_text)

        if report_type == 'daily':
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, height - 80, "GLBA Daily Compliance Report")

        # Regulatory citations
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 120, "Regulatory Citations:")
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 140, "• 16 CFR §314 — FTC Safeguards Rule (amended 2023)")
        c.drawString(50, height - 155, "• GLBA Title V — Privacy Rule")
        c.drawString(50, height - 170, "• NIST Cybersecurity Framework")
        c.drawString(50, height - 185, "• NIST FIPS 204 — ML-DSA (Dilithium3 signatures)")

        # Compliance matrix
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 220, "GLBA §314.4 Compliance Matrix:")

        y_pos = height - 245
        c.setFont("Helvetica", 9)
        for control_id, control_info in GLBA_REQUIREMENTS.items():
            status = 'Implemented' if control_info.get('implemented', False) else 'Pending'
            line = f"{control_info['section']}  —  {control_info['title']}  —  {status}"
            c.drawString(50, y_pos, line)
            y_pos -= 14
            if y_pos < 100:
                c.showPage()
                y_pos = height - 50

        # Summary
        coverage = self.calculate_coverage()
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_pos - 20, "Audit Summary:")
        c.setFont("Helvetica", 10)
        c.drawString(50, y_pos - 40, f"Total Transactions Logged: {len(self.audit_log)}")
        c.drawString(50, y_pos - 55, f"Merkle Root: {self.merkle_tree.merkle_root[:32]}...")
        c.drawString(50, y_pos - 70, f"Chain Hash: {self.chain_hash[:32]}...")
        c.drawString(50, y_pos - 85, f"Controls Implemented: {coverage}%")
        c.drawString(50, y_pos - 100, f"Report Generated: {datetime.now().isoformat()}")

        c.save()
        buf.seek(0)
        return buf.read()

"""
ComplyChain Crypto Engine
Implements GLBA §314.4(c)(3) — Data Encryption

Provides quantum-safe digital signatures via CRYSTALS-Dilithium3 (NIST FIPS 204 / ML-DSA).
Falls back to RSA-4096 when liboqs is not available.

Key storage uses AES-GCM-256 with Scrypt key derivation (OWASP 2024 parameters).
"""

import os
import json
import secrets
import ctypes
import tempfile
import shutil
import logging
from pathlib import Path
from contextlib import contextmanager
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from .exceptions import KeyValidationError

# Try quantum-safe backend (liboqs — FIPS 204 / ML-DSA)
try:
    import oqs  # type: ignore
    OQS_AVAILABLE = True
    logging.getLogger(__name__).info("liboqs available — FIPS 204 / ML-DSA (Dilithium3) enabled")
except ImportError:
    OQS_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "liboqs not available — falling back to RSA-4096. "
        "Install liboqs-python for FIPS 204 / ML-DSA support."
    )

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security parameters
# ---------------------------------------------------------------------------
# Scrypt parameters per OWASP 2024 recommendation: N=16384, r=8, p=1
# (Use N=131072 / 2^17 for higher-security deployments)
SCRYPT_N = 2 ** 14   # 16,384 — balanced for production
SCRYPT_R = 8
SCRYPT_P = 1
MIN_SALT_LEN = 32    # 256-bit salt

DEFAULT_KEY_DIR = Path.home() / '.complychain' / 'keys'


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class KeyStoreError(Exception):
    """Key store operation failed (wrong password, corruption, or missing keys)."""
    pass


class CorruptKeyError(KeyStoreError):
    """Key file is corrupt or has been tampered with."""
    pass


# ---------------------------------------------------------------------------
# QuantumSafeSigner
# ---------------------------------------------------------------------------

class QuantumSafeSigner:
    """
    GLBA §314.4(c)(3) — Quantum-safe digital signatures.

    Algorithm hierarchy:
        Dilithium3 (NIST FIPS 204 / ML-DSA) via liboqs  →  RSA-4096 fallback

    Key storage:
        AES-GCM-256 encrypted, Scrypt-derived key (OWASP 2024 parameters).
        Default location: ~/.complychain/keys/
    """

    def __init__(self, algorithm: str = "Dilithium3"):
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None

        if algorithm.upper() in ("DILITHIUM3", "DILITHIUM") and OQS_AVAILABLE:
            self._backend = "liboqs"
            self.algorithm = "Dilithium3"
        else:
            if algorithm.upper() not in ("RSA-4096", "RSA"):
                logger.warning(
                    f"{algorithm} requested but liboqs is not available — "
                    "falling back to RSA-4096"
                )
            self._backend = "rsa"
            self.algorithm = "RSA-4096"

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keys(self) -> tuple:
        """
        Generate a key pair.

        Returns:
            (private_key_bytes, public_key_bytes)
        """
        try:
            if self._backend == "liboqs":
                with oqs.Signature("Dilithium3") as signer:
                    public_key = signer.generate_keypair()
                    private_key = signer.export_secret_key()
                self._private_key = private_key
                self._public_key = public_key
                logger.info("Generated Dilithium3 (FIPS 204) key pair via liboqs")
            else:
                priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
                pub = priv.public_key()
                self._private_key = priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                self._public_key = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                logger.info("Generated RSA-4096 fallback key pair")

            return self._private_key, self._public_key

        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise RuntimeError(f"Failed to generate {self.algorithm} keys: {e}")

    # ------------------------------------------------------------------
    # Sign / Verify
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Sign a message. Keys must be loaded via generate_keys() or load_keys() first."""
        if not self._private_key:
            raise RuntimeError("No private key available — call generate_keys() or load_keys() first")
        try:
            if self._backend == "liboqs":
                with oqs.Signature("Dilithium3") as signer:
                    signer.import_secret_key(self._private_key)
                    return signer.sign(message)
            else:
                priv = serialization.load_pem_private_key(self._private_key, password=None)
                return priv.sign(
                    message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
        except Exception as e:
            raise RuntimeError(f"Signing failed: {e}")

    def verify(self, message: bytes, signature: bytes, public_key: bytes = None) -> bool:
        """Verify a signature. Uses internal public key when public_key is None."""
        pub = public_key if public_key is not None else self._public_key
        if pub is None:
            raise RuntimeError("No public key available for verification")
        try:
            if self._backend == "liboqs":
                with oqs.Signature("Dilithium3") as verifier:
                    verifier.import_public_key(pub)
                    return verifier.verify(message, signature)
            else:
                loaded_pub = serialization.load_pem_public_key(pub)
                try:
                    loaded_pub.verify(
                        signature, message,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256(),
                    )
                    return True
                except Exception:
                    return False
        except Exception as e:
            raise RuntimeError(f"Verification failed: {e}")

    # ------------------------------------------------------------------
    # Encrypted key storage (AES-GCM-256 + Scrypt)
    # ------------------------------------------------------------------

    def save_keys(self, path: Path, password: str) -> None:
        """
        Encrypt and save the key pair to disk.

        Encryption: AES-GCM-256
        KDF: Scrypt (N=16384, r=8, p=1) per OWASP 2024
        """
        if self._private_key is None or self._public_key is None:
            raise KeyStoreError("No keys to save — call generate_keys() first")
        if not password:
            raise KeyStoreError("Password required for key storage")

        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        salt = secrets.token_bytes(MIN_SALT_LEN)
        nonce = secrets.token_bytes(12)
        derived = self._derive_key(password, salt)

        try:
            aesgcm = AESGCM(derived)
            encrypted_priv = aesgcm.encrypt(nonce, self._private_key, b"")
        except Exception as e:
            raise KeyStoreError(f"Key encryption failed: {e}")
        finally:
            self._zeroize(bytearray(derived))

        pub_bytes = (
            self._public_key
            if isinstance(self._public_key, bytes)
            else self._public_key.encode()
        )

        payload = {
            'algorithm': self.algorithm,
            'backend': self._backend,
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'encrypted_private_key': encrypted_priv.hex(),
            'public_key': pub_bytes.hex(),
        }

        key_file = path / 'keystore.json'
        with tempfile.NamedTemporaryFile(mode='w', dir=path, delete=False, suffix='.tmp') as f:
            json.dump(payload, f, indent=2)
            tmp_path = f.name
        shutil.move(tmp_path, key_file)
        os.chmod(key_file, 0o600)
        logger.info(f"Keys saved to {key_file}")

    def load_keys(self, path: Path, password: str) -> None:
        """Load and decrypt a key pair from disk."""
        key_file = Path(path) / 'keystore.json'
        if not key_file.exists():
            raise KeyStoreError(f"Key store not found: {key_file}")
        if not password:
            raise KeyStoreError("Password required to load keys")

        with open(key_file) as f:
            payload = json.load(f)

        salt = bytes.fromhex(payload['salt'])
        nonce = bytes.fromhex(payload['nonce'])
        encrypted_priv = bytes.fromhex(payload['encrypted_private_key'])

        derived = self._derive_key(password, salt)
        try:
            aesgcm = AESGCM(derived)
            self._private_key = aesgcm.decrypt(nonce, encrypted_priv, b"")
        except InvalidTag:
            raise KeyStoreError("Authentication failed — incorrect password or corrupted key store")
        except Exception as e:
            raise KeyStoreError(f"Key decryption failed: {e}")
        finally:
            self._zeroize(bytearray(derived))

        self._public_key = bytes.fromhex(payload['public_key'])
        # Restore backend / algorithm from stored metadata
        self._backend = payload.get('backend', self._backend)
        self.algorithm = payload.get('algorithm', self.algorithm)
        logger.info(f"Keys loaded from {key_file} (algorithm: {self.algorithm})")

    # ------------------------------------------------------------------
    # PEM export / import (for HSM and interoperability)
    # ------------------------------------------------------------------

    def export_public_key_pem(self) -> str:
        if not self._public_key:
            raise RuntimeError("No public key available")
        if self._backend == "rsa":
            return self._public_key.decode('ascii')
        import base64
        b64 = base64.b64encode(self._public_key).decode('ascii')
        return f"-----BEGIN {self.algorithm} PUBLIC KEY-----\n{b64}\n-----END {self.algorithm} PUBLIC KEY-----\n"

    def export_private_key_pem(self) -> str:
        if not self._private_key:
            raise RuntimeError("No private key available")
        if self._backend == "rsa":
            return self._private_key.decode('ascii')
        import base64
        b64 = base64.b64encode(self._private_key).decode('ascii')
        return f"-----BEGIN {self.algorithm} PRIVATE KEY-----\n{b64}\n-----END {self.algorithm} PRIVATE KEY-----\n"

    def import_public_key_pem(self, pem_data: str) -> None:
        if self._backend == "rsa":
            self._public_key = pem_data.encode('ascii')
        else:
            import base64
            lines = [l for l in pem_data.strip().splitlines() if not l.startswith("-----")]
            self._public_key = base64.b64decode(''.join(lines))

    def import_private_key_pem(self, pem_data: str) -> None:
        if self._backend == "rsa":
            self._private_key = pem_data.encode('ascii')
        else:
            import base64
            lines = [l for l in pem_data.strip().splitlines() if not l.startswith("-----")]
            self._private_key = base64.b64decode(''.join(lines))

    def get_public_key(self) -> bytes:
        if self._public_key is None:
            raise KeyStoreError("No public key available")
        return self._public_key

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit AES key from password + salt using Scrypt.
        Parameters per OWASP 2024: N=16384, r=8, p=1.
        """
        kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        return kdf.derive(password.encode('utf-8'))

    def _zeroize(self, data: bytearray) -> None:
        """Securely overwrite sensitive memory."""
        try:
            import nacl.utils  # type: ignore
            nacl.utils.sodium_memzero(data)
        except ImportError:
            ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))

    def get_available_algorithms(self) -> list:
        """Return list of available signature algorithms on this system."""
        algorithms = []
        if OQS_AVAILABLE:
            algorithms.extend(['dilithium3', 'falcon512', 'sphincs+-sha256-128f-simple'])
        algorithms.append('rsa-4096')
        return algorithms

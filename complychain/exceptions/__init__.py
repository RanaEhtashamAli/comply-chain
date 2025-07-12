"""
Custom exceptions for ComplyChain package.

This module defines all custom exceptions used throughout the ComplyChain
codebase for better error handling and debugging.
"""


class ComplyChainError(Exception):
    """Base exception for all ComplyChain errors."""
    pass


class ComplianceViolationError(ComplyChainError):
    """Raised when GLBA compliance requirements are violated."""
    pass


class KeyValidationError(ComplyChainError):
    """Raised when cryptographic key validation fails."""
    pass


class AuditTamperDetected(ComplyChainError):
    """Raised when audit log tampering is detected."""
    pass


class ThreatScanException(ComplyChainError):
    """Raised when threat scanning operations fail."""
    pass


class CryptoEngineError(ComplyChainError):
    """Raised when cryptographic operations fail."""
    pass


class ConfigurationError(ComplyChainError):
    """Raised when configuration is invalid or missing."""
    pass


class ModelTrainingError(ComplyChainError):
    """Raised when ML model training fails."""
    pass


class FilePermissionError(ComplyChainError):
    """Raised when file permission issues occur."""
    pass


class SignatureVerificationError(ComplyChainError):
    """Raised when signature verification fails."""
    pass


class MemoryProtectionError(ComplyChainError):
    """Raised when memory protection operations fail."""
    pass


# Export all exceptions
__all__ = [
    'ComplyChainError',
    'ComplianceViolationError',
    'KeyValidationError',
    'AuditTamperDetected',
    'ThreatScanException',
    'CryptoEngineError',
    'ConfigurationError',
    'ModelTrainingError',
    'FilePermissionError',
    'SignatureVerificationError',
    'MemoryProtectionError',
] 
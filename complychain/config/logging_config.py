"""
Logging configuration for ComplyChain package.

This module provides centralized logging configuration with support for
different log levels, formats, and output destinations.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None,
    quantum_backend_monitoring: bool = True
) -> logging.Logger:
    """
    Set up logging configuration for ComplyChain.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging output
        format_string: Optional custom format string
        quantum_backend_monitoring: Enable monitoring of quantum backend status
        
    Returns:
        Configured logger instance
    """
    # Convert string level to logging constant
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Default format for production use
    if format_string is None:
        format_string = (
            "%(asctime)s - %(name)s - %(levelname)s - "
            "%(filename)s:%(lineno)d - %(message)s"
        )
    
    # Create formatter
    formatter = logging.Formatter(format_string)
    
    # Get root logger
    logger = logging.getLogger("complychain")
    logger.setLevel(log_level)
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Quantum backend monitoring
    if quantum_backend_monitoring:
        quantum_logger = logging.getLogger("complychain.quantum")
        quantum_logger.setLevel(logging.WARNING)
        
        # Monitor quantum backend availability
        try:
            import oqs
            quantum_logger.info("Quantum backend (liboqs) is available")
        except ImportError:
            quantum_logger.error("Quantum backend (liboqs) is not available - falling back to RSA-4096")
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(f"complychain.{name}")


# Default logger setup
def setup_default_logging() -> logging.Logger:
    """Set up default logging configuration."""
    return setup_logging(level="INFO")


# Debug logger setup
def setup_debug_logging() -> logging.Logger:
    """Set up debug logging configuration."""
    return setup_logging(level="DEBUG")


# Production logger setup
def setup_production_logging(log_file: Path) -> logging.Logger:
    """Set up production logging configuration."""
    return setup_logging(
        level="WARNING",
        log_file=log_file,
        format_string="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    ) 
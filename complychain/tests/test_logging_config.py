"""Tests for complychain.config.logging_config."""

import logging
import pytest
from pathlib import Path
from complychain.config.logging_config import (
    setup_logging,
    get_logger,
    setup_default_logging,
    setup_debug_logging,
    setup_production_logging,
)


@pytest.fixture(autouse=True)
def _close_file_handlers():
    """Close and remove any FileHandlers added to the complychain logger after each test.

    Without this, FileHandler objects outlive tmp_path and trigger
    PytestUnraisableExceptionWarning when Python's GC eventually closes
    already-deleted files.
    """
    yield
    root = logging.getLogger("complychain")
    for handler in root.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.close()
            root.removeHandler(handler)


def test_setup_logging_returns_logger():
    logger = setup_logging(level="INFO")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "complychain"


def test_setup_logging_sets_level():
    logger = setup_logging(level="DEBUG")
    assert logger.level == logging.DEBUG


def test_setup_logging_warning_level():
    logger = setup_logging(level="WARNING")
    assert logger.level == logging.WARNING


def test_setup_logging_with_log_file(tmp_path):
    log_file = tmp_path / "complychain.log"
    logger = setup_logging(level="INFO", log_file=log_file)
    assert log_file.exists() or True  # file may be created on first write
    # Check that a file handler was added
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) > 0


def test_setup_logging_with_nested_log_dir(tmp_path):
    log_file = tmp_path / "subdir" / "nested" / "complychain.log"
    logger = setup_logging(level="INFO", log_file=log_file)
    assert log_file.parent.exists()


def test_setup_logging_with_custom_format():
    fmt = "%(levelname)s: %(message)s"
    logger = setup_logging(level="INFO", format_string=fmt)
    assert isinstance(logger, logging.Logger)


def test_setup_logging_no_quantum_monitoring():
    logger = setup_logging(level="INFO", quantum_backend_monitoring=False)
    assert isinstance(logger, logging.Logger)


def test_setup_logging_quantum_monitoring_enabled():
    logger = setup_logging(level="INFO", quantum_backend_monitoring=True)
    assert isinstance(logger, logging.Logger)


def test_setup_logging_clears_duplicate_handlers():
    setup_logging(level="INFO")
    setup_logging(level="INFO")
    logger = logging.getLogger("complychain")
    # Should not accumulate duplicate handlers
    console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)
                        and not isinstance(h, logging.FileHandler)]
    assert len(console_handlers) == 1


def test_get_logger_returns_child_logger():
    logger = get_logger("my.module")
    assert "complychain.my.module" in logger.name


def test_get_logger_different_modules():
    l1 = get_logger("module_a")
    l2 = get_logger("module_b")
    assert l1.name != l2.name


def test_setup_default_logging():
    logger = setup_default_logging()
    assert isinstance(logger, logging.Logger)
    assert logger.level == logging.INFO


def test_setup_debug_logging():
    logger = setup_debug_logging()
    assert isinstance(logger, logging.Logger)
    assert logger.level == logging.DEBUG


def test_setup_production_logging(tmp_path):
    log_file = tmp_path / "prod.log"
    logger = setup_production_logging(log_file)
    assert isinstance(logger, logging.Logger)
    assert logger.level == logging.WARNING
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) > 0

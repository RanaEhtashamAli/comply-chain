"""Tests for complychain.config — ConfigManager and helper functions."""

import pytest
import yaml
from pathlib import Path
from complychain.config import (
    ConfigManager,
    get_config,
    get_setting,
    set_setting,
    save_config,
)


# ---------------------------------------------------------------------------
# ConfigManager — get / set
# ---------------------------------------------------------------------------

def test_get_existing_key():
    mgr = ConfigManager()
    value = mgr.get("compliance.mode")
    assert value == "strict"


def test_get_nested_key():
    mgr = ConfigManager()
    value = mgr.get("crypto.algorithm")
    assert value == "Dilithium3"


def test_get_missing_key_returns_default():
    mgr = ConfigManager()
    assert mgr.get("nonexistent.key", "default_val") == "default_val"


def test_get_missing_key_no_default_returns_none():
    mgr = ConfigManager()
    assert mgr.get("nonexistent.deeply.nested") is None


def test_set_existing_key():
    mgr = ConfigManager()
    mgr.set("audit.retention_days", 730)
    assert mgr.get("audit.retention_days") == 730
    mgr.set("audit.retention_days", 365)


def test_set_creates_new_nested_key():
    mgr = ConfigManager()
    mgr.set("custom.section.key", "test_value")
    assert mgr.get("custom.section.key") == "test_value"


def test_set_top_level_key():
    mgr = ConfigManager()
    mgr.set("new_top_level", 42)
    assert mgr.get("new_top_level") == 42


# ---------------------------------------------------------------------------
# ConfigManager — load from file
# ---------------------------------------------------------------------------

def test_load_config_from_file(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump({"custom_key": "custom_value"}))
    mgr = ConfigManager()
    result = mgr.load_config(config_file)
    assert result["custom_key"] == "custom_value"


def test_load_config_merges_with_defaults(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump({"audit": {"retention_days": 999}}))
    mgr = ConfigManager()
    result = mgr.load_config(config_file)
    assert result["audit"]["retention_days"] == 999
    assert "compliance" in result


def test_load_config_empty_file(tmp_path):
    config_file = tmp_path / "empty.yaml"
    config_file.write_text("")
    mgr = ConfigManager()
    result = mgr.load_config(config_file)
    assert isinstance(result, dict)


def test_load_config_no_file():
    mgr = ConfigManager()
    result = mgr.load_config()
    assert isinstance(result, dict)
    assert "compliance" in result


# ---------------------------------------------------------------------------
# ConfigManager — save
# ---------------------------------------------------------------------------

def test_save_config_writes_yaml(tmp_path):
    config_file = tmp_path / "saved_config.yaml"
    mgr = ConfigManager()
    mgr.save_config(config_file)
    assert config_file.exists()
    content = yaml.safe_load(config_file.read_text())
    assert isinstance(content, dict)
    assert "compliance" in content


# ---------------------------------------------------------------------------
# ConfigManager — reload
# ---------------------------------------------------------------------------

def test_reload_with_no_config_file_is_noop():
    mgr = ConfigManager()
    mgr._config_file = None
    mgr.reload()


def test_reload_rereads_file(tmp_path):
    config_file = tmp_path / "reload_test.yaml"
    config_file.write_text(yaml.dump({"reload_key": "v1"}))
    mgr = ConfigManager()
    mgr.load_config(config_file)
    config_file.write_text(yaml.dump({"reload_key": "v2"}))
    mgr.reload()
    assert mgr.get("reload_key") == "v2"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def test_get_setting_existing():
    value = get_setting("compliance.mode")
    assert value is not None


def test_get_setting_missing_returns_default():
    assert get_setting("does.not.exist", "fallback") == "fallback"


def test_set_setting_and_get():
    set_setting("scanner.batch_size", 200)
    assert get_setting("scanner.batch_size") == 200
    set_setting("scanner.batch_size", 100)


def test_save_config_module_function(tmp_path):
    out_file = tmp_path / "module_save.yaml"
    save_config(out_file)
    assert out_file.exists()

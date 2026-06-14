"""Tests for complychain.audit_server entry point."""

import json
import stat
import sys
import pytest
from pathlib import Path
from unittest.mock import patch
from complychain.audit_server import main


def test_main_creates_audit_dir(tmp_path):
    audit_dir = tmp_path / "audit_chain"
    with patch("sys.argv", ["audit_server", "--data-dir", str(audit_dir)]):
        main()
    assert audit_dir.exists()


def test_main_creates_chain_file(tmp_path):
    audit_dir = tmp_path / "audit_chain"
    with patch("sys.argv", ["audit_server", "--data-dir", str(audit_dir)]):
        main()
    chain_file = audit_dir / "audit_chain.json"
    assert chain_file.exists()


def test_main_chain_file_is_valid_json(tmp_path):
    audit_dir = tmp_path / "audit_chain"
    with patch("sys.argv", ["audit_server", "--data-dir", str(audit_dir)]):
        main()
    chain_file = audit_dir / "audit_chain.json"
    data = json.loads(chain_file.read_text())
    assert "genesis_block" in data
    assert data["genesis_block"]["glba_compliance_version"] == "314.4"


def test_main_chain_file_permissions(tmp_path):
    audit_dir = tmp_path / "audit_chain"
    with patch("sys.argv", ["audit_server", "--data-dir", str(audit_dir)]):
        main()
    chain_file = audit_dir / "audit_chain.json"
    mode = stat.S_IMODE(chain_file.stat().st_mode)
    assert mode == 0o600


def test_main_does_not_overwrite_existing_chain(tmp_path):
    audit_dir = tmp_path / "audit_chain"
    audit_dir.mkdir()
    chain_file = audit_dir / "audit_chain.json"
    chain_file.write_text('{"existing": true}')

    with patch("sys.argv", ["audit_server", "--data-dir", str(audit_dir)]):
        main()

    data = json.loads(chain_file.read_text())
    assert "existing" in data


def test_main_uses_default_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    audit_dir = tmp_path / "audit_chain"
    with patch("sys.argv", ["audit_server", "--data-dir", str(audit_dir)]):
        main()
    assert audit_dir.exists()

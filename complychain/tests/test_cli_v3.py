"""CLI tests for v3.0.0 commands: generate-sar, rules, monitor, export-evidence, key-rotation."""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from complychain.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# generate-sar
# ---------------------------------------------------------------------------

def test_generate_sar_missing_scan_result():
    result = runner.invoke(app, ["generate-sar", "--scan-result", "/nonexistent/path.json"])
    assert result.exit_code != 0


def test_generate_sar_json_output(tmp_path):
    scan = {
        "risk_score": 85,
        "threat_flags": ["HIGH_VALUE_TRANSACTION"],
        "fincen_compliance": {"ctr_required": True, "sar_required": False},
    }
    tx = {"amount": 15000, "transaction_type": "wire"}
    scan_file = tmp_path / "scan.json"
    tx_file = tmp_path / "tx.json"
    out_file = tmp_path / "sar.json"
    scan_file.write_text(json.dumps(scan))
    tx_file.write_text(json.dumps(tx))

    result = runner.invoke(app, [
        "generate-sar",
        "--scan-result", str(scan_file),
        "--transaction", str(tx_file),
        "--output", str(out_file),
    ])
    assert result.exit_code == 0
    data = json.loads(out_file.read_text())
    assert "sar_id" in data


def test_generate_sar_xml_output(tmp_path):
    scan = {"risk_score": 70, "threat_flags": [], "fincen_compliance": {}}
    scan_file = tmp_path / "scan.json"
    out_file = tmp_path / "sar.xml"
    scan_file.write_text(json.dumps(scan))

    result = runner.invoke(app, [
        "generate-sar",
        "--scan-result", str(scan_file),
        "--output", str(out_file),
    ])
    assert result.exit_code == 0
    assert "EFilingBatchXML" in out_file.read_text()


def test_generate_sar_pdf_output(tmp_path):
    scan = {"risk_score": 50, "threat_flags": [], "fincen_compliance": {}}
    scan_file = tmp_path / "scan.json"
    out_file = tmp_path / "sar.pdf"
    scan_file.write_text(json.dumps(scan))

    result = runner.invoke(app, [
        "generate-sar",
        "--scan-result", str(scan_file),
        "--output", str(out_file),
    ])
    assert result.exit_code == 0
    assert out_file.read_bytes()[:4] == b"%PDF"


def test_generate_sar_custom_filing_type(tmp_path):
    scan = {"risk_score": 60, "threat_flags": [], "fincen_compliance": {}}
    scan_file = tmp_path / "scan.json"
    out_file = tmp_path / "sar.json"
    scan_file.write_text(json.dumps(scan))

    result = runner.invoke(app, [
        "generate-sar",
        "--scan-result", str(scan_file),
        "--output", str(out_file),
        "--filing-type", "CORRECT",
    ])
    assert result.exit_code == 0
    assert json.loads(out_file.read_text())["filing_type"] == "CORRECT"


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

def test_serve_no_fastapi_exits_nonzero():
    import sys
    with patch.dict(sys.modules, {"uvicorn": None}):
        result = runner.invoke(app, ["serve", "--port", "9999"])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# rules validate
# ---------------------------------------------------------------------------

def test_rules_validate_valid_file(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("""
rules:
  - name: test_rule
    condition: "amount > 5000"
    risk_weight: 20
    flag: TEST
    severity: HIGH
    description: test
    enabled: true
""")
    result = runner.invoke(app, ["rules", "validate", str(rules)])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_rules_validate_invalid_severity(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("""
rules:
  - name: bad
    condition: "amount > 0"
    risk_weight: 10
    flag: BAD
    severity: GARBAGE
    description: test
    enabled: true
""")
    result = runner.invoke(app, ["rules", "validate", str(rules)])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# monitor commands
# ---------------------------------------------------------------------------

def test_monitor_list():
    result = runner.invoke(app, ["monitor", "list"])
    assert result.exit_code == 0


def test_monitor_stop():
    result = runner.invoke(app, ["monitor", "stop", "--job-id", "fake-id"])
    assert result.exit_code == 0


def test_monitor_start_no_apscheduler():
    with patch("complychain.monitoring.scheduler.MonitoringScheduler.start",
               side_effect=ImportError("apscheduler not installed")):
        result = runner.invoke(app, [
            "monitor", "start",
            "--regulation", "glba",
            "--name", "Test Bank",
        ])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# export-evidence
# ---------------------------------------------------------------------------

def test_export_evidence_creates_zip(tmp_path):
    out = tmp_path / "evidence.zip"
    result = runner.invoke(app, [
        "export-evidence",
        "--output", str(out),
        "--no-sign",
    ])
    assert result.exit_code == 0
    assert out.exists()


def test_export_evidence_specific_regulation(tmp_path):
    out = tmp_path / "evidence.zip"
    result = runner.invoke(app, [
        "export-evidence",
        "--output", str(out),
        "--regulations", "glba",
        "--no-sign",
    ])
    assert result.exit_code == 0
    assert out.exists()


# ---------------------------------------------------------------------------
# key-rotation check
# ---------------------------------------------------------------------------

def test_key_rotation_check_runs():
    result = runner.invoke(app, ["key-rotation", "check"])
    assert result.exit_code == 0
    output = result.output.lower()
    assert "rotation" in output


# ---------------------------------------------------------------------------
# key-rotation rotate
# ---------------------------------------------------------------------------

def test_key_rotation_rotate_dry_run(tmp_path):
    result = runner.invoke(app, [
        "key-rotation", "rotate",
        "--dry-run",
        "--backup-dir", str(tmp_path / "backups"),
    ])
    assert result.exit_code == 0
    assert "dry run" in result.output.lower() or "rotation" in result.output.lower()


# ---------------------------------------------------------------------------
# key-rotation history
# ---------------------------------------------------------------------------

def test_key_rotation_history_empty(tmp_path):
    result = runner.invoke(app, [
        "key-rotation", "history",
        "--backup-dir", str(tmp_path / "no_backups"),
    ])
    assert result.exit_code == 0
    assert "no rotation" in result.output.lower() or "0" in result.output


def test_key_rotation_history_with_entries(tmp_path):
    backup_dir = tmp_path / "backups"
    entry = backup_dir / "20260704_120000"
    entry.mkdir(parents=True)
    manifest = {
        "rotated_at": "20260704_120000",
        "new_algorithm": "rsa-4096",
        "old_algorithm": "rsa-4096",
    }
    (entry / "rotation_manifest.json").write_text(json.dumps(manifest))

    result = runner.invoke(app, ["key-rotation", "history", "--backup-dir", str(backup_dir)])
    assert result.exit_code == 0
    assert "20260704_120000" in result.output


# ---------------------------------------------------------------------------
# regulations history and diff (previously uncovered)
# ---------------------------------------------------------------------------

def test_regulations_history_no_data():
    result = runner.invoke(app, [
        "regulations", "history",
        "--regulation", "glba",
        "--days", "1",
    ])
    assert result.exit_code == 0


def test_regulations_history_json_format():
    result = runner.invoke(app, [
        "regulations", "history",
        "--regulation", "glba",
        "--format", "json",
    ])
    assert result.exit_code == 0


def test_regulations_diff_not_enough_history():
    result = runner.invoke(app, ["regulations", "diff", "--regulation", "glba"])
    assert result.exit_code == 0
    assert "not enough" in result.output.lower() or "diff" in result.output.lower()

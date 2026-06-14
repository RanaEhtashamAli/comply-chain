"""Tests for the `complychain regulations` CLI sub-app."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from complychain.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# regulations list
# ---------------------------------------------------------------------------

def test_regulations_list_default_shows_us_fintech():
    result = runner.invoke(app, ["regulations", "list"])
    assert result.exit_code == 0
    assert "glba" in result.output.lower() or "GLBA" in result.output


def test_regulations_list_all_flag_shows_dora():
    result = runner.invoke(app, ["regulations", "list", "--all"])
    assert result.exit_code == 0
    assert "dora" in result.output.lower() or "DORA" in result.output


def test_regulations_list_eu_jurisdiction_shows_dora():
    result = runner.invoke(app, [
        "regulations", "list",
        "--jurisdiction", "DE",
        "--all",
    ])
    assert result.exit_code == 0
    assert "dora" in result.output.lower() or "DORA" in result.output


def test_regulations_list_processes_cards_shows_pci():
    result = runner.invoke(app, [
        "regulations", "list",
        "--processes-cards",
    ])
    assert result.exit_code == 0
    assert "pci" in result.output.lower() or "PCI" in result.output


def test_regulations_list_saas_entity_shows_soc2():
    result = runner.invoke(app, [
        "regulations", "list",
        "--entity-type", "saas",
    ])
    assert result.exit_code == 0
    assert "soc2" in result.output.lower() or "SOC" in result.output


# ---------------------------------------------------------------------------
# regulations assess — table format
# ---------------------------------------------------------------------------

def test_regulations_assess_glba_table():
    result = runner.invoke(app, ["regulations", "assess", "glba"])
    assert result.exit_code == 0
    assert "GLBA" in result.output or "glba" in result.output


def test_regulations_assess_unknown_regulation_exits_nonzero():
    result = runner.invoke(app, ["regulations", "assess", "not_a_real_reg"])
    assert result.exit_code != 0
    assert "Unknown regulation" in result.output or "not_a_real_reg" in result.output


# ---------------------------------------------------------------------------
# regulations assess — JSON format
# ---------------------------------------------------------------------------

def test_regulations_assess_json_output(tmp_path):
    out_file = tmp_path / "inline.json"
    result = runner.invoke(app, [
        "regulations", "assess", "glba",
        "--format", "json",
        "--output", str(out_file),
    ])
    assert result.exit_code == 0
    assert out_file.exists()
    parsed = json.loads(out_file.read_text())
    assert "glba" in parsed
    assert "overall_status" in parsed["glba"]
    assert "controls" in parsed["glba"]


def test_regulations_assess_json_written_to_file(tmp_path):
    out_file = tmp_path / "report.json"
    result = runner.invoke(app, [
        "regulations", "assess", "glba",
        "--format", "json",
        "--output", str(out_file),
    ])
    assert result.exit_code == 0
    assert out_file.exists()
    parsed = json.loads(out_file.read_text())
    assert "glba" in parsed


# ---------------------------------------------------------------------------
# regulations assess — all applicable (no regulation_id arg)
# ---------------------------------------------------------------------------

def test_regulations_assess_all_applicable_default_profile():
    result = runner.invoke(app, ["regulations", "assess"])
    assert result.exit_code == 0
    # US fintech: GLBA and SOC2 should both be applicable
    output_lower = result.output.lower()
    assert "glba" in output_lower or "soc" in output_lower

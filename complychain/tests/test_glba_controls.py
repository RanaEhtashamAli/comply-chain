"""Tests for the 5 newly implemented GLBA §314.4 controls."""

import pytest
from pathlib import Path
from complychain.compliance.data_inventory import DataInventoryScanner
from complychain.compliance.data_disposal import DataDisposal
from complychain.compliance.change_management import ChangeManager
from complychain.compliance.training import TrainingManager, REQUIRED_COURSES


# ---------------------------------------------------------------------------
# §314.4(c)(2) — Data Inventory
# ---------------------------------------------------------------------------

def test_data_inventory_scan_empty_dir(tmp_path):
    scanner = DataInventoryScanner()
    report = scanner.scan(tmp_path)
    assert report.total_files == 0


def test_data_inventory_detects_ssn(tmp_path):
    (tmp_path / "records.txt").write_text("SSN: 123-45-6789 customer data")
    scanner = DataInventoryScanner()
    report = scanner.scan(tmp_path)
    assert report.sensitive_files == 1
    assert 'ssn' in report.records[0].pii_types_found


def test_data_inventory_detects_email(tmp_path):
    (tmp_path / "contacts.txt").write_text("Email: user@example.com")
    scanner = DataInventoryScanner()
    report = scanner.scan(tmp_path)
    assert report.restricted_files == 1


def test_data_inventory_public_file(tmp_path):
    (tmp_path / "readme.txt").write_text("No PII here at all.")
    scanner = DataInventoryScanner()
    report = scanner.scan(tmp_path)
    assert report.public_files == 1


def test_data_inventory_save_report(tmp_path):
    scanner = DataInventoryScanner()
    report = scanner.scan(tmp_path)
    out = tmp_path / "inventory.json"
    scanner.save_report(report, out)
    assert out.exists()
    import json
    data = json.loads(out.read_text())
    assert 'scanned_at' in data


# ---------------------------------------------------------------------------
# §314.4(c)(6) — Data Disposal
# ---------------------------------------------------------------------------

def test_secure_disposal_removes_file(tmp_path):
    f = tmp_path / "sensitive.txt"
    f.write_text("SSN: 123-45-6789")
    disposal = DataDisposal(passes=1)
    assert disposal.dispose(f)
    assert not f.exists()


def test_secure_disposal_nonexistent_file(tmp_path):
    disposal = DataDisposal()
    assert disposal.dispose(tmp_path / "ghost.txt") is False


def test_retention_enforcement(tmp_path):
    import time
    old_file = tmp_path / "old.txt"
    old_file.write_text("old data")
    # Backdate mtime by 60 days
    old_time = time.time() - 60 * 86400
    import os
    os.utime(old_file, (old_time, old_time))

    new_file = tmp_path / "new.txt"
    new_file.write_text("new data")

    disposal = DataDisposal(passes=1)
    disposed = disposal.enforce_retention(tmp_path, max_age_days=30)
    assert old_file in disposed
    assert new_file not in disposed
    assert not old_file.exists()
    assert new_file.exists()


def test_retention_dry_run(tmp_path):
    import os, time
    old = tmp_path / "old.txt"
    old.write_text("data")
    old_time = time.time() - 60 * 86400
    os.utime(old, (old_time, old_time))

    disposal = DataDisposal(passes=1)
    disposed = disposal.enforce_retention(tmp_path, max_age_days=30, dry_run=True)
    assert old in disposed
    assert old.exists()  # not actually deleted in dry_run


# ---------------------------------------------------------------------------
# §314.4(c)(7) — Change Management
# ---------------------------------------------------------------------------

def test_change_record_stored(tmp_path):
    mgr = ChangeManager(log_dir=tmp_path)
    cid = mgr.record('config', 'scanner.threshold', 'Updated threshold', 'alice')
    assert 'scanner.threshold' in cid
    assert len(mgr.get_recent()) == 1


def test_config_change_helper(tmp_path):
    mgr = ChangeManager(log_dir=tmp_path)
    mgr.record_config_change('ml.contamination', 0.1, 0.05, 'bob')
    records = mgr.get_by_component('ml.contamination')
    assert len(records) == 1
    assert records[0]['before'] == 0.1
    assert records[0]['after'] == 0.05


def test_key_rotation_logged(tmp_path):
    mgr = ChangeManager(log_dir=tmp_path)
    mgr.record_key_rotation('Dilithium3', 'alice')
    records = mgr.get_by_component('crypto:Dilithium3')
    assert len(records) == 1
    assert records[0]['change_type'] == 'key_rotation'


def test_change_log_persists(tmp_path):
    mgr = ChangeManager(log_dir=tmp_path)
    mgr.record('deploy', 'complychain', 'v1.1.0 deployed', 'ci-bot')
    mgr2 = ChangeManager(log_dir=tmp_path)
    assert len(mgr2.get_recent()) == 1


# ---------------------------------------------------------------------------
# §314.4(e) — Employee Training
# ---------------------------------------------------------------------------

def test_assign_and_complete(tmp_path):
    mgr = TrainingManager(store_dir=tmp_path)
    mgr.assign('alice', 'glba_safeguards_overview')
    assert not mgr.is_compliant('alice')  # only 1 of 5 required
    mgr.complete('alice', 'glba_safeguards_overview', score=95.0)
    summary = mgr.employee_summary('alice')
    assert summary['completed'] == 1


def test_assign_all_required(tmp_path):
    mgr = TrainingManager(store_dir=tmp_path)
    records = mgr.assign_all_required('bob')
    assert len(records) == len(REQUIRED_COURSES)


def test_compliance_after_all_completed(tmp_path):
    mgr = TrainingManager(store_dir=tmp_path)
    mgr.assign_all_required('carol')
    for course in REQUIRED_COURSES:
        mgr.complete('carol', course, score=80.0)
    assert mgr.is_compliant('carol')


def test_overdue_detection(tmp_path):
    from datetime import datetime, timedelta
    mgr = TrainingManager(store_dir=tmp_path, due_days=30)
    mgr.assign('dave', 'phishing_and_social_engineering')
    # Manually backdate the due_date
    key = 'dave::phishing_and_social_engineering'
    mgr._records[key].due_date = (datetime.now() - timedelta(days=1)).isoformat()
    overdue = mgr.refresh_overdue()
    assert any(r.employee_id == 'dave' for r in overdue)


def test_training_store_persists(tmp_path):
    mgr = TrainingManager(store_dir=tmp_path)
    mgr.assign('eve', 'data_handling_and_privacy')
    mgr2 = TrainingManager(store_dir=tmp_path)
    summary = mgr2.employee_summary('eve')
    assert summary['total_assigned'] == 1


def test_compliance_report(tmp_path):
    mgr = TrainingManager(store_dir=tmp_path)
    mgr.assign_all_required('frank')
    report = mgr.compliance_report()
    assert 'total_employees' in report
    assert report['total_employees'] == 1

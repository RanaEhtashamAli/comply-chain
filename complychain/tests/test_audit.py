import pytest
from complychain.audit_system import GLBAAuditor, SimpleMerkleTree
from hashlib import sha256


def test_log_transaction():
    auditor = GLBAAuditor()
    tx_data = {"amount": 100}
    signature = b"sig"
    audit_id = auditor.log_transaction(tx_data, signature)
    assert isinstance(audit_id, str)


def test_generate_report():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("daily")
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b'%PDF' or pdf[:4] == b'\x25PDF'


def test_generate_report_monthly():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("monthly")
    assert isinstance(pdf, bytes)


def test_generate_report_incident():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("incident")
    assert isinstance(pdf, bytes)


def test_generate_report_unknown_type():
    auditor = GLBAAuditor()
    pdf = auditor.generate_report("quarterly")
    assert isinstance(pdf, bytes)


def test_calculate_coverage():
    auditor = GLBAAuditor()
    coverage = auditor.calculate_coverage()
    assert isinstance(coverage, int)
    assert 0 <= coverage <= 100


def test_load_chain_from_disk(tmp_path):
    auditor1 = GLBAAuditor(chain_dir=tmp_path)
    tx = {"amount": 5000, "ref": "TX001"}
    auditor1.log_transaction(tx, b"sig1")
    auditor1.log_transaction({"amount": 200}, b"sig2")

    auditor2 = GLBAAuditor(chain_dir=tmp_path)
    assert len(auditor2.audit_log) == 2
    assert auditor2.chain_hash == auditor1.chain_hash


def test_load_chain_restores_merkle_root(tmp_path):
    auditor1 = GLBAAuditor(chain_dir=tmp_path)
    auditor1.log_transaction({"amount": 1000}, b"sig")
    root1 = auditor1.calculate_merkle_root()

    auditor2 = GLBAAuditor(chain_dir=tmp_path)
    root2 = auditor2.calculate_merkle_root()
    assert root1 == root2


def test_merkle_tree_odd_leaves_padding():
    tree = SimpleMerkleTree(hashfunc=sha256)
    for i in range(3):
        tree.append(f"leaf{i}".encode())
    root = tree.merkle_root
    assert len(root) == 64


def test_merkle_tree_single_leaf():
    tree = SimpleMerkleTree(hashfunc=sha256)
    tree.append(b"only_leaf")
    assert len(tree.merkle_root) == 64


def test_chain_file_permissions(tmp_path):
    import stat
    auditor = GLBAAuditor(chain_dir=tmp_path)
    auditor.log_transaction({"amount": 100}, b"sig")
    chain_file = tmp_path / "audit_chain.json"
    assert chain_file.exists()
    mode = stat.S_IMODE(chain_file.stat().st_mode)
    assert mode == 0o600


def test_merkle_tree_empty_root():
    """_update_root with no leaves should produce a deterministic hash of b'empty'."""
    tree = SimpleMerkleTree(hashfunc=sha256)
    assert len(tree.merkle_root) == 64


def test_load_chain_invalid_hex_sig(tmp_path):
    """A sig stored as non-hex string should fall back to .encode() without raising."""
    import json
    chain_file = tmp_path / "audit_chain.json"
    chain_file.write_text(json.dumps({
        "entries": [
            {"tx": {"amount": 1}, "sig": "NOT_HEX_ZZ", "id": "abc", "prev_hash": "0" * 64}
        ],
        "chain_hash": "0" * 64,
    }))
    auditor = GLBAAuditor(chain_dir=tmp_path)
    assert len(auditor.audit_log) == 1
    assert isinstance(auditor.audit_log[0]["sig"], bytes)


def test_load_chain_corrupted_file(tmp_path):
    """A totally corrupted chain file should be swallowed with a warning (not raise)."""
    chain_file = tmp_path / "audit_chain.json"
    chain_file.write_text("NOT JSON {{{")
    auditor = GLBAAuditor(chain_dir=tmp_path)
    assert auditor.audit_log == []


def test_save_chain_exception_does_not_raise(tmp_path, monkeypatch):
    """_save_chain error should be logged but not propagate."""
    import shutil
    auditor = GLBAAuditor(chain_dir=tmp_path)
    monkeypatch.setattr(shutil, "move", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    auditor.log_transaction({"amount": 1}, b"sig")  # should not raise


def test_calculate_coverage_no_requirements(monkeypatch):
    """calculate_coverage returns 100 when GLBA_REQUIREMENTS is empty."""
    import complychain.audit_system as _as
    monkeypatch.setattr(_as, "GLBA_REQUIREMENTS", {})
    auditor = GLBAAuditor()
    assert auditor.calculate_coverage() == 100


def test_generate_report_many_entries_causes_page_break(tmp_path):
    """Enough audit entries trigger the y_pos < 100 page-break path in the PDF."""
    auditor = GLBAAuditor(chain_dir=tmp_path)
    for i in range(60):
        auditor.log_transaction({"amount": i, "ref": f"TX{i:04d}"}, b"sig")
    pdf = auditor.generate_report("daily")
    assert pdf[:4] in (b"%PDF", b"\x25PDF")
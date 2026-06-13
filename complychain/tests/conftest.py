import pytest


@pytest.fixture(autouse=True)
def isolated_audit_chain(tmp_path, monkeypatch):
    """Each test gets a fresh, empty audit chain directory."""
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path / "audit"))

import pytest
from complychain.threat_scanner import GLBAScanner


@pytest.fixture(autouse=True)
def isolated_audit_chain(tmp_path, monkeypatch):
    """Each test gets a fresh, empty audit chain directory."""
    monkeypatch.setenv("COMPLYCHAIN_AUDIT_DIR", str(tmp_path / "audit"))


@pytest.fixture(autouse=True)
def patch_scanner_for_speed(monkeypatch):
    """Bypass all live sanctions API calls in every test."""
    def _fallback(self):
        self._sanction_cache = self._get_ofac_fallback_data()
        self._sanctions_status.__class__  # keep attribute access safe
        from complychain.threat_scanner import SanctionsVerificationStatus
        self._sanctions_status = SanctionsVerificationStatus.TEST_MODE
        return self._sanction_cache

    monkeypatch.setattr(GLBAScanner, 'load_sanction_list', _fallback)
    monkeypatch.setattr(GLBAScanner, '_load_ofac_sdn_list',   lambda self: set())
    monkeypatch.setattr(GLBAScanner, '_load_fincen_bsa_data', lambda self, k: set())
    monkeypatch.setattr(GLBAScanner, '_load_unsc_sanctions',  lambda self: set())
    monkeypatch.setattr(GLBAScanner, '_load_uk_sanctions',    lambda self: set())

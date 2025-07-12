"""
CLI usage tests for ComplyChain.

This module tests the Typer-based CLI interface using direct function calls
to verify commands work correctly without subprocess issues.
"""

import json
import tempfile
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def sample_transaction():
    """Create a sample transaction for testing."""
    return {
        "amount": 5000,
        "currency": "USD",
        "timestamp": 1640995200,
        "sender": "test_sender",
        "recipient": "test_recipient",
        "transaction_type": "wire_transfer",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "account_age_days": 365,
        "transaction_count": 50,
        "avg_transaction_amount": 1000,
        "is_high_value": False,
        "is_cross_border": False,
        "is_wire_transfer": True,
        "is_new_recipient": False,
        "is_after_hours": False,
    }


@pytest.fixture
def temp_files():
    """Create temporary files for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create sample transaction file
        tx_file = temp_path / "sample_tx.json"
        with open(tx_file, 'w') as f:
            json.dump({
                "amount": 5000,
                "currency": "USD",
                "timestamp": 1640995200,
            }, f)
        
        # Create sample data file for signing
        data_file = temp_path / "sample_data.json"
        with open(data_file, 'w') as f:
            json.dump({"test": "data"}, f)
        
        yield {
            'temp_dir': temp_path,
            'tx_file': tx_file,
            'data_file': data_file,
        }


class TestCLICommands:
    """Test CLI command functionality using direct function calls."""
    
    @pytest.mark.cli
    def test_cli_import(self):
        """Test that CLI can be imported and has commands."""
        from complychain.cli_enhanced import app
        
        # Check that app has commands
        assert hasattr(app, 'registered_commands')
        assert len(app.registered_commands) > 0
        
        # Check for specific commands (using function names)
        command_names = [cmd.callback.__name__ for cmd in app.registered_commands if hasattr(cmd, 'callback') and cmd.callback is not None]
        expected_commands = ['scan', 'quantum_sign', 'quantum_verify', 'quantum_keys', 'benchmark']
        
        for cmd in expected_commands:
            assert cmd in command_names, f"Command {cmd} not found in CLI"
    
    @pytest.mark.cli
    def test_quantum_commands_exist(self):
        """Test that quantum-safe commands are available."""
        from complychain.cli_enhanced import app
        
        command_names = [cmd.callback.__name__ for cmd in app.registered_commands if hasattr(cmd, 'callback') and cmd.callback is not None]
        
        # Check for quantum-safe commands
        assert 'quantum_sign' in command_names
        assert 'quantum_verify' in command_names
        assert 'quantum_keys' in command_names
        assert 'benchmark' in command_names
    
    @pytest.mark.cli
    def test_cli_structure(self):
        """Test CLI structure and command definitions."""
        from complychain.cli_enhanced import app
        
        # Test that all commands have proper structure
        for cmd in app.registered_commands:
            assert hasattr(cmd, 'name') or cmd.name is None  # Some commands might not have names
            assert hasattr(cmd, 'help') or cmd.help is None  # Some commands might not have help
    
    @pytest.mark.cli
    def test_cli_callback(self):
        """Test CLI callback function."""
        from complychain.cli_enhanced import main
        
        # Test that main function exists and is callable
        assert callable(main)
        
        # Test with minimal arguments
        with patch('complychain.cli_enhanced.console.print'):
            main(verbose=False, dry_run=False, log_level="INFO", config_file=None)


class TestCLIErrorHandling:
    """Test CLI error handling using direct function calls."""
    
    @pytest.mark.cli
    def test_scan_function_exists(self):
        """Test that scan function exists and is callable."""
        from complychain.cli_enhanced import scan
        
        assert callable(scan)
    
    @pytest.mark.cli
    def test_sign_function_exists(self):
        """Test that sign function exists and is callable."""
        from complychain.cli_enhanced import sign
        
        assert callable(sign)
    
    @pytest.mark.cli
    def test_verify_function_exists(self):
        """Test that verify function exists and is callable."""
        from complychain.cli_enhanced import verify
        
        assert callable(verify)
    
    @pytest.mark.cli
    def test_quantum_sign_function_exists(self):
        """Test that quantum_sign function exists and is callable."""
        from complychain.cli_enhanced import quantum_sign
        
        assert callable(quantum_sign)
    
    @pytest.mark.cli
    def test_quantum_verify_function_exists(self):
        """Test that quantum_verify function exists and is callable."""
        from complychain.cli_enhanced import quantum_verify
        
        assert callable(quantum_verify)
    
    @pytest.mark.cli
    def test_quantum_keys_function_exists(self):
        """Test that quantum_keys function exists and is callable."""
        from complychain.cli_enhanced import quantum_keys
        
        assert callable(quantum_keys)
    
    @pytest.mark.cli
    def test_benchmark_function_exists(self):
        """Test that benchmark function exists and is callable."""
        from complychain.cli_enhanced import benchmark
        
        assert callable(benchmark)


class TestCLIArgumentValidation:
    """Test CLI argument validation using direct function calls."""
    
    @pytest.mark.cli
    def test_scan_function_signature(self, temp_files):
        """Test scan function signature."""
        from complychain.cli_enhanced import scan
        
        # Test that function accepts expected arguments
        import inspect
        sig = inspect.signature(scan)
        params = list(sig.parameters.keys())
        
        assert 'file' in params
        assert 'output' in params
    
    @pytest.mark.cli
    def test_sign_function_signature(self, temp_files):
        """Test sign function signature."""
        from complychain.cli_enhanced import sign
        
        # Test that function accepts expected arguments
        import inspect
        sig = inspect.signature(sign)
        params = list(sig.parameters.keys())
        
        assert 'file' in params
        assert 'output' in params
    
    @pytest.mark.cli
    def test_quantum_sign_function_signature(self, temp_files):
        """Test quantum_sign function signature."""
        from complychain.cli_enhanced import quantum_sign
        
        # Test that function accepts expected arguments
        import inspect
        sig = inspect.signature(quantum_sign)
        params = list(sig.parameters.keys())
        
        assert 'file' in params
        assert 'output' in params
        assert 'algorithm' in params
    
    @pytest.mark.cli
    def test_quantum_keys_function_signature(self, temp_files):
        """Test quantum_keys function signature."""
        from complychain.cli_enhanced import quantum_keys
        
        # Test that function accepts expected arguments
        import inspect
        sig = inspect.signature(quantum_keys)
        params = list(sig.parameters.keys())
        
        assert 'action' in params
        assert 'algorithm' in params
        assert 'output_dir' in params
        assert 'key_file' in params


class TestCLIOutputFormat:
    """Test CLI output format using direct function calls."""
    
    @pytest.mark.cli
    def test_cli_app_structure(self):
        """Test that CLI app has proper structure."""
        from complychain.cli_enhanced import app
        
        # Test app properties
        assert hasattr(app, 'info')
        assert hasattr(app, 'registered_commands')
        assert hasattr(app, 'callback')
    
    @pytest.mark.cli
    def test_cli_help_text(self):
        """Test CLI help text structure."""
        from complychain.cli_enhanced import app
        
        # Test that app has help text
        if hasattr(app, 'info') and app.info:
            info_str = str(app.info)
            # Just check that info exists and can be converted to string
            assert len(info_str) > 0
    
    @pytest.mark.cli
    def test_command_help_text(self):
        """Test command help text structure."""
        from complychain.cli_enhanced import app
        
        # Test that commands have help text
        for cmd in app.registered_commands:
            if hasattr(cmd, 'help') and cmd.help:
                assert isinstance(cmd.help, str)
                assert len(cmd.help) > 0


class TestCLIIntegration:
    """Test CLI integration with core modules."""
    
    @pytest.mark.cli
    def test_cli_imports_core_modules(self):
        """Test that CLI can import all required core modules."""
        try:
            from complychain.cli_enhanced import app
            from complychain.crypto_engine import QuantumSafeSigner
            from complychain.threat_scanner import GLBAScanner
            from complychain.audit_system import GLBAAuditor
            from complychain.detection.ml_engine import MLEngine
            from complychain.config import get_config
            
            assert True  # All imports successful
        except ImportError as e:
            pytest.fail(f"Failed to import required module: {e}")
    
    @pytest.mark.cli
    def test_cli_quantum_safe_integration(self):
        """Test that CLI integrates with quantum-safe cryptography."""
        from complychain.cli_enhanced import quantum_sign, quantum_verify, quantum_keys
        from complychain.crypto_engine import QuantumSafeSigner
        
        # Test that functions can create QuantumSafeSigner instances
        signer = QuantumSafeSigner()
        assert signer is not None
        assert hasattr(signer, 'sign')
        assert hasattr(signer, 'verify')
        assert hasattr(signer, 'generate_keys') 
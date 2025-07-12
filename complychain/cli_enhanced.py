"""
Enhanced CLI for ComplyChain using Typer.

This module provides a modern CLI interface with new commands for
audit verification, key rotation, model training, and compliance checking.
"""

import json
import sys
import time
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config.logging_config import setup_logging, get_logger
from .config import get_config
from .exceptions import ComplyChainError
from .threat_scanner import GLBAScanner
from .crypto_engine import QuantumSafeSigner
from .audit_system import GLBAAuditor
from .detection.ml_engine import MLEngine

# Create Typer app
app = typer.Typer(
    name="complychain",
    help="Enterprise-grade GLBA compliance toolkit with quantum-safe cryptography",
    add_completion=False
)

# Rich console for better output
console = Console()
logger = get_logger(__name__)


def setup_cli_logging(log_level: str) -> None:
    """Set up CLI logging."""
    setup_logging(level=log_level.upper())


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Perform dry run without making changes"),
    log_level: str = typer.Option("INFO", "--log-level", help="Set log level (DEBUG/INFO/WARNING/ERROR)"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to configuration file")
):
    """ComplyChain - GLBA Compliance Toolkit."""
    setup_cli_logging(log_level)
    
    if verbose:
        console.print("[bold blue]ComplyChain[/bold blue] - GLBA Compliance Toolkit")
        console.print(f"Log level: {log_level}")
        console.print(f"Dry run: {dry_run}")
        if config_file:
            console.print(f"Config file: {config_file}")
    
    # Load configuration
    try:
        config = get_config(config_file)
        if verbose:
            console.print(f"Configuration loaded: {config.get('compliance.mode')} mode")
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)


@app.command()
def scan(
    file: Path = typer.Argument(..., help="Transaction file to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file for results")
):
    """Scan a transaction for threats and compliance."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning transaction...", total=None)
            
            # Load transaction
            with open(file, 'r') as f:
                transaction = json.load(f)
            
            # Initialize scanner
            scanner = GLBAScanner()
            
            # Perform scan
            result = scanner.scan(transaction)
            
            progress.update(task, completed=True)
        
        # Display results
        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print_json(data=result)
            
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)


@app.command()
def sign(
    file: Path = typer.Argument(..., help="File to sign"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output signature file")
):
    """Sign a file with quantum-safe cryptography."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Signing file...", total=None)
            
            # Load file content
            with open(file, 'rb') as f:
                data = f.read()
            
            # Initialize quantum-safe signer
            signer = QuantumSafeSigner()
            
            # Generate signature
            signature = signer.sign(data)
            
            progress.update(task, completed=True)
        
        # Save signature
        if output:
            with open(output, 'wb') as f:
                f.write(signature)
            console.print(f"[green]Signature saved to {output}[/green]")
        else:
            console.print(f"[green]Signature generated: {len(signature)} bytes[/green]")
            
    except Exception as e:
        console.print(f"[red]Signing failed: {e}[/red]")
        sys.exit(1)


@app.command()
def verify(
    file: Path = typer.Argument(..., help="File to verify"),
    signature: Path = typer.Argument(..., help="Signature file"),
    public_key: Optional[Path] = typer.Option(None, "--public-key", help="Public key file")
):
    """Verify a file signature."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Verifying signature...", total=None)
            
            # Load files
            with open(file, 'rb') as f:
                data = f.read()
            
            with open(signature, 'rb') as f:
                sig_data = f.read()
            
            # Initialize quantum-safe signer
            signer = QuantumSafeSigner()
            
            # Verify signature
            if public_key:
                with open(public_key, 'rb') as f:
                    pub_key = f.read()
                is_valid = signer.verify(data, sig_data, pub_key)
            else:
                is_valid = signer.verify(data, sig_data)
            
            progress.update(task, completed=True)
        
        if is_valid:
            console.print("[green]✓ Signature is valid[/green]")
        else:
            console.print("[red]✗ Signature is invalid[/red]")
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Verification failed: {e}[/red]")
        sys.exit(1)


@app.command()
def report(
    report_type: str = typer.Argument(..., help="Report type (daily/monthly/incident)"),
    output: Path = typer.Option(..., "--output", "-o", help="Output PDF file")
):
    """Generate compliance reports."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating report...", total=None)
            
            # Initialize auditor
            auditor = GLBAAuditor()
            
            # Generate report
            pdf_bytes = auditor.generate_report(report_type)
            
            progress.update(task, completed=True)
        
        # Write PDF to output file
        with open(output, 'wb') as f:
            f.write(pdf_bytes)
        console.print(f"[green]Report generated: {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Report generation failed: {e}[/red]")
        sys.exit(1)


@app.command()
def audit(
    action: str = typer.Argument(..., help="Audit action (verify/status)"),
    audit_file: Optional[Path] = typer.Option(None, "--file", help="Audit log file")
):
    """Audit log operations (not available in this release)."""
    console.print("[yellow]Audit log verification and status are not available in this release.[/yellow]")
    sys.exit(0)


@app.command()
def train_model(
    input_file: Path = typer.Argument(..., help="Training data file"),
    validation_file: Optional[Path] = typer.Option(None, "--validation", help="Validation data file"),
    model_path: Optional[Path] = typer.Option(None, "--model-path", help="Model output path")
):
    """Train ML model for threat detection."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Training ML model...", total=None)
            
            # Load training data
            with open(input_file, 'r') as f:
                training_data = json.load(f)
            
            validation_data = None
            if validation_file:
                with open(validation_file, 'r') as f:
                    validation_data = json.load(f)
            
            # Initialize ML engine
            ml_engine = MLEngine(model_path=model_path)
            
            # Train model
            metrics = ml_engine.train(training_data, validation_data)
            
            progress.update(task, completed=True)
        
        # Display metrics
        table = Table(title="Training Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        for key, value in metrics.items():
            table.add_row(key, f"{value:.4f}" if isinstance(value, float) else str(value))
        
        console.print(table)
        console.print("[green]✓ Model training completed[/green]")
        
    except Exception as e:
        console.print(f"[red]Model training failed: {e}[/red]")
        sys.exit(1)


@app.command()
def compliance(
    action: str = typer.Argument(..., help="Compliance action (show/check)"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Configuration file")
):
    """Compliance operations (partial support)."""
    if action == "show":
        config = get_config(config_file)
        # Show compliance table as before
        table = Table(title="GLBA Compliance Status")
        table.add_column("Section", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Implementation", style="green")
        glba_sections = [
            ("§314.4(c)(1)", "Data Encryption", "threat_scanner"),
            ("§314.4(c)(2)", "Access Controls", "crypto_engine"),
            ("§314.4(c)(3)", "Device Authentication", "audit_system"),
            ("§314.4(b)", "Audit Trails", "audit_system"),
            ("§314.4(d)", "Incident Response", "audit_system"),
            ("§314.4(f)", "Employee Training", "threat_scanner"),
        ]
        for section, description, module in glba_sections:
            status = "✓" if config.get(f"compliance.{section}", False) else "⚠"
            table.add_row(section, status, module)
        console.print(table)
    else:
        console.print("[yellow]Compliance check is not available in this release.[/yellow]")
        sys.exit(0)


@app.command()
def quantum_sign(
    file: Path = typer.Argument(..., help="File to sign with quantum-safe cryptography"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output signature file"),
    algorithm: str = typer.Option("dilithium3", "--algorithm", "-a", help="Quantum algorithm (dilithium3/falcon/sphincs+/rsa)")
):
    """Sign a file with quantum-safe cryptography (Dilithium3/Falcon/SPHINCS+ with RSA fallback)."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Signing with quantum-safe cryptography...", total=None)
            
            # Load file content
            with open(file, 'rb') as f:
                data = f.read()
            
            # Initialize quantum-safe signer
            signer = QuantumSafeSigner(algorithm=algorithm.upper())
            
            # Generate signature
            signature = signer.sign(data)
            
            progress.update(task, completed=True)
        
        # Save signature
        if output:
            with open(output, 'wb') as f:
                f.write(signature)
            console.print(f"[green]Quantum-safe signature saved to {output}[/green]")
        else:
            console.print(f"[green]Quantum-safe signature generated: {len(signature)} bytes[/green]")
            
    except Exception as e:
        console.print(f"[red]Quantum signing failed: {e}[/red]")
        sys.exit(1)


@app.command()
def quantum_verify(
    file: Path = typer.Argument(..., help="File to verify"),
    signature: Path = typer.Argument(..., help="Signature file"),
    public_key: Optional[Path] = typer.Option(None, "--public-key", help="Public key file")
):
    """Verify a file signature with quantum-safe cryptography."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Verifying quantum-safe signature...", total=None)
            
            # Load files
            with open(file, 'rb') as f:
                data = f.read()
            
            with open(signature, 'rb') as f:
                sig_data = f.read()
            
            # Initialize quantum-safe signer
            signer = QuantumSafeSigner()
            
            # Verify signature
            if public_key:
                with open(public_key, 'rb') as f:
                    pub_key = f.read()
                is_valid = signer.verify(data, sig_data, pub_key)
            else:
                is_valid = signer.verify(data, sig_data)
            
            progress.update(task, completed=True)
        
        if is_valid:
            console.print("[green]✓ Quantum-safe signature is valid[/green]")
        else:
            console.print("[red]✗ Quantum-safe signature is invalid[/red]")
            console.print("[yellow]Note: If using fallback RSA, ensure you're using the correct public key[/yellow]")
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Quantum verification failed: {e}[/red]")
        sys.exit(1)


@app.command()
def quantum_keys(
    action: str = typer.Argument(..., help="Key action (generate/export/import)"),
    algorithm: str = typer.Option("dilithium3", "--algorithm", "-a", help="Quantum algorithm (dilithium3/falcon/sphincs+/rsa)"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory for keys"),
    key_file: Optional[Path] = typer.Option(None, "--key-file", "-k", help="Key file for import/export")
):
    """Manage quantum-safe cryptographic keys."""
    try:
        signer = QuantumSafeSigner(algorithm=algorithm.upper())
        
        if action == "generate":
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Generating {algorithm} keys...", total=None)
                
                # Generate key pair
                private_key, public_key = signer.generate_keys()
                
                progress.update(task, completed=True)
            
            # Save keys
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
                private_path = output_dir / f"private_key_{algorithm}.pem"
                public_path = output_dir / f"public_key_{algorithm}.pem"
                
                with open(private_path, 'wb') as f:
                    f.write(private_key)
                with open(public_path, 'wb') as f:
                    f.write(public_key)
                
                console.print(f"[green]Keys generated and saved to {output_dir}[/green]")
                console.print(f"Private key: {private_path}")
                console.print(f"Public key: {public_path}")
            else:
                console.print(f"[green]{algorithm.upper()} keys generated[/green]")
                console.print(f"Private key: {len(private_key)} bytes")
                console.print(f"Public key: {len(public_key)} bytes")
        
        elif action == "export":
            if not key_file:
                console.print("[red]Key file required for export[/red]")
                sys.exit(1)
            
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            # Export in PEM format
            pem_data = signer.export_public_key_pem()
            
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
                export_path = output_dir / f"exported_key_{algorithm}.pem"
                with open(export_path, 'wb') as f:
                    f.write(pem_data.encode())
                console.print(f"[green]Key exported to {export_path}[/green]")
            else:
                console.print("[green]Key exported in PEM format[/green]")
                console.print(pem_data)
        
        elif action == "import":
            if not key_file:
                console.print("[red]Key file required for import[/red]")
                sys.exit(1)
            
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            # Import key
            signer.import_public_key_pem(key_data.decode())
            console.print(f"[green]Key imported successfully[/green]")
        
        else:
            console.print("[red]Invalid action. Use: generate, export, or import[/red]")
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Key operation failed: {e}[/red]")
        sys.exit(1)


@app.command()
def benchmark(
    samples: int = typer.Option(100, "--samples", "-s", help="Number of samples to test"),
    algorithm: str = typer.Option("dilithium3", "--algorithm", "-a", help="Algorithm to benchmark")
):
    """Run performance benchmarks for quantum-safe cryptography."""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Running {algorithm} benchmarks...", total=samples)
            
            signer = QuantumSafeSigner(algorithm=algorithm.upper())
            
            # Generate test data
            test_data = b"benchmark_test_data" * 1000
            
            # Benchmark key generation
            key_gen_times = []
            for i in range(min(samples, 10)):  # Limit key generation tests
                start_time = time.time()
                signer.generate_keys()
                key_gen_times.append(time.time() - start_time)
                progress.update(task, advance=1)
            
            # Benchmark signing
            sign_times = []
            for i in range(samples):
                start_time = time.time()
                signer.sign(test_data)
                sign_times.append(time.time() - start_time)
                progress.update(task, advance=1)
            
            progress.update(task, completed=True)
        
        # Calculate statistics
        avg_key_gen = sum(key_gen_times) / len(key_gen_times)
        avg_sign = sum(sign_times) / len(sign_times)
        
        # Display results
        table = Table(title=f"{algorithm.upper()} Performance Benchmark")
        table.add_column("Operation", style="cyan")
        table.add_column("Average Time (ms)", style="magenta")
        table.add_column("Samples", style="green")
        
        table.add_row("Key Generation", f"{avg_key_gen*1000:.2f}", str(len(key_gen_times)))
        table.add_row("Signing", f"{avg_sign*1000:.2f}", str(len(sign_times)))
        
        console.print(table)
        console.print("[green]✓ Benchmark completed[/green]")
        
    except Exception as e:
        console.print(f"[red]Benchmark failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    app() 
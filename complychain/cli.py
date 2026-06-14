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


def _resolve_keys(signer: QuantumSafeSigner, key_dir: Path = None) -> Path:
    """
    Load keys from key_dir (or default ~/.complychain/keys/).
    Generates and saves a new key pair if none exist yet.
    Returns the key directory used.
    """
    from .crypto_engine import DEFAULT_KEY_DIR
    keys_dir = Path(key_dir) if key_dir else DEFAULT_KEY_DIR
    algo_slug = signer.algorithm.lower().replace('-', '_').replace('+', 'plus')
    priv_path = keys_dir / f"private_key_{algo_slug}.pem"
    pub_path = keys_dir / f"public_key_{algo_slug}.pem"

    if priv_path.exists() and pub_path.exists():
        signer.import_private_key_pem(priv_path.read_text())
        signer.import_public_key_pem(pub_path.read_text())
        console.print(f"[blue]Using existing keys from {keys_dir}[/blue]")
    else:
        console.print(f"[yellow]No keys found — generating new {signer.algorithm} key pair...[/yellow]")
        signer.generate_keys()
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path.write_text(signer.export_private_key_pem())
        pub_path.write_text(signer.export_public_key_pem())
        # Restrict private key permissions
        priv_path.chmod(0o600)
        console.print(f"[green]Keys saved to {keys_dir}[/green]")
        console.print(f"  Private key: {priv_path}")
        console.print(f"  Public key:  {pub_path}")

    return keys_dir


@app.command()
def sign(
    file: Path = typer.Argument(..., help="File to sign"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output signature file"),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Key directory (default: ~/.complychain/keys/)"),
):
    """Sign a file with quantum-safe cryptography (GLBA §314.4(c)(3))."""
    try:
        with open(file, 'rb') as f:
            data = f.read()

        signer = QuantumSafeSigner()
        _resolve_keys(signer, key_dir)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Signing with {signer.algorithm}...", total=None)
            signature = signer.sign(data)
            progress.update(task, completed=True)

        if output:
            with open(output, 'wb') as f:
                f.write(signature)
            console.print(f"[green]Signature saved to {output}[/green]")
        else:
            console.print(f"[green]Signature generated: {len(signature)} bytes ({signer.algorithm})[/green]")

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
            ("§314.4(b)",    "Risk Assessment",                   "glba_engine"),
            ("§314.4(c)(1)", "Access Controls",                   "threat_scanner"),
            ("§314.4(c)(2)", "Data Inventory",                    "—"),
            ("§314.4(c)(3)", "Data Encryption (FIPS 204)",        "crypto_engine"),
            ("§314.4(c)(4)", "Secure Development Practices",      "pyproject.toml"),
            ("§314.4(c)(5)", "Multi-Factor Authentication",       "—"),
            ("§314.4(c)(6)", "Data Disposal",                     "—"),
            ("§314.4(c)(7)", "Change Management",                 "—"),
            ("§314.4(c)(8)", "Audit Trails & Activity Monitoring","audit_system"),
            ("§314.4(d)",    "Testing and Monitoring",            "ml_engine"),
            ("§314.4(e)",    "Employee Training",                 "—"),
            ("§314.4(f)",    "Vendor Management",                 "—"),
            ("§314.4(h)",    "Incident Response Plan",            "audit_system"),
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
    algorithm: str = typer.Option("dilithium3", "--algorithm", "-a", help="Quantum algorithm (dilithium3/rsa)"),
    key_dir: Optional[Path] = typer.Option(None, "--key-dir", help="Key directory (default: ~/.complychain/keys/)"),
):
    """Sign a file with FIPS 204 / ML-DSA (Dilithium3) or RSA-4096 fallback (GLBA §314.4(c)(3))."""
    try:
        with open(file, 'rb') as f:
            data = f.read()

        signer = QuantumSafeSigner(algorithm=algorithm.upper())
        _resolve_keys(signer, key_dir)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Signing with {signer.algorithm}...", total=None)
            signature = signer.sign(data)
            progress.update(task, completed=True)

        if output:
            with open(output, 'wb') as f:
                f.write(signature)
            console.print(f"[green]Quantum-safe signature saved to {output}[/green]")
        else:
            console.print(f"[green]Quantum-safe signature generated: {len(signature)} bytes ({signer.algorithm})[/green]")

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


@app.command()
def sanctions_status():
    """Show OFAC/FinCEN sanctions data verification status and live source connectivity."""
    import os
    from .threat_scanner import SanctionsVerificationStatus

    scanner = GLBAScanner()
    fincen_key = os.environ.get("COMPLYCHAIN_FINCEN_API_KEY")

    table = Table(title="Sanctions Data Status (GLBA §314.4(c)(1))")
    table.add_column("Source", style="cyan")
    table.add_column("Status", style="magenta")

    status_str = scanner._sanctions_status.value if scanner._sanctions_status else "UNKNOWN"
    table.add_row("Sanctions cache", status_str)
    table.add_row("OFAC SDN List", "configured (live on next load)")
    table.add_row("UNSC Consolidated List", "configured (live on next load)")
    table.add_row("UK Sanctions List", "configured (live on next load)")
    table.add_row(
        "FinCEN BSA API Key",
        "configured" if fincen_key else "not set — set COMPLYCHAIN_FINCEN_API_KEY",
    )
    console.print(table)

    if not fincen_key:
        console.print(
            "[yellow]⚠ FinCEN BSA live data requires COMPLYCHAIN_FINCEN_API_KEY.[/yellow]"
        )
        console.print(
            "[yellow]  Export it before running: export COMPLYCHAIN_FINCEN_API_KEY=<your_key>[/yellow]"
        )
    else:
        console.print("[green]✓ FinCEN API key is set — live BSA data will be fetched.[/green]")


# ---------------------------------------------------------------------------
# regulations sub-app
# ---------------------------------------------------------------------------

regulations_app = typer.Typer(
    name="regulations",
    help="Multi-regulation compliance management (GLBA, PCI-DSS, DORA, SOC 2)",
    add_completion=False,
)
app.add_typer(regulations_app, name="regulations")


def _build_profile(
    profile_name: str,
    jurisdiction: str,
    entity_type: str,
    processes_cards: bool,
    eu_nexus: bool,
) -> "InstitutionProfile":
    from .regulations.base import InstitutionProfile
    return InstitutionProfile(
        name=profile_name,
        jurisdiction=jurisdiction,
        entity_type=entity_type,
        processes_card_payments=processes_cards,
        eu_nexus=eu_nexus,
    )


@regulations_app.command("list")
def regulations_list(
    profile_name: str = typer.Option("My Institution", "--profile-name", "-n"),
    jurisdiction: str = typer.Option("US", "--jurisdiction", "-j"),
    entity_type: str = typer.Option("fintech", "--entity-type", "-e"),
    processes_cards: bool = typer.Option(False, "--processes-cards/--no-processes-cards"),
    eu_nexus: bool = typer.Option(False, "--eu-nexus/--no-eu-nexus"),
    show_all: bool = typer.Option(False, "--all", help="Show all regulations, not just applicable ones"),
) -> None:
    """List available compliance regulations and their applicability."""
    from .regulations.registry import default_registry

    profile = _build_profile(profile_name, jurisdiction, entity_type, processes_cards, eu_nexus)
    all_regs = default_registry.list_all()

    table = Table(title=f"Available Regulations — {profile_name} ({jurisdiction})")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Regulation", style="white")
    table.add_column("Version", style="dim")
    table.add_column("Applicable", style="magenta")

    for reg in all_regs:
        applicable = reg.is_applicable(profile)
        if not show_all and not applicable:
            continue
        table.add_row(
            reg.regulation_id,
            reg.regulation_name,
            reg.version,
            "[green]YES[/green]" if applicable else "[red]NO[/red]",
        )
    console.print(table)


@regulations_app.command("assess")
def regulations_assess(
    regulation_id: Optional[str] = typer.Argument(
        None,
        help="Regulation ID to assess (glba, pci_dss, dora, soc2). Omit to assess all applicable.",
    ),
    profile_name: str = typer.Option("My Institution", "--profile-name", "-n"),
    jurisdiction: str = typer.Option("US", "--jurisdiction", "-j"),
    entity_type: str = typer.Option("fintech", "--entity-type", "-e"),
    processes_cards: bool = typer.Option(False, "--processes-cards/--no-processes-cards"),
    eu_nexus: bool = typer.Option(False, "--eu-nexus/--no-eu-nexus"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report to file"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
) -> None:
    """Run a compliance assessment for one or all applicable regulations."""
    from .regulations.registry import default_registry
    from .regulations.base import ComplianceStatus

    profile = _build_profile(profile_name, jurisdiction, entity_type, processes_cards, eu_nexus)

    if regulation_id:
        reg = default_registry.get(regulation_id)
        if reg is None:
            console.print(f"[red]Unknown regulation: '{regulation_id}'[/red]")
            console.print(f"Available: {', '.join(r.regulation_id for r in default_registry.list_all())}")
            sys.exit(1)
        reports = {regulation_id: reg.assess(profile)}
    else:
        reports = {
            rid: report
            for rid, report in default_registry.assess_all(profile).items()
            if report.applicable
        }

    if fmt == "json":
        payload = {rid: r.to_dict() for rid, r in reports.items()}
        if output:
            output.write_text(__import__("json").dumps(payload, indent=2))
            console.print(f"[green]✓ Report written to {output}[/green]")
        else:
            print(__import__("json").dumps(payload, indent=2))
        return

    _status_colour = {
        ComplianceStatus.COMPLIANT:     "green",
        ComplianceStatus.PARTIAL:       "yellow",
        ComplianceStatus.NON_COMPLIANT: "red",
        ComplianceStatus.PENDING:       "dim",
        ComplianceStatus.NOT_APPLICABLE: "dim",
    }

    for rid, report in reports.items():
        colour = _status_colour.get(report.overall_status, "white")
        table = Table(
            title=f"{report.regulation_name} — {profile_name}",
            show_lines=True,
        )
        table.add_column("Control", style="cyan", no_wrap=True)
        table.add_column("Title", style="white")
        table.add_column("Status", no_wrap=True)
        table.add_column("Findings", style="dim")

        for ctrl in report.controls.values():
            c = _status_colour.get(ctrl.status, "white")
            table.add_row(
                ctrl.control_id,
                ctrl.title[:60],
                f"[{c}]{ctrl.status.value}[/{c}]",
                "; ".join(ctrl.findings[:2]),
            )

        console.print(table)
        console.print(
            f"  Overall: [{colour}]{report.overall_status.value}[/{colour}]"
            f"  |  Risk score: {report.risk_score:.2f}"
        )

    if output:
        payload = {rid: r.to_dict() for rid, r in reports.items()}
        output.write_text(__import__("json").dumps(payload, indent=2))
        console.print(f"[green]✓ Report written to {output}[/green]")

    # Persist results and emit events
    try:
        import uuid as _uuid
        from .persistence import AssessmentStore
        from .events import default_bus, Event, EventType as _ET

        store = AssessmentStore()
        run_id = str(_uuid.uuid4())
        for rid, report in reports.items():
            store.save(report, run_id=run_id)
            prev = store.previous(rid)
            default_bus.emit(Event(_ET.ASSESSMENT_COMPLETED, {
                "regulation": rid,
                "risk_score": report.risk_score,
                "status": report.overall_status.value,
            }))
            if prev and prev.overall_status != report.overall_status.value:
                default_bus.emit(Event(_ET.COMPLIANCE_STATUS_CHANGED, {
                    "regulation": rid,
                    "old_status": prev.overall_status,
                    "status": report.overall_status.value,
                }))
    except Exception:
        pass


@regulations_app.command("history")
def regulations_history(
    regulation: Optional[str] = typer.Option(None, "--regulation", "-r",
                                              help="Filter by regulation ID (glba, pci_dss, dora, soc2)"),
    days: int = typer.Option(30, "--days", "-d", help="Look-back window in days"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
) -> None:
    """Show assessment history from the local store."""
    from .persistence import AssessmentStore

    store = AssessmentStore()
    records = store.query(regulation_id=regulation, days=days)

    if not records:
        console.print("[yellow]No assessment history found for the given filter.[/yellow]")
        return

    if fmt == "json":
        print(__import__("json").dumps(
            [{"run_id": r.run_id, "regulation_id": r.regulation_id,
              "assessed_at": r.assessed_at, "overall_status": r.overall_status,
              "risk_score": r.risk_score} for r in records],
            indent=2,
        ))
        return

    table = Table(title=f"Assessment History (last {days} days)")
    table.add_column("Date", style="dim")
    table.add_column("Regulation", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Risk Score", justify="right")

    _colours = {"COMPLIANT": "green", "PARTIAL": "yellow",
                "NON_COMPLIANT": "red", "PENDING": "dim", "NOT_APPLICABLE": "dim"}
    for rec in records:
        c = _colours.get(rec.overall_status, "white")
        table.add_row(
            rec.assessed_at[:19],
            rec.regulation_id,
            f"[{c}]{rec.overall_status}[/{c}]",
            f"{rec.risk_score:.3f}",
        )
    console.print(table)


@regulations_app.command("diff")
def regulations_diff(
    regulation: str = typer.Option(..., "--regulation", "-r",
                                   help="Regulation ID to diff (e.g. glba)"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
) -> None:
    """Show what changed between the last two assessments for a regulation."""
    from .persistence import AssessmentStore

    store = AssessmentStore()
    diff = store.diff(regulation)

    if diff is None:
        console.print(
            f"[yellow]Not enough history for '{regulation}' — run assess at least twice.[/yellow]"
        )
        return

    if fmt == "json":
        print(__import__("json").dumps({
            "regulation_id": diff.regulation_id,
            "old_assessed_at": diff.old_assessed_at,
            "new_assessed_at": diff.new_assessed_at,
            "risk_delta": diff.risk_delta,
            "status_changed": diff.status_changed,
            "controls": [
                {"control_id": c.control_id, "old_status": c.old_status,
                 "new_status": c.new_status, "changed": c.changed}
                for c in diff.control_diffs
            ],
        }, indent=2))
        return

    delta_colour = "red" if diff.risk_delta > 0 else "green"
    console.print(
        f"  {diff.regulation_id.upper()} diff: "
        f"{diff.old_assessed_at[:19]} → {diff.new_assessed_at[:19]}  |  "
        f"Risk delta: [{delta_colour}]{diff.risk_delta:+.3f}[/{delta_colour}]  |  "
        f"Status changed: {'YES' if diff.status_changed else 'no'}"
    )

    if diff.control_diffs:
        table = Table(show_lines=True)
        table.add_column("Control", style="cyan", no_wrap=True)
        table.add_column("Old Status", style="dim")
        table.add_column("New Status")
        table.add_column("Changed")
        _colours = {"COMPLIANT": "green", "PARTIAL": "yellow",
                    "NON_COMPLIANT": "red", "PENDING": "dim"}
        for c in diff.control_diffs:
            if not c.changed:
                continue
            nc = _colours.get(c.new_status or "", "white")
            table.add_row(
                c.control_id,
                c.old_status or "—",
                f"[{nc}]{c.new_status or '—'}[/{nc}]",
                ":heavy_check_mark:" if c.changed else "",
            )
        console.print(table)


if __name__ == "__main__":
    app()
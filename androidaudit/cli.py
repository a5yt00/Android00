from __future__ import annotations

import click
import time
from pathlib import Path
from rich.console import Console

from androidaudit.session import ADBSession
from androidaudit.exceptions import AndroidAuditError

# Import modules
from androidaudit.modules.static.apk_parser import parse_apk, decompile_apk
from androidaudit.modules.static.manifest import audit_manifest
from androidaudit.modules.static.secret_scan import scan_secrets
from androidaudit.modules.static.crypto_check import scan_crypto
from androidaudit.modules.dynamic.frida_runner import FridaRunner
from androidaudit.modules.network.mitm import run_mitm
from androidaudit.modules.network.ssl_setup import SSLSetup
from androidaudit.modules.storage.puller import pull_storage
from androidaudit.modules.storage.inspector import inspect_storage
from androidaudit.report.engine import ReportEngine
from androidaudit.findings import Finding

console = Console()

@click.group()
def cli() -> None:
    """AndroidAudit: A professional Android Pentesting CLI tool."""
    pass

@cli.command()
@click.option("--package", "-p", required=True, help="Target package name")
@click.option("--output", "-o", default="./reports", help="Output directory")
@click.option("--skip", multiple=True, help="Modules to skip")
def run(package: str, output: str, skip: tuple[str, ...]) -> None:
    """Run the exhaustive AndroidAudit pipeline."""
    console.print(f"[bold green]Starting full audit for {package}[/bold green]")
    session = ADBSession()
    session.connect()
    
    findings: list[Finding] = []
    
    apk_path = session.get_apk_path(package)
    if not apk_path:
        console.print(f"[red]Package {package} not found on the device.[/red]")
        return
        
    local_apk = Path(output) / f"{package}.apk"
    Path(output).mkdir(parents=True, exist_ok=True)
    
    console.print(f"[cyan]Pulling APK from {apk_path}...[/cyan]")
    session.pull(apk_path, local_apk)
    
    if "static" not in skip:
        console.print("[cyan]Running static analysis...[/cyan]")
        findings.extend(audit_manifest(local_apk))
        
        # Decompile for deep scan
        src_dir = Path(output) / f"{package}_src"
        decompile_apk(local_apk, src_dir)
        findings.extend(scan_secrets(src_dir))
        findings.extend(scan_crypto(src_dir))
        
    if "network" not in skip:
        console.print("[cyan]Setting up network interception...[/cyan]")
        import queue
        import threading
        mitm_queue = queue.Queue()
        mitm_thread = threading.Thread(target=run_mitm, args=(mitm_queue,), daemon=True)
        mitm_thread.start()
        ssl_setup = SSLSetup(session)
        ssl_setup.setup_proxy_and_cert()
        
    if "dynamic" not in skip:
        console.print("[cyan]Starting Frida dynamic analysis...[/cyan]")
        try:
            frida_runner = FridaRunner(session, package)
            frida_runner.attach()
            try:
                frida_runner.run_script("ssl_pinning_bypass")
                frida_runner.run_script("root_detection_bypass")
            except Exception as e:
                console.print(f"[yellow]Failed to load scripts: {e}[/yellow]")
            time.sleep(5)
            for msg in frida_runner.get_messages():
                if msg.get('type') == 'send':
                    payload = msg.get('payload', {})
                    findings.append(Finding(
                        id=f"DYN-{len(findings) + 1}",
                        title=payload.get("title", 'Frida Hook Event'),
                        severity=Severity.MEDIUM,
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        cvss_score=0.0,
                        owasp_category="M7: Client Code Quality",
                        description=str(payload.get("description", payload)),
                        evidence="Dynamic hook trace",
                        remediation="Ensure dynamically detected flows are intentional.",
                        module="dynamic.frida"
                    ))
            frida_runner.detach()
        except Exception as e:
            console.print(f"[bold yellow]Skipping dynamic analysis. Reason: {e}[/bold yellow]")
        
    if "storage" not in skip:
        console.print("[cyan]Pulling storage...[/cyan]")
        storage_dir = Path(output) / f"{package}_storage"
        pull_storage(session, package, storage_dir)
        
        findings.extend(inspect_storage(storage_dir))
        
    if "network" not in skip:
        # Drain network queue
        while not mitm_queue.empty():
            findings.append(mitm_queue.get())

    console.print("[bold green]Generating Report...[/bold green]")
    engine = ReportEngine(Path(output))
    engine.generate_html(findings, package, "report.html")
    console.print(f"Report saved to {Path(output) / 'report.html'}")

@cli.command()
@click.option("--apk", required=True, help="Path to APK file")
@click.option("--output", default="./reports", help="Output directory")
def static(apk: str, output: str) -> None:
    """Run static analysis on an APK."""
    console.print(f"[bold cyan]Running static analysis on {apk}[/bold cyan]")
    Path(output).mkdir(parents=True, exist_ok=True)
    findings = audit_manifest(Path(apk))
    src_dir = Path(output) / "src_decompiled"
    decompile_apk(Path(apk), src_dir)
    findings.extend(scan_secrets(src_dir))
    findings.extend(scan_crypto(src_dir))
    engine = ReportEngine(Path(output))
    engine.generate_html(findings, package, "static_report.html")

@cli.command()
@click.option("--package", required=True, help="Target package name")
@click.option("--scripts", help="Comma-separated list of scripts (e.g., ssl,root,bio)")
@click.option("--duration", type=int, default=60, help="Duration in seconds")
def dynamic(package: str, scripts: str | None, duration: int) -> None:
    """Run dynamic analysis (Frida instrumentation)."""
    console.print(f"[bold cyan]Running dynamic analysis on {package}[/bold cyan]")
    session = ADBSession()
    session.connect()
    runner = FridaRunner(session, package)
    runner.attach()
    if scripts:
        for s in scripts.split(","):
            runner.run_script(s.strip())
    time.sleep(duration)
    runner.detach()

@cli.command()
@click.option("--package", required=True, help="Target package name")
@click.option("--duration", type=int, default=60, help="Duration in seconds")
def network(package: str, duration: int) -> None:
    """Run network interception using mitmproxy."""
    console.print(f"[bold cyan]Running network interception for {package}[/bold cyan]")
    session = ADBSession()
    session.connect()
    import queue
    import threading
    mitm_queue = queue.Queue()
    mitm_thread = threading.Thread(target=run_mitm, args=(mitm_queue,), daemon=True)
    mitm_thread.start()
    ssl_setup = SSLSetup(session)
    ssl_setup.setup_proxy_and_cert()
    time.sleep(duration)
    # Stop is unhandled gracefully in scripts, typical daemon thread exit
    ssl_setup.cleanup()

@cli.command()
@click.option("--package", required=True, help="Target package name")
@click.option("--output", default="./reports", help="Output directory")
def storage(package: str, output: str) -> None:
    """Run storage forensics."""
    console.print(f"[bold cyan]Running storage forensics on {package}[/bold cyan]")
    session = ADBSession()
    session.connect()
    storage_dir = Path(output) / package
    pull_storage(session, package, storage_dir)
    findings = inspect_storage(storage_dir)
    engine = ReportEngine(Path(output))
    engine.generate_html(findings, package, "storage_report.html")

@cli.command()
@click.option("--session", required=True, help="Path to session directory")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "md"]), default="html", help="Report format")
@click.option("--output", help="Output file path")
def report(session: str, fmt: str, output: str | None) -> None:
    """Generate pentest reports from existing session data."""
    console.print(f"[bold magenta]Generating {fmt} report from {session}[/bold magenta]")
    # TODO: Load raw findings and generate templates

@cli.command("devices")
def list_devices() -> None:
    """List connected ADB devices."""
    try:
        session = ADBSession()
        devices = session.client.devices()
        if not devices:
            console.print("[red]No devices found.[/red]")
            return
        console.print("[bold]Connected Devices:[/bold]")
        for d in devices:
            console.print(f" - {d.serial}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@cli.command("push-frida")
def push_frida_cmd() -> None:
    """Manually push frida-server to the connected device."""
    console.print("[cyan]Pushing frida-server...[/cyan]")
    session = ADBSession()
    session.connect()
    # It pushes automatically on connect

@cli.command()
@click.option("--cmd", required=True, help="Command to run via ADB shell")
def shell(cmd: str) -> None:
    """Run arbitrary ADB shell cmd via ADBSession."""
    try:
        session = ADBSession()
        session.connect()
        output = session.shell(cmd)
        console.print(output)
    except AndroidAuditError as e:
        console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    cli()

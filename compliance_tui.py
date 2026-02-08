import time, os, argparse
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

# Import your refined engine
from audit_engine import NextGenAuditor 

console = Console()

def generate_dashboard(results):
    """Creates the SOC 2 Matrix Table."""
    table = Table(title="Compliance Readiness Matrix (Internal Audit)", expand=True)
    table.add_column("Series", style="cyan", no_wrap=True)
    table.add_column("Control ID", style="magenta")
    table.add_column("Control Objective", style="white")
    table.add_column("Status", justify="center")

    # Mapping scan results to the Matrix
    for finding in results.get("findings", []):
        status_text = "[bold green]PASS[/bold green]" if finding["status"] == "PASS" else "[bold red]FAIL[/bold red]"
        
        table.add_row(
            # finding.get("type", "Logic"),
            finding["id"],
            finding.get("control", "Check"),
            status_text
        )

    # 2. Coverage Stats
    meta = results.get("metadata", {})
    count = meta.get("files_scanned", 0)
    path = meta.get("target_path", "Unknown")
    
    # Audit Integrity Check
    if count == 0:
        coverage_str = f"[bold red]CRITICAL: 0 Files Scanned. Audit Inconclusive![/bold red]"
    else:
        coverage_str = f"[bold green]Coverage:[/bold green] {count} files analyzed in [blue]{path}[/blue]"

    # 3. Assemble Layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=5)
    )

    layout["header"].update(Panel(
        Text(f"Automated Governance | {meta.get('scan_time')}", justify="center", style="bold white"),
        style="blue"
    ))
    
    layout["main"].update(table)
    
    layout["footer"].update(Panel(
        Text.from_markup(f"{coverage_str}\n[dim]Press Ctrl+C to stop background monitoring[/dim]"),
        title="Audit Integrity & Coverage", border_style="white"
    ))
    
    return layout

def run_tui(target_path="."):
    auditor = NextGenAuditor(target_path)
    
    with Live(console=console, screen=True, refresh_per_second=1) as live:
        while True:
            auditor.results = {"metadata": {}, "stats": {"pass": 0, "fail": 0}, "findings": []}
            auditor.audit_git()
            auditor.audit_logic()
            
            live.update(generate_dashboard(auditor.results))
            live.refresh()
            time.sleep(5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NGG Live Dashboard")
    parser.add_argument("target", help="Path to the project root")
    args = parser.parse_args()

    try:
        # run_tui()
        run_tui(target_path=args.target)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Exiting Governance Dashboard...[/bold yellow]")

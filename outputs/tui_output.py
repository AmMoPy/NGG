import time
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.console import Console
from engine import AuditEngine
from outputs.base_output import BaseOutput
from models.base_models import AuditResultsSummary


class TUIOutput(BaseOutput):
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.console = Console()


    def render(self, audit_engine: AuditEngine):
        """
        Starts the Rich Live dashboard loop.
        This should be called from the main script if TUI is desired,
        passing a function that fetches the latest results.
        """
        self.logger.info("Starting TUI dashboard loop...")
        with Live(console=self.console, screen=True, refresh_per_second=1) as live:
            try:
                while True:
                    # Get the latest results from the provided function
                    results = audit_engine.run(live = True)
                    # Update the live display with current results
                    live.update(self.generate_dashboard(results))
                    live.refresh()
                    time.sleep(60)
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Stopping TUI Dashboard...[/bold yellow]")
                self.logger.info("TUI dashboard loop interrupted.")
        self.logger.info("TUI dashboard loop ended.")


    def generate_dashboard(self, results: AuditResultsSummary): # Separate dashboard generation
        """Creates the SOC 2 Matrix Table using Rich."""
        table = Table(title="Compliance Readiness Matrix (Internal Audit)", expand=True)
        table.add_column("Control ID", style="magenta", no_wrap=True)
        table.add_column("Control Objective", style="white")
        table.add_column("Type", style="cyan")
        table.add_column("Status", justify="center")

        for finding in results.findings: # Iterate over Pydantic objects directly
            status_text = (
                "[bold green]PASS[/bold green]" if finding.status == "PASS" else
                "[bold yellow]ERROR[/bold yellow]" if finding.status == "ERROR" else
                "[bold red]FAIL[/bold red]"
            )
            table.add_row(
                finding.id, # Access attributes directly
                finding.control,
                finding.type.value, # Use .value for enum
                status_text
            )

        meta = results.metadata
        count = meta.get("files_scanned", 0)
        path = meta.get("target_path", "Unknown")
        scan_time = meta.get("scan_time", "N/A")

        if count == 0:
            coverage_str = "[bold red]CRITICAL: 0 Files Scanned. Audit Inconclusive![/bold red]"
        else:
            coverage_str = f"[bold green]Coverage:[/bold green] {count} files analyzed in [blue]{path}[/blue]"

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=6)
        )

        layout["header"].update(Panel(
            Text(f"Automated Governance | {scan_time}", justify="center", style="bold white"),
            style="blue"
        ))

        layout["main"].update(table)

        layout["footer"].update(Panel(
            Text.from_markup(
                f"{coverage_str}\n[dim]Status: {results.stats['pass']} PASS / {results.stats['fail']} FAIL\n"
                f"[dim]Integrity Hash: {results.metadata['integrity_hash']}\n[dim]Press Ctrl+C to exit[/dim]"
            ),
            title="Audit Integrity & Coverage",
            border_style="white"
        ))

        return layout


# The __plugin__ pattern, tells loader to looks for one specific variable name
# It can be named anything, but __plugin__ is common
__plugin__ = TUIOutput
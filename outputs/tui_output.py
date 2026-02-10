import time
import queue
import threading
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.console import Console
from outputs.base_output import BaseOutput
from models.base_models import AuditResultsSummary
from engine import AuditEngine


class TUIOutput(BaseOutput):
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.console = Console()
        self.results_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.current_results: AuditResultsSummary = AuditResultsSummary(
            findings=[], stats={"pass": 0, "fail": 0}, metadata={}
        )


    def _run_audit_loop(self):
        """Background thread function to run audits periodically."""
        while not self.stop_event.is_set():
            try:
                # Create a new engine instance for each run
                engine = AuditEngine(self.config.config_file_path)
                engine.run() # This populates engine.results
                # Put the Pydantic summary object into the queue
                self.results_queue.put(engine.results)
                self.logger.info("TUI: Results put into queue.")
            except Exception as e:
                self.logger.error(f"TUI Output audit loop failed: {e}")
            self.stop_event.wait(timeout=5)


    def render(self, initial_results):
        """
        Starts the TUI dashboard loop.
        """
        audit_thread = threading.Thread(target=self._run_audit_loop, daemon=True)
        audit_thread.start()

        def generate_dashboard(results: AuditResultsSummary): # Type hint for clarity
            """Creates the SOC 2 Matrix Table."""
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
                    finding.id,
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
                    f"{coverage_str}\n[dim]Status: {results.stats['pass']} PASS / {results.stats['fail']} FAIL\n[dim]Press Ctrl+C to exit[/dim]"
                ),
                title="Audit Integrity & Coverage",
                border_style="white"
            ))

            return layout

        self.logger.info("TUI: Starting dashboard render loop.")

        with Live(console=self.console, screen=True, refresh_per_second=1) as live:
            try:
                while not self.stop_event.is_set():
                    try:
                        new_results: AuditResultsSummary = self.results_queue.get_nowait()
                        self.current_results = new_results
                        # self.logger.info("Audit cycle completed, results queued")
                    except queue.Empty:
                        # self.logger.info("Audit cycle failed, empty queue")
                        pass

                    live.update(generate_dashboard(self.current_results))
                    live.refresh()
                    time.sleep(5)

            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]Stopping TUI Dashboard...[/bold yellow]")
                self.stop_event.set()

        audit_thread.join(timeout=2)
        
        if audit_thread.is_alive():
            self.logger.warning("Audit thread did not stop gracefully.")
        else:
            self.logger.info("TUI Dashboard stopped.")


# The __plugin__ pattern, tells loader to looks for one specific variable name
# It can be named anything, but __plugin__ is common
__plugin__ = TUIOutput
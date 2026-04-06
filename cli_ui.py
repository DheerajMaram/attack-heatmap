"""Rich-based CLI presentation (quiet vs verbose)."""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class PipelineUI:
    """quiet=False: full Rich output. quiet=True: only info_always() prints."""

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.console = Console()  # used by Progress in main

    def rule(self, title: str, style: str = "bold blue") -> None:
        if self.quiet:
            return
        self.console.rule(f"[{style}]{title}[/{style}]")

    def panel(self, body: str, title: str, style: str = "blue") -> None:
        if self.quiet:
            return
        self.console.print(Panel(body, title=title, border_style=style))

    def print(self, *args, **kwargs) -> None:
        if self.quiet:
            return
        self.console.print(*args, **kwargs)

    def info_always(self, *args, **kwargs) -> None:
        """Printed even in quiet mode (errors, final paths)."""
        self.console.print(*args, **kwargs)

    def summary_table(self, rows: list) -> None:
        if self.quiet:
            return
        t = Table(show_header=True, header_style="bold magenta")
        t.add_column("Item", style="dim")
        t.add_column("Value", justify="right")
        for a, b in rows:
            t.add_row(str(a), str(b))
        self.console.print(t)

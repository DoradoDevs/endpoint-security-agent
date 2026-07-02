"""
Sentinel Agent — TUI Dashboard Panel Renderers

Rich-based panel rendering functions for the interactive terminal dashboard.
Each function takes TUIState and returns a Rich renderable for display
in the Live layout.
"""

from __future__ import annotations

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.columns import Columns
from rich import box

from core import __version__, __product__
from tui.state import TUIState


_SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def _severity_style(severity: str) -> str:
    """Return a Rich style string for the given severity level."""
    return _SEVERITY_STYLES.get(severity.lower(), "white")


def _grade_style(grade: str) -> str:
    """Return a Rich style string for a risk grade."""
    if grade.startswith("A"):
        return "bold green"
    if grade == "B":
        return "bold cyan"
    if grade == "C":
        return "bold yellow"
    if grade == "D":
        return "bold dark_orange"
    return "bold red"


def _score_style(score: float) -> str:
    """Return a Rich style string for a risk score."""
    if score <= 15:
        return "bold green"
    if score <= 30:
        return "green"
    if score <= 45:
        return "bold cyan"
    if score <= 60:
        return "bold yellow"
    if score <= 75:
        return "bold dark_orange"
    return "bold red"


def render_header(state: TUIState) -> Panel:
    """Render the header with product name and status."""
    header = Text()
    header.append(f"  {__product__}", style="bold cyan")
    header.append(f"  v{__version__}", style="dim")
    header.append("  |  ", style="dim")

    # Panel tabs
    for i, name in enumerate(state.panel_names):
        if i == state.active_panel:
            header.append(f" [{name}] ", style="bold white on blue")
        else:
            header.append(f"  {name}  ", style="dim")

    header.append("  |  ", style="dim")

    # Status
    if state.scan_in_progress:
        header.append(state.status_message, style="bold yellow")
    elif "failed" in state.status_message.lower():
        header.append(state.status_message, style="bold red")
    else:
        header.append(state.status_message, style="green")

    if state.last_scan_time:
        header.append(f"  (last scan: {state.last_scan_time})", style="dim")

    return Panel(header, box=box.HEAVY, border_style="cyan", height=3)


def render_overview(state: TUIState) -> Panel:
    """Render risk score, grade, and severity summary."""
    layout = Layout()
    layout.split_row(
        Layout(name="score", ratio=1),
        Layout(name="breakdown", ratio=2),
    )

    # Left side: big risk score and grade
    score_text = Text(justify="center")
    score_text.append("\n")
    score_text.append("RISK SCORE\n", style="bold dim")
    score_text.append(f"{state.risk_score}\n", style=_score_style(state.risk_score))
    score_text.append(f"/ 100\n\n", style="dim")
    score_text.append("GRADE\n", style="bold dim")
    score_text.append(f"{state.risk_grade}\n", style=_grade_style(state.risk_grade))
    score_text.append(f"\nFindings: {state.total_findings}\n", style="dim")

    layout["score"].update(
        Panel(score_text, title="[bold]Risk Assessment[/]", border_style="cyan", box=box.ROUNDED),
    )

    # Right side: severity breakdown table with bar chart
    breakdown = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", expand=True)
    breakdown.add_column("Severity", width=10)
    breakdown.add_column("Count", width=8, justify="center")
    breakdown.add_column("Distribution", ratio=1)

    max_count = max(
        state.critical_count, state.high_count, state.medium_count,
        state.low_count, state.info_count, 1,
    )

    for label, count, style in [
        ("CRITICAL", state.critical_count, "red"),
        ("HIGH", state.high_count, "yellow"),
        ("MEDIUM", state.medium_count, "dark_orange"),
        ("LOW", state.low_count, "blue"),
        ("INFO", state.info_count, "dim"),
    ]:
        bar_width = int((count / max_count) * 30) if max_count > 0 else 0
        bar = Text()
        bar.append("█" * bar_width, style=style)
        bar.append(f" {count}" if bar_width > 0 else "", style="dim")
        breakdown.add_row(Text(label, style=_severity_style(label.lower())), str(count), bar)

    # Scanners run summary
    scanners_text = Text()
    scanners_text.append(f"\nScanners executed: {len(state.scanners_run)}", style="dim")
    if state.scanners_run:
        scanners_text.append(f"\n{', '.join(state.scanners_run[:5])}", style="dim italic")
        if len(state.scanners_run) > 5:
            scanners_text.append(f" +{len(state.scanners_run) - 5} more", style="dim")

    right_layout = Layout()
    right_layout.split_column(
        Layout(name="bars", ratio=3),
        Layout(name="scanners", ratio=1),
    )
    right_layout["bars"].update(breakdown)
    right_layout["scanners"].update(Panel(scanners_text, box=box.SIMPLE))

    layout["breakdown"].update(
        Panel(right_layout, title="[bold]Severity Breakdown[/]", border_style="cyan", box=box.ROUNDED),
    )

    return Panel(layout, title="[bold]Overview[/]", border_style="blue", box=box.ROUNDED)


def render_findings(state: TUIState) -> Panel:
    """Render findings list with severity filter."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        expand=True,
        row_styles=["", "dim"],
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Title", ratio=2)
    table.add_column("Category", width=20)
    table.add_column("Scanner", width=18)

    # Filter findings
    filtered = state.findings
    if state.severity_filter != "all":
        filtered = [
            f for f in state.findings
            if f.severity.value == state.severity_filter
        ]

    # Sort by severity weight (highest first)
    filtered_sorted = sorted(filtered, key=lambda f: f.severity.weight, reverse=True)

    # Display up to 50 findings to avoid overwhelming the terminal
    display_limit = 50
    for idx, finding in enumerate(filtered_sorted[:display_limit], 1):
        sev_value = finding.severity.value
        style = _severity_style(sev_value)
        table.add_row(
            str(idx),
            Text(sev_value.upper(), style=style),
            finding.title,
            finding.category,
            finding.scanner,
        )

    if len(filtered_sorted) > display_limit:
        table.add_row(
            "...",
            "",
            Text(f"({len(filtered_sorted) - display_limit} more findings)", style="dim"),
            "",
            "",
        )

    # Filter indicator
    filter_text = f"Filter: {state.severity_filter.upper()}"
    if state.severity_filter != "all":
        filter_text += f"  ({len(filtered)}/{state.total_findings} shown)"
    else:
        filter_text += f"  ({state.total_findings} total)"

    subtitle = f"[dim]{filter_text} | Press [bold]f[/bold] to cycle filter[/dim]"

    return Panel(
        table,
        title="[bold]Findings[/]",
        subtitle=subtitle,
        border_style="blue",
        box=box.ROUNDED,
    )


def render_scanners(state: TUIState) -> Panel:
    """Render scanner status with checkmarks."""
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        expand=True,
    )
    table.add_column("Status", width=6, justify="center")
    table.add_column("Scanner", ratio=1)

    # Known scanner list (all possible scanners)
    all_scanners = [
        "ProcessScanner",
        "NetworkScanner",
        "StartupScanner",
        "PackageScanner",
        "ConfigScanner",
        "FileIntegrityScanner",
        "BrowserScanner",
        "CredentialScanner",
        "LogAnalysisScanner",
        "PrivilegeScanner",
        "ServiceAuditScanner",
        "ThreatIntelScanner",
        "NetworkVulnScanner",
    ]

    run_set = set(state.scanners_run)

    for scanner in all_scanners:
        if scanner in run_set:
            table.add_row(
                Text("[ok]", style="bold green"),
                Text(scanner, style="green"),
            )
        else:
            table.add_row(
                Text("--", style="dim"),
                Text(scanner, style="dim"),
            )

    # Any additional scanners not in the known list
    for scanner in state.scanners_run:
        if scanner not in all_scanners:
            table.add_row(
                Text("[ok]", style="bold green"),
                Text(scanner, style="green italic"),
            )

    if state.scan_in_progress:
        status = Text("\nScan in progress...", style="bold yellow")
    elif state.scanners_run:
        status = Text(
            f"\n{len(state.scanners_run)} scanners completed",
            style="green",
        )
    else:
        status = Text(
            "\nNo scan has been run yet. Press [s] to start.",
            style="dim",
        )

    layout = Layout()
    layout.split_column(
        Layout(name="table", ratio=3),
        Layout(name="status", size=3),
    )
    layout["table"].update(table)
    layout["status"].update(Panel(status, box=box.SIMPLE))

    return Panel(
        layout,
        title="[bold]Scanner Status[/]",
        border_style="blue",
        box=box.ROUNDED,
    )


def render_actions(state: TUIState) -> Panel:
    """Render available actions panel with keyboard shortcuts help."""
    shortcuts = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        expand=True,
        title="Keyboard Shortcuts",
    )
    shortcuts.add_column("Key", width=12, justify="center", style="bold cyan")
    shortcuts.add_column("Action", ratio=1)

    shortcut_list = [
        ("s", "Start a new security scan"),
        ("q", "Quit the dashboard"),
        ("Tab", "Switch to next panel"),
        ("1", "Switch to Overview panel"),
        ("2", "Switch to Findings panel"),
        ("3", "Switch to Scanners panel"),
        ("4", "Switch to Actions panel"),
        ("f", "Cycle severity filter (all/critical/high/medium/low)"),
    ]

    for key, action in shortcut_list:
        shortcuts.add_row(key, action)

    # Current state summary
    state_info = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold",
        expand=True,
        title="Current State",
    )
    state_info.add_column("Property", width=20)
    state_info.add_column("Value", ratio=1)

    state_info.add_row("Active Panel", state.panel_names[state.active_panel])
    state_info.add_row("Severity Filter", state.severity_filter.upper())
    state_info.add_row(
        "Scan Status",
        Text("In Progress", style="yellow") if state.scan_in_progress
        else Text("Idle", style="green"),
    )
    state_info.add_row("Last Scan", state.last_scan_time or "Never")
    state_info.add_row("Risk Grade", Text(state.risk_grade, style=_grade_style(state.risk_grade)))
    state_info.add_row("Total Findings", str(state.total_findings))

    layout = Layout()
    layout.split_row(
        Layout(name="shortcuts", ratio=1),
        Layout(name="state", ratio=1),
    )
    layout["shortcuts"].update(shortcuts)
    layout["state"].update(state_info)

    return Panel(
        layout,
        title="[bold]Actions & Help[/]",
        border_style="blue",
        box=box.ROUNDED,
    )


def render_footer(state: TUIState) -> Panel:
    """Render the footer with keyboard hints."""
    footer = Text()
    footer.append("  [s]", style="bold cyan")
    footer.append(" Scan  ", style="dim")
    footer.append("[Tab]", style="bold cyan")
    footer.append(" Next Panel  ", style="dim")
    footer.append("[1-4]", style="bold cyan")
    footer.append(" Switch Panel  ", style="dim")
    footer.append("[f]", style="bold cyan")
    footer.append(" Filter  ", style="dim")
    footer.append("[q]", style="bold cyan")
    footer.append(" Quit", style="dim")

    footer.append("    ", style="dim")

    # Current filter
    if state.severity_filter != "all":
        footer.append(f"Filter: {state.severity_filter.upper()}", style="bold yellow")
    else:
        footer.append("Filter: ALL", style="dim")

    return Panel(footer, box=box.HEAVY, border_style="dim", height=3)

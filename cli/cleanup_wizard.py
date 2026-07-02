"""
Sentinel Agent — Interactive Cleanup Wizard

Guided post-scan cleanup: review each finding, choose to fix, skip,
allowlist, view details, or quit.
"""

from __future__ import annotations

import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from core.config import AgentConfig, ScanDepth, Severity
from core.logging import get_logger


class CleanupWizard:
    """Interactive post-scan cleanup wizard."""

    def __init__(self, config: AgentConfig | None = None, console: Console | None = None):
        self.config = config or AgentConfig()
        self.console = console or Console()
        self.log = get_logger()
        self._stats = {"fixed": 0, "skipped": 0, "allowlisted": 0}

    def run(self) -> dict:
        """Run scan then interactive review. Returns summary dict."""
        # Run scan
        self.console.print("[cyan]Running security scan...[/]")
        from core.agent import SentinelAgent
        agent = SentinelAgent(self.config)
        result = agent.scan()

        findings = sorted(result.findings, key=lambda f: f.severity.weight, reverse=True)

        if not findings:
            self.console.print("[bold green]No security issues found! Your system is clean.[/]")
            return self._stats

        self.console.print(f"\n[bold]Found {len(findings)} security issues to review.[/]")
        self.console.print("[dim]For each finding: [F]ix  [S]kip  [A]llowlist  [D]etails  [Q]uit[/]\n")

        for i, finding in enumerate(findings, 1):
            if not self._review_finding(finding, i, len(findings)):
                break  # User quit

        return self._stats

    def _review_finding(self, finding, index: int, total: int) -> bool:
        """Review a single finding. Returns False if user wants to quit."""
        sev = finding.severity.value.upper()
        sev_style = {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }.get(sev, "white")

        # Display finding summary
        self.console.print(f"[bold]({index}/{total})[/] [{sev_style}][{sev}][/{sev_style}] {finding.title}")
        self.console.print(f"  [dim]{finding.description[:120]}[/]")
        if finding.remediation:
            self.console.print(f"  [green]Fix: {finding.remediation[:100]}[/]")

        while True:
            try:
                choice = self.console.input("  [bold]Action [F/S/A/D/Q]:[/] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return False

            if choice in ("f", "fix"):
                self._fix_finding(finding)
                return True
            elif choice in ("s", "skip"):
                self._stats["skipped"] += 1
                self.console.print("  [dim]Skipped.[/]\n")
                return True
            elif choice in ("a", "allowlist"):
                self._allowlist_finding(finding)
                return True
            elif choice in ("d", "details"):
                self._show_details(finding)
                # Don't return — show details then re-prompt
            elif choice in ("q", "quit"):
                self.console.print("[yellow]Cleanup wizard stopped by user.[/]")
                return False
            else:
                self.console.print("  [dim]Choose: [F]ix [S]kip [A]llowlist [D]etails [Q]uit[/]")

    def _fix_finding(self, finding) -> None:
        """Attempt to fix/respond to a finding."""
        try:
            from response.engine import ResponseEngine
            from core.agent import SentinelAgent

            agent = SentinelAgent(self.config)

            # Show dry-run preview first
            self.console.print("  [cyan]Preview (dry-run):[/]")
            dry_config = AgentConfig()
            dry_config.response = self.config.response
            dry_config.response.dry_run = True
            dry_config.response.enabled = True

            engine = ResponseEngine(dry_config)
            preview = engine.respond_to_finding(finding)

            if not preview:
                self.console.print("  [yellow]No automated fix available for this finding.[/]")
                self._stats["skipped"] += 1
                return

            for action_info in preview:
                action_name = action_info.get("action_name", "unknown")
                target = action_info.get("target", "")
                self.console.print(f"    Would: {action_name} → {target}")

            # Confirm
            try:
                confirm = self.console.input("  [bold]Apply fix? [Y/n]:[/] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                self._stats["skipped"] += 1
                return

            if confirm in ("y", "yes", ""):
                # Execute for real
                real_config = AgentConfig()
                real_config.response = self.config.response
                real_config.response.dry_run = False
                real_config.response.enabled = True
                real_engine = ResponseEngine(real_config)
                real_engine.respond_to_finding(finding)
                self._stats["fixed"] += 1
                self.console.print("  [green]Fixed![/]\n")
            else:
                self._stats["skipped"] += 1
                self.console.print("  [dim]Skipped.[/]\n")

        except ImportError:
            self.console.print("  [yellow]Response engine not available — cannot auto-fix.[/]")
            self._stats["skipped"] += 1
        except Exception as e:
            self.console.print(f"  [red]Fix failed: {e}[/]")
            self._stats["skipped"] += 1

    def _allowlist_finding(self, finding) -> None:
        """Add finding to allowlist."""
        try:
            from core.allowlist import AllowlistManager
            mgr = AllowlistManager()

            # Auto-detect what to allowlist from evidence
            evidence = finding.evidence or {}
            sha256 = evidence.get("sha256", "")
            path = evidence.get("path") or evidence.get("filepath") or evidence.get("file", "")
            proc = evidence.get("process_name") or evidence.get("name", "")

            if sha256:
                entry = mgr.add_hash(sha256, reason=f"Cleanup wizard: {finding.title}")
                self.console.print(f"  [cyan]Allowlisted hash:[/] {sha256[:16]}... (ID: {entry.id})")
            elif path:
                entry = mgr.add_path(str(path), reason=f"Cleanup wizard: {finding.title}")
                self.console.print(f"  [cyan]Allowlisted path:[/] {path} (ID: {entry.id})")
            elif proc:
                entry = mgr.add_process(proc, reason=f"Cleanup wizard: {finding.title}")
                self.console.print(f"  [cyan]Allowlisted process:[/] {proc} (ID: {entry.id})")
            else:
                self.console.print("  [yellow]No hash/path/process in evidence to allowlist.[/]")
                self._stats["skipped"] += 1
                return

            self._stats["allowlisted"] += 1
            self.console.print()
        except ImportError:
            self.console.print("  [yellow]Allowlist module not available.[/]")
            self._stats["skipped"] += 1
        except Exception as e:
            self.console.print(f"  [red]Allowlist failed: {e}[/]")
            self._stats["skipped"] += 1

    def _show_details(self, finding) -> None:
        """Show detailed info about a finding."""
        table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 1))
        table.add_column("Key", style="bold", width=18)
        table.add_column("Value", width=60)

        table.add_row("Title", finding.title)
        table.add_row("Severity", finding.severity.value.upper())
        table.add_row("Category", finding.category or "—")
        table.add_row("Scanner", finding.scanner or "—")
        table.add_row("Description", finding.description)
        if finding.remediation:
            table.add_row("Remediation", finding.remediation)

        # Evidence
        if finding.evidence:
            for k, v in finding.evidence.items():
                val_str = str(v)[:80]
                table.add_row(f"Evidence: {k}", val_str)

        # Kill chain analysis if available
        try:
            from response.actions.kill_chain import KillChainAnalyzer
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                analyzer = KillChainAnalyzer(self.config)
                report = analyzer.analyze(finding)
                table.add_row("Kill Chain Risk", report.risk_level.upper())
                table.add_row("Process Tree", f"{len(report.process_tree)} processes")
                table.add_row("Related Files", f"{len(report.related_files)} files")
                table.add_row("Auto-cleanable", "Yes" if report.auto_cleanable else "No")
                if report.remediation_steps:
                    steps = "; ".join(report.remediation_steps[:3])
                    table.add_row("Steps", steps)
        except (ImportError, Exception):
            pass

        self.console.print(table)

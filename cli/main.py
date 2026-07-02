"""
Sentinel Security Agent — CLI Entry Point

Professional command-line interface for the Sentinel security agent.
Uses Rich for polished terminal output.

Usage:
    sentinel --scan              Standard security scan
    sentinel --deep-scan         Deep scan with extended checks
    sentinel --harden            Apply safe hardening recommendations
    sentinel --harden --dry-run  Show what hardening would do
    sentinel --harden --auto     Apply hardening without confirmation
    sentinel --report            Generate reports from last scan
    sentinel --update            Check/apply system updates
    sentinel --server-mode       Enable Linux server checks
    sentinel --daemon            Start continuous monitoring
    sentinel --stop-daemon       Stop the daemon
    sentinel --daemon-status     Check if daemon is running

Combinations:
    sentinel --scan --report           Scan and generate reports
    sentinel --deep-scan --report      Deep scan with reports
    sentinel --scan --harden --auto    Scan, then auto-harden
    sentinel --daemon --profile strict Daemon with strict profile
"""

from __future__ import annotations

import argparse
import sys
import os
from pathlib import Path

# Ensure project root is on the path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

from core import __version__, __product__
from core.config import AgentConfig, ScanDepth, AgentEdition
from core.profiles import (
    SecurityProfile,
    BUILTIN_PROFILES,
    get_profile,
    list_profiles,
)


console = Console()


def _build_banner() -> Panel:
    banner_text = Text()
    banner_text.append("  SENTINEL ", style="bold cyan")
    banner_text.append("Security Agent", style="bold white")
    banner_text.append(f"  v{__version__}", style="dim")
    banner_text.append("\n  Defensive Security Posture Assessment", style="dim italic")
    return Panel(banner_text, box=box.DOUBLE, border_style="cyan", padding=(0, 1))


def _severity_style(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }.get(severity, "white")


def _display_results(result, config: AgentConfig) -> None:
    """Display scan results with Rich formatting."""
    console.print()

    # Risk Score
    score = result.risk_score
    grade = result.risk_grade
    if score <= 30:
        score_style = "bold green"
    elif score <= 60:
        score_style = "bold yellow"
    else:
        score_style = "bold red"

    score_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
    score_table.add_column("", width=20, justify="right")
    score_table.add_column("", width=50)
    score_table.add_row("Risk Score", Text(f"{score}/100", style=score_style))
    score_table.add_row("Grade", Text(grade, style=score_style))
    score_table.add_row("Total Findings", str(len(result.findings)))
    score_table.add_row("Duration", f"{result.scan_duration_seconds}s")

    console.print(Panel(score_table, title="[bold]Scan Results[/]", border_style="cyan"))

    # Severity summary
    summary = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    summary.add_column("Severity", width=12)
    summary.add_column("Count", width=8, justify="center")
    summary.add_column("", width=40)

    for sev, count, bar_char in [
        ("CRITICAL", result.critical_count, "[red]|||[/]"),
        ("HIGH", result.high_count, "[yellow]|||[/]"),
        ("MEDIUM", result.medium_count, "[dark_orange]|||[/]"),
        ("LOW", result.low_count, "[blue]|||[/]"),
        ("INFO", result.info_count, "[dim]|||[/]"),
    ]:
        if count > 0:
            bar = bar_char * min(count, 20)
            style = _severity_style(sev.lower())
            summary.add_row(Text(sev, style=style), str(count), bar)

    console.print(summary)
    console.print()

    # Findings detail
    findings_sorted = sorted(result.findings, key=lambda f: f.severity.weight, reverse=True)

    for finding in findings_sorted:
        if finding.severity.value == "info" and config.scan.depth != ScanDepth.DEEP:
            continue  # Skip info in non-deep mode

        style = _severity_style(finding.severity.value)
        tag = f"[{style}][{finding.severity.value.upper()}][/{style}]"

        console.print(f"  {tag} {finding.title}")
        if finding.severity.value in ("critical", "high"):
            console.print(f"         [dim]{finding.description[:120]}[/]")
            if finding.remediation:
                console.print(f"         [green]Fix: {finding.remediation[:120]}[/]")

    console.print()


def _display_hardening_results(harden_result: dict) -> None:
    """Display hardening results."""
    console.print()

    table = Table(title="Hardening Results", box=box.ROUNDED, border_style="cyan")
    table.add_column("Action", width=40)
    table.add_column("Status", width=20)
    table.add_column("Details", width=40)

    for item in harden_result.get("applied", []):
        status = item.get("status", "unknown")
        style = "green" if status == "applied" else "yellow" if "dry" in status else "cyan"
        table.add_row(
            item["name"],
            Text(status, style=style),
            item.get("message", item.get("reason", "")),
        )

    for item in harden_result.get("errors", []):
        table.add_row(item["name"], Text("FAILED", style="red"), item.get("error", ""))

    console.print(table)
    console.print()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{__product__} v{__version__} — Defensive Security Posture Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel --scan                  Run standard security scan
  sentinel --deep-scan --report    Deep scan with HTML/JSON reports
  sentinel --harden --dry-run      Preview hardening changes
  sentinel --scan --harden --auto  Scan and auto-apply hardening
        """,
    )

    profile_group = parser.add_argument_group("Security Profiles")
    profile_group.add_argument(
        "--profile", type=str, default=None,
        choices=["minimal", "standard", "strict", "fort_knox", "custom"],
        help="Security profile (controls scan depth, scanners, hardening)",
    )
    profile_group.add_argument(
        "--profile-config", type=str, default=None,
        help="Path to custom profile JSON file (use with --profile custom)",
    )
    profile_group.add_argument(
        "--list-profiles", action="store_true",
        help="List available security profiles and exit",
    )
    profile_group.add_argument(
        "--show-profile", type=str, default=None,
        choices=["minimal", "standard", "strict", "fort_knox"],
        help="Show details of a specific profile and exit",
    )

    scan_group = parser.add_argument_group("Scanning")
    scan_group.add_argument("--scan", action="store_true", help="Run standard security scan")
    scan_group.add_argument("--deep-scan", action="store_true", help="Run deep scan (extended checks)")
    scan_group.add_argument("--hunt", action="store_true", help="Enable all threat hunting scanners (malware, memory, persistence, heuristic, IOC)")
    scan_group.add_argument("--kill-chain", action="store_true", help="Run kill chain analysis on CRITICAL/HIGH findings")
    scan_group.add_argument("--clean", action="store_true", help="Interactive cleanup wizard — scan then guided fix/skip/allowlist")

    harden_group = parser.add_argument_group("Hardening")
    harden_group.add_argument("--harden", action="store_true", help="Apply safe hardening recommendations")
    harden_group.add_argument("--auto", action="store_true", help="Apply remediations without confirmation")
    harden_group.add_argument("--dry-run", action="store_true", help="Preview changes without applying")

    report_group = parser.add_argument_group("Reporting")
    report_group.add_argument("--report", action="store_true", help="Generate HTML and JSON reports")
    report_group.add_argument("--output-dir", type=str, help="Report output directory")

    daemon_group = parser.add_argument_group("Monitoring")
    daemon_group.add_argument("--daemon", action="store_true", help="Start continuous monitoring daemon")
    daemon_group.add_argument("--stop-daemon", action="store_true", help="Stop running daemon")
    daemon_group.add_argument("--daemon-status", action="store_true", help="Check daemon status")
    daemon_group.add_argument("--guard", action="store_true", help="Enable real-time file guard (with --daemon)")

    intel_group = parser.add_argument_group("Threat Intelligence")
    intel_group.add_argument("--update-intel", action="store_true", help="Refresh threat intelligence feeds")
    intel_group.add_argument("--intel-status", action="store_true", help="Show threat intelligence database status")
    intel_group.add_argument("--check-ioc", type=str, default=None, help="Check an IOC (IP, hash, domain) against the database")

    response_group = parser.add_argument_group("Threat Response")
    response_group.add_argument("--respond", action="store_true", help="Enable automated threat response after scan")
    response_group.add_argument("--quarantine-list", action="store_true", help="List quarantined files")
    response_group.add_argument("--quarantine-restore", type=str, default=None, help="Restore a quarantined file by ID")
    response_group.add_argument("--quarantine-purge", action="store_true", help="Purge expired quarantined files")
    response_group.add_argument("--quarantine-info", type=str, default=None, help="Show details of a quarantined file by ID")
    response_group.add_argument("--response-history", action="store_true", help="Show threat response audit history")
    response_group.add_argument("--undo", nargs="?", const="__list__", default=None,
        help="Rollback a response action by ID (no ID = list candidates)")
    response_group.add_argument("--undo-allowlist", action="store_true",
        help="Also add to allowlist when using --undo <id>")

    compliance_group = parser.add_argument_group("Compliance")
    compliance_group.add_argument(
        "--compliance", type=str, default=None,
        choices=["cis", "nist", "soc2", "all"],
        help="Run compliance assessment against a framework",
    )

    audit_group = parser.add_argument_group("Audit Log")
    audit_group.add_argument("--audit-verify", action="store_true", help="Verify audit log integrity")
    audit_group.add_argument("--audit-export", type=str, default=None, help="Export audit log to JSON file")

    email_group = parser.add_argument_group("Email Reports")
    email_group.add_argument("--email-test", action="store_true", help="Send a test email to verify SMTP config")
    email_group.add_argument("--email-config", action="store_true", help="Show current email report configuration")

    tui_group = parser.add_argument_group("Dashboard")
    tui_group.add_argument(
        "--tui", "--dashboard", action="store_true", dest="tui",
        help="Launch interactive terminal dashboard",
    )

    mesh_group = parser.add_argument_group("Mesh Network")
    mesh_group.add_argument("--mesh-status", action="store_true", help="Show mesh network status and peers")

    allowlist_group = parser.add_argument_group("Allowlist")
    allowlist_group.add_argument("--allowlist-add", type=str, default=None,
        help="Add to allowlist (auto-detects hash/path/process)")
    allowlist_group.add_argument("--allowlist-remove", type=str, default=None,
        help="Remove an allowlist entry by ID")
    allowlist_group.add_argument("--allowlist-list", action="store_true",
        help="List all allowlist entries")

    rules_group = parser.add_argument_group("Malware Rules")
    rules_group.add_argument("--update-rules", action="store_true",
        help="Fetch latest malware rules from configured URL")
    rules_group.add_argument("--rules-info", action="store_true",
        help="Show malware rule set information")

    license_group = parser.add_argument_group("License")
    license_group.add_argument("--activate", type=str, default=None, help="Activate a Sentinel Pro license key")
    license_group.add_argument("--deactivate", action="store_true", help="Deactivate the current license")
    license_group.add_argument("--license-info", action="store_true", help="Show license status")
    license_group.add_argument("--start-trial", action="store_true", help="Start a 14-day Sentinel Pro trial")

    timeline_group = parser.add_argument_group("EDR Timeline")
    timeline_group.add_argument("--timeline", action="store_true", help="Show EDR event timeline")
    timeline_group.add_argument("--timeline-hours", type=int, default=24, help="Timeline hours (default: 24)")
    timeline_group.add_argument("--timeline-type", type=str, default=None, help="Filter timeline by event type")
    timeline_group.add_argument("--timeline-process", type=str, default=None, help="Filter timeline by process name")

    isolation_group = parser.add_argument_group("Endpoint Isolation")
    isolation_group.add_argument("--isolate", action="store_true", help="Isolate endpoint from network")
    isolation_group.add_argument("--isolate-release", action="store_true", help="Release endpoint from isolation")
    isolation_group.add_argument("--isolate-status", action="store_true", help="Check isolation status")

    playbook_group = parser.add_argument_group("Playbooks")
    playbook_group.add_argument("--playbooks", action="store_true", help="List available response playbooks")

    appcontrol_group = parser.add_argument_group("Application Control")
    appcontrol_group.add_argument("--appcontrol-status", action="store_true", help="Show application control status")

    device_group = parser.add_argument_group("Device Control")
    device_group.add_argument("--usb-status", action="store_true", help="Show USB device control status")

    system_group = parser.add_argument_group("System")
    system_group.add_argument("--update", action="store_true", help="Check for and apply system updates")
    system_group.add_argument("--server-mode", action="store_true", help="Enable Linux server mode checks")
    system_group.add_argument("--verbose", action="store_true", help="Verbose output")
    system_group.add_argument("--version", action="version", version=f"{__product__} {__version__}")

    args = parser.parse_args(argv)

    # Default: if no action specified, show help
    if not any([args.scan, args.deep_scan, args.harden, args.report, args.update,
                args.list_profiles, args.show_profile,
                args.daemon, args.stop_daemon, args.daemon_status,
                args.update_intel, args.intel_status, args.check_ioc,
                args.respond, args.quarantine_list, args.quarantine_restore,
                args.response_history, args.compliance,
                args.audit_verify, args.audit_export,
                args.email_test, args.email_config,
                args.tui, args.mesh_status, args.hunt, args.clean,
                args.allowlist_add, args.allowlist_remove, args.allowlist_list,
                args.update_rules, args.rules_info,
                args.quarantine_purge, args.quarantine_info, args.undo,
                args.activate, args.deactivate, args.license_info, args.start_trial,
                args.timeline,
                args.isolate, args.isolate_release, args.isolate_status,
                args.playbooks, args.appcontrol_status, args.usb_status]):
        parser.print_help()
        sys.exit(0)

    return args


def _display_profiles() -> None:
    """Display all available security profiles in a Rich table."""
    table = Table(
        title="Security Profiles",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Profile", style="bold cyan", width=12)
    table.add_column("Description", width=50)
    table.add_column("Depth", width=10, justify="center")
    table.add_column("Scanners", width=10, justify="center")
    table.add_column("Hardening", width=10, justify="center")
    table.add_column("Auto Fix", width=10, justify="center")
    table.add_column("Min Severity", width=12, justify="center")

    for info in list_profiles():
        table.add_row(
            info["id"],
            info["description"],
            info["depth"],
            info["scanners"],
            info["hardening"],
            info["auto_remediate"],
            info["min_severity"],
        )

    console.print(table)
    console.print()
    console.print("[dim]Usage: sentinel --profile <name> --scan[/]")
    console.print("[dim]Custom: sentinel --profile custom --profile-config ./my_profile.json --scan[/]")


def _display_profile_detail(profile_id: str) -> None:
    """Display detailed info about a specific profile."""
    profile_enum = SecurityProfile(profile_id)
    spec = BUILTIN_PROFILES[profile_enum]

    console.print(Panel(
        f"[bold cyan]{spec.name}[/]\n{spec.description}",
        border_style="cyan",
    ))

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Setting", style="bold", width=30)
    table.add_column("Value", width=40)

    table.add_row("Scan Depth", spec.scan_depth.value)
    table.add_row("Min Severity", spec.min_severity.value)

    # Scanner toggles
    scanners = []
    if spec.enable_process_scan: scanners.append("Process")
    if spec.enable_network_scan: scanners.append("Network")
    if spec.enable_startup_scan: scanners.append("Startup")
    if spec.enable_package_scan: scanners.append("Package")
    if spec.enable_config_scan: scanners.append("Config")
    if spec.enable_file_integrity_scan: scanners.append("File Integrity")
    if spec.enable_browser_scan: scanners.append("Browser")
    if spec.enable_credential_scan: scanners.append("Credential")
    if spec.enable_log_analysis_scan: scanners.append("Log Analysis")
    if spec.enable_privilege_scan: scanners.append("Privilege")
    if spec.enable_service_audit_scan: scanners.append("Service Audit")
    if spec.enable_threat_intel: scanners.append("Threat Intel")
    if spec.enable_network_vuln_scan: scanners.append("Network Vuln")
    if spec.enable_device_scan: scanners.append("Device")
    if spec.enable_cloud_scan: scanners.append("Cloud")
    if spec.enable_malware_scan: scanners.append("Malware")
    if spec.enable_memory_scan: scanners.append("Memory")
    if spec.enable_persistence_scan: scanners.append("Persistence")
    if spec.enable_heuristic_scan: scanners.append("Heuristic")
    if spec.enable_ioc_scan: scanners.append("IOC")
    table.add_row("Enabled Scanners", ", ".join(scanners))
    table.add_row("CVE Lookup", "Yes" if spec.enable_cve_lookup else "No")

    # Hardening
    table.add_row("Hardening", "Enabled" if spec.enable_hardening else "Disabled")
    table.add_row("Auto Remediate", "Yes" if spec.auto_remediate else "No")
    table.add_row("Response Level", spec.response_level)
    table.add_row("Continuous Monitoring", "Yes" if spec.enable_continuous_monitoring else "No")
    if spec.scan_interval_minutes > 0:
        table.add_row("Scan Interval", f"{spec.scan_interval_minutes} minutes")

    console.print(table)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # TUI dashboard — launch before banner (takes over screen)
    if args.tui:
        from tui.app import TUIApp

        config = AgentConfig()
        if args.profile:
            profile_enum = SecurityProfile(args.profile)
            custom_path = Path(args.profile_config) if args.profile_config else None
            profile_spec = get_profile(profile_enum, custom_path)
            config.scan = profile_spec.to_scan_config()
            config.profile = args.profile

        app = TUIApp(config)
        app.run()
        return 0

    console.print(_build_banner())
    console.print()

    # Profile info commands (no scan needed)
    if args.list_profiles:
        _display_profiles()
        return 0

    if args.show_profile:
        _display_profile_detail(args.show_profile)
        return 0

    # Daemon commands
    if args.daemon_status:
        from core.daemon import SentinelDaemon
        if SentinelDaemon.is_running():
            console.print("[green]Sentinel daemon is running.[/]")
        else:
            console.print("[yellow]Sentinel daemon is not running.[/]")
        return 0

    if args.stop_daemon:
        from core.daemon import SentinelDaemon
        if SentinelDaemon.stop_running():
            console.print("[green]Sentinel daemon stopped.[/]")
        else:
            console.print("[yellow]No running daemon found.[/]")
        return 0

    if args.daemon:
        from core.daemon import SentinelDaemon
        config = AgentConfig()
        if args.profile:
            profile_enum = SecurityProfile(args.profile)
            custom_path = Path(args.profile_config) if args.profile_config else None
            profile_spec = get_profile(profile_enum, custom_path)
            config.scan = profile_spec.to_scan_config()
            config.profile = args.profile
            if profile_spec.auto_remediate:
                config.scan.auto_mode = True
            console.print(f"[cyan]Profile:[/] [bold]{profile_spec.name}[/]")

        if getattr(args, 'guard', False):
            config.guard.enabled = True
            console.print("[bold cyan]Real-time file guard enabled[/]")

        console.print("[cyan]Starting Sentinel continuous monitoring...[/]")
        console.print("[dim]Press Ctrl+C to stop.[/]")
        console.print()
        daemon = SentinelDaemon(config)
        try:
            daemon.start()
        except KeyboardInterrupt:
            pass
        return 0

    # Threat intel commands
    if args.update_intel:
        from threat_intel.ioc_database import IOCDatabase
        from threat_intel.feed_manager import FeedManager
        console.print("[cyan]Refreshing threat intelligence feeds...[/]")
        db = IOCDatabase()
        fm = FeedManager(db)
        results = fm.refresh_all(force=True)
        for feed_name, count in results.items():
            console.print(f"  {feed_name}: [green]{count}[/] new IOCs")
        stats = db.get_stats()
        console.print(f"\n[bold]Total IOCs in database:[/] {stats['total']}")
        console.print(f"  IPs: {stats['ip_addresses']} | Domains: {stats['domains']} | "
                      f"Hashes: {stats['file_hashes']} | URLs: {stats['urls']}")
        return 0

    if args.intel_status:
        from threat_intel.ioc_database import IOCDatabase
        from threat_intel.feed_manager import FeedManager
        db = IOCDatabase()
        fm = FeedManager(db)
        stats = db.get_stats()
        table = Table(title="Threat Intelligence Status", box=box.ROUNDED, border_style="cyan")
        table.add_column("Feed", width=30)
        table.add_column("Description", width=40)
        table.add_column("Needs Refresh", width=15, justify="center")
        for feed_info in fm.list_feeds():
            refresh = "[red]Yes[/]" if feed_info["needs_refresh"] == "True" else "[green]No[/]"
            table.add_row(feed_info["name"], feed_info["description"], refresh)
        console.print(table)
        console.print(f"\n[bold]Total IOCs:[/] {stats['total']}")
        console.print(f"  IPs: {stats['ip_addresses']} | Domains: {stats['domains']} | "
                      f"Hashes: {stats['file_hashes']} | URLs: {stats['urls']}")
        return 0

    if args.check_ioc:
        from threat_intel.ioc_database import IOCDatabase
        db = IOCDatabase()
        ioc_value = args.check_ioc
        # Try all lookup methods
        result_entry = db.lookup_ip(ioc_value) or db.lookup_hash(ioc_value) or db.lookup_domain(ioc_value)
        if result_entry:
            console.print(f"[bold red]MATCH FOUND[/]")
            console.print(f"  Value: {result_entry.value}")
            console.print(f"  Type: {result_entry.ioc_type.value}")
            console.print(f"  Category: {result_entry.threat_category.value}")
            console.print(f"  Source: {result_entry.source}")
            console.print(f"  Confidence: {result_entry.confidence}%")
            console.print(f"  Description: {result_entry.description}")
        else:
            console.print(f"[green]No match found[/] for '{ioc_value}' in threat intel database.")
            stats = db.get_stats()
            console.print(f"[dim]Database contains {stats['total']} indicators. "
                         f"Run --update-intel to refresh.[/]")
        return 0

    # Quarantine management commands
    if args.quarantine_list:
        from response.actions.file_response import FileQuarantineManager
        manager = FileQuarantineManager()
        entries = manager.list_quarantined()
        if not entries:
            console.print("[green]No files currently quarantined.[/]")
        else:
            table = Table(title="Quarantined Files", box=box.ROUNDED, border_style="cyan")
            table.add_column("ID", width=10)
            table.add_column("Original Path", width=40)
            table.add_column("Finding", width=30)
            table.add_column("Severity", width=10)
            table.add_column("Timestamp", width=22)
            for entry in entries:
                style = _severity_style(entry.finding_severity)
                table.add_row(
                    entry.quarantine_id,
                    entry.original_path,
                    entry.finding_title,
                    Text(entry.finding_severity.upper(), style=style),
                    entry.timestamp[:19],
                )
            console.print(table)
            console.print(f"\n[dim]Restore with: sentinel --quarantine-restore <ID>[/]")
        return 0

    if args.quarantine_restore:
        from response.actions.file_response import FileQuarantineManager
        manager = FileQuarantineManager()
        success, message = manager.restore(args.quarantine_restore)
        if success:
            console.print(f"[green]{message}[/]")
        else:
            console.print(f"[red]{message}[/]")
        return 0

    if args.quarantine_purge:
        from response.actions.file_response import FileQuarantineManager
        manager = FileQuarantineManager()
        purged = manager.purge_expired()
        if purged:
            console.print(f"[green]Purged {len(purged)} expired quarantine entries.[/]")
            for qid in purged:
                console.print(f"  [dim]{qid}[/]")
        else:
            console.print("[green]No expired quarantine entries to purge.[/]")
        return 0

    if args.quarantine_info:
        from response.actions.file_response import FileQuarantineManager
        manager = FileQuarantineManager()
        entry = manager.get_info(args.quarantine_info)
        if entry is None:
            console.print(f"[red]Quarantine ID '{args.quarantine_info}' not found.[/]")
        else:
            table = Table(title=f"Quarantine Entry: {entry.quarantine_id}", box=box.ROUNDED, border_style="cyan")
            table.add_column("Property", style="bold", width=20)
            table.add_column("Value", width=50)
            table.add_row("ID", entry.quarantine_id)
            table.add_row("Original Path", entry.original_path)
            table.add_row("Quarantine Path", entry.quarantine_path)
            table.add_row("SHA-256", entry.sha256)
            table.add_row("Finding", entry.finding_title)
            style = _severity_style(entry.finding_severity)
            table.add_row("Severity", Text(entry.finding_severity.upper(), style=style))
            table.add_row("Timestamp", entry.timestamp[:19])
            table.add_row("Encrypted", "Yes" if getattr(entry, 'xor_key', '') else "No")
            table.add_row("File Size", f"{getattr(entry, 'file_size', 0):,} bytes")
            table.add_row("Restored", "Yes" if entry.restored else "No")
            console.print(table)
        return 0

    if args.undo is not None:
        from response.rollback import RollbackManager
        mgr = RollbackManager()
        if args.undo == "__list__":
            candidates = mgr.list_rollback_candidates()
            if not candidates:
                console.print("[green]No rollback candidates found.[/]")
            else:
                table = Table(title="Rollback Candidates", box=box.ROUNDED, border_style="cyan")
                table.add_column("Action ID", width=10)
                table.add_column("Action", width=18)
                table.add_column("Target", width=30)
                table.add_column("Finding", width=25)
                table.add_column("Timestamp", width=20)
                for r in reversed(candidates):
                    table.add_row(
                        getattr(r, 'action_id', '?'),
                        r.action_name,
                        r.target[:28],
                        r.finding_title[:23],
                        r.timestamp[:19],
                    )
                console.print(table)
                console.print("\n[dim]Rollback with: sentinel --undo <ACTION_ID>[/]")
                console.print("[dim]Rollback + allowlist: sentinel --undo <ACTION_ID> --undo-allowlist[/]")
        else:
            if args.undo_allowlist:
                success, message = mgr.rollback_and_allowlist(args.undo)
            else:
                success, message = mgr.rollback(args.undo)
            if success:
                console.print(f"[green]{message}[/]")
            else:
                console.print(f"[red]{message}[/]")
        return 0

    if args.response_history:
        from response.audit import ResponseAuditLog
        audit = ResponseAuditLog()
        history = audit.get_history(limit=50)
        if not history:
            console.print("[dim]No response history found.[/]")
        else:
            table = Table(title="Threat Response History", box=box.ROUNDED, border_style="cyan")
            table.add_column("Action", width=18)
            table.add_column("Status", width=12)
            table.add_column("Finding", width=30)
            table.add_column("Target", width=25)
            table.add_column("Timestamp", width=22)
            for record in reversed(history):
                status_style = {
                    "executed": "green", "dry_run": "yellow",
                    "failed": "red", "skipped": "dim",
                }.get(record.status, "white")
                table.add_row(
                    record.action_name,
                    Text(record.status, style=status_style),
                    record.finding_title[:28],
                    record.target[:23],
                    record.timestamp[:19],
                )
            console.print(table)
        return 0

    # Compliance assessment
    if args.compliance:
        from compliance.models import ComplianceFramework
        from compliance.engine import ComplianceEngine

        console.print("[cyan]Running scan for compliance assessment...[/]")
        config = AgentConfig()
        if args.profile:
            profile_enum = SecurityProfile(args.profile)
            custom_path = Path(args.profile_config) if args.profile_config else None
            profile_spec = get_profile(profile_enum, custom_path)
            config.scan = profile_spec.to_scan_config()
            config.profile = args.profile

        from core.agent import SentinelAgent
        agent = SentinelAgent(config)
        scan_result = agent.scan()

        engine = ComplianceEngine()

        if args.compliance == "all":
            comp_results = engine.evaluate_all(scan_result)
        else:
            fw_map = {
                "cis": ComplianceFramework.CIS,
                "nist": ComplianceFramework.NIST_800_53,
                "soc2": ComplianceFramework.SOC2,
            }
            comp_results = [engine.evaluate(scan_result, fw_map[args.compliance])]

        for comp in comp_results:
            pct = comp.compliance_percentage
            if pct >= 80:
                pct_style = "bold green"
            elif pct >= 50:
                pct_style = "bold yellow"
            else:
                pct_style = "bold red"

            table = Table(
                title=f"Compliance: {comp.framework.value.upper()}",
                box=box.ROUNDED,
                border_style="cyan",
            )
            table.add_column("Control", width=12)
            table.add_column("Title", width=35)
            table.add_column("Status", width=14, justify="center")
            table.add_column("Findings", width=10, justify="center")

            for cr in comp.controls:
                status_style = {
                    "pass": "green",
                    "fail": "red",
                    "partial": "yellow",
                    "not_assessed": "dim",
                }.get(cr.status.value, "white")
                table.add_row(
                    cr.control.id,
                    cr.control.title[:33],
                    Text(cr.status.value.upper(), style=status_style),
                    str(len(cr.findings)),
                )

            console.print(table)
            console.print(
                f"  Compliance: [{pct_style}]{pct}%[/{pct_style}]  "
                f"(Passed: {comp.passed} | Failed: {comp.failed} | "
                f"Partial: {comp.partial} | Not Assessed: "
                f"{comp.total_controls - comp.passed - comp.failed - comp.partial})"
            )
            console.print()

        return 0

    # Audit log commands
    if args.audit_verify:
        from core.audit_log import AuditLog
        audit = AuditLog()
        valid, errors = audit.verify_chain()
        if valid:
            console.print("[bold green]Audit log integrity verified — chain is intact.[/]")
        else:
            console.print("[bold red]Audit log integrity check FAILED[/]")
            for err in errors:
                console.print(f"  [red]{err}[/]")
        return 0 if valid else 1

    if args.audit_export:
        from core.audit_log import AuditLog
        audit = AuditLog()
        output_path = Path(args.audit_export)
        count = audit.export(output_path)
        console.print(f"[green]Exported {count} audit entries to {output_path}[/]")
        return 0

    # Email commands (no scan needed)
    if args.email_config:
        from core.config import EmailReportConfig
        config = AgentConfig()
        email_cfg = config.email
        table = Table(title="Email Report Configuration", box=box.ROUNDED, border_style="cyan")
        table.add_column("Setting", style="bold", width=25)
        table.add_column("Value", width=45)
        table.add_row("Enabled", str(email_cfg.enabled))
        table.add_row("SMTP Host", email_cfg.smtp.host or "(not set)")
        table.add_row("SMTP Port", str(email_cfg.smtp.port))
        table.add_row("SMTP Username", email_cfg.smtp.username or "(not set)")
        table.add_row("SMTP TLS", str(email_cfg.smtp.use_tls))
        table.add_row("From Address", email_cfg.smtp.from_address or "(not set)")
        table.add_row("Recipients", ", ".join(email_cfg.recipients) if email_cfg.recipients else "(none)")
        table.add_row("Subject Prefix", email_cfg.subject_prefix)
        table.add_row("HTML Attachment", str(email_cfg.include_html_attachment))
        table.add_row("Schedule Frequency", email_cfg.schedule.frequency)
        table.add_row("Schedule Day", str(email_cfg.schedule.day_of_week))
        table.add_row("Schedule Time", f"{email_cfg.schedule.hour:02d}:{email_cfg.schedule.minute:02d}")
        console.print(table)
        return 0

    if args.email_test:
        from core.config import EmailReportConfig
        from reporting.email_sender import EmailSender
        config = AgentConfig()
        sender = EmailSender(config.email)
        console.print("[cyan]Sending test email...[/]")
        success, message = sender.send_test_email()
        if success:
            console.print(f"[green]{message}[/]")
        else:
            console.print(f"[red]{message}[/]")
        return 0

    # Mesh network commands
    if args.mesh_status:
        try:
            from mesh.config import MeshConfig
            mesh_cfg = MeshConfig()
            table = Table(title="Mesh Network Status", box=box.ROUNDED, border_style="cyan")
            table.add_column("Setting", style="bold", width=25)
            table.add_column("Value", width=45)
            table.add_row("Enabled", str(mesh_cfg.enabled))
            table.add_row("Discovery Port", str(mesh_cfg.discovery_port))
            table.add_row("Communication Port", str(mesh_cfg.comm_port))
            table.add_row("Allowed Subnets", ", ".join(mesh_cfg.allowed_subnets) if mesh_cfg.allowed_subnets else "(all)")
            console.print(table)
            console.print("\n[dim]Enable mesh with configuration. Peers auto-discover on the local network.[/]")
        except ImportError:
            console.print("[yellow]Mesh module not available.[/]")
        return 0

    # Interactive cleanup wizard
    if args.clean:
        config = AgentConfig()
        if args.profile:
            profile_enum = SecurityProfile(args.profile)
            custom_path = Path(args.profile_config) if args.profile_config else None
            profile_spec = get_profile(profile_enum, custom_path)
            config.scan = profile_spec.to_scan_config()
            config.profile = args.profile
        if args.deep_scan:
            config.scan.depth = ScanDepth.DEEP
        if args.hunt:
            config.scan.enable_malware_scan = True
            config.scan.enable_memory_scan = True
            config.scan.enable_persistence_scan = True
            config.scan.enable_heuristic_scan = True
            config.scan.enable_ioc_scan = True
            config.scan.enable_yara_scan = True
            config.scan.enable_amsi_scan = True
            config.scan.depth = ScanDepth.DEEP
        try:
            from cli.cleanup_wizard import CleanupWizard
            wizard = CleanupWizard(config, console)
            summary = wizard.run()
            console.print()
            console.print(f"[bold]Cleanup Summary:[/] "
                         f"[green]{summary['fixed']} fixed[/], "
                         f"[yellow]{summary['skipped']} skipped[/], "
                         f"[cyan]{summary['allowlisted']} allowlisted[/]")
        except ImportError:
            console.print("[red]Cleanup wizard module not available.[/]")
        return 0

    # Allowlist commands
    if args.allowlist_list:
        from core.allowlist import AllowlistManager
        mgr = AllowlistManager()
        entries = mgr.list_entries()
        if not entries:
            console.print("[green]Allowlist is empty — no exclusions configured.[/]")
        else:
            table = Table(title="Allowlist Entries", box=box.ROUNDED, border_style="cyan")
            table.add_column("ID", width=10)
            table.add_column("Type", width=10)
            table.add_column("Value", width=45)
            table.add_column("Scope", width=20)
            table.add_column("Reason", width=20)
            for entry in entries:
                scope = ", ".join(entry.scanner_scope) if entry.scanner_scope else "All scanners"
                table.add_row(entry.id, entry.entry_type, entry.value, scope, entry.reason or "—")
            console.print(table)
            console.print(f"\n[dim]Remove with: sentinel --allowlist-remove <ID>[/]")
        return 0

    if args.allowlist_add:
        from core.allowlist import AllowlistManager
        mgr = AllowlistManager()
        value = args.allowlist_add
        # Auto-detect type: 64 hex chars = hash, contains / or \ or * = path, else process
        import re as _re
        if _re.fullmatch(r"[0-9a-fA-F]{64}", value):
            entry = mgr.add_hash(value)
            console.print(f"[green]Added hash to allowlist:[/] {entry.id} — {value[:16]}...")
        elif any(c in value for c in "/\\*"):
            entry = mgr.add_path(value)
            console.print(f"[green]Added path pattern to allowlist:[/] {entry.id} — {value}")
        else:
            entry = mgr.add_process(value)
            console.print(f"[green]Added process to allowlist:[/] {entry.id} — {value}")
        return 0

    if args.allowlist_remove:
        from core.allowlist import AllowlistManager
        mgr = AllowlistManager()
        success, message = mgr.remove(args.allowlist_remove)
        if success:
            console.print(f"[green]{message}[/]")
        else:
            console.print(f"[red]{message}[/]")
        return 0

    # License commands
    if args.license_info:
        try:
            from core.license import LicenseManager
            mgr = LicenseManager()
            info = mgr.get_license_info()
            table = Table(title="Sentinel License", box=box.ROUNDED, border_style="cyan")
            table.add_column("Setting", style="bold", width=25)
            table.add_column("Value", width=45)
            edition_style = {"pro": "bold green", "enterprise": "bold cyan", "free": "dim"}.get(info["edition"], "white")
            table.add_row("Edition", Text(info["edition"].upper(), style=edition_style))
            table.add_row("Pro Features", "[green]Available[/]" if info["pro_available"] else "[dim]Not available[/]")
            table.add_row("License Active", "[green]Yes[/]" if info.get("license_active") else "[dim]No[/]")
            if info.get("expiry_date"):
                table.add_row("Expires", info["expiry_date"])
            if info.get("customer_id"):
                table.add_row("Customer", info["customer_id"])
            table.add_row("Trial Active", "[green]Yes[/]" if info.get("trial_active") else "[dim]No[/]")
            if info.get("trial_days_remaining") is not None:
                table.add_row("Trial Days Left", str(info["trial_days_remaining"]))
            console.print(table)
        except ImportError:
            console.print("[yellow]License module not available.[/]")
        return 0

    if args.activate:
        try:
            from core.license import LicenseManager
            mgr = LicenseManager()
            success, message = mgr.activate(args.activate)
            if success:
                console.print(f"[green]{message}[/]")
            else:
                console.print(f"[red]{message}[/]")
        except ImportError:
            console.print("[yellow]License module not available.[/]")
        return 0

    if args.deactivate:
        try:
            from core.license import LicenseManager
            mgr = LicenseManager()
            success, message = mgr.deactivate()
            if success:
                console.print(f"[green]{message}[/]")
            else:
                console.print(f"[red]{message}[/]")
        except ImportError:
            console.print("[yellow]License module not available.[/]")
        return 0

    if args.start_trial:
        try:
            from core.license import LicenseManager
            mgr = LicenseManager()
            success, message = mgr.start_trial()
            if success:
                console.print(f"[green]{message}[/]")
            else:
                console.print(f"[yellow]{message}[/]")
        except ImportError:
            console.print("[yellow]License module not available.[/]")
        return 0

    # EDR Timeline commands
    if args.timeline:
        try:
            from edr.event_store import EventStore
            from edr.timeline_query import TimelineQuery
            store = EventStore()
            tq = TimelineQuery(store)

            if args.timeline_process:
                events = tq.query_events(process_name=args.timeline_process, hours=args.timeline_hours)
            elif args.timeline_type:
                events = tq.query_events(event_type=args.timeline_type, hours=args.timeline_hours)
            else:
                events = tq.query_events(hours=args.timeline_hours)

            if not events:
                console.print("[dim]No EDR events found in the specified time range.[/]")
                summary = tq.get_summary(hours=args.timeline_hours)
                console.print(f"[dim]Database: {summary['db_size_mb']} MB, {summary['total_events']} total events[/]")
            else:
                table = Table(title=f"EDR Timeline (last {args.timeline_hours}h)", box=box.ROUNDED, border_style="cyan")
                table.add_column("Time", width=20)
                table.add_column("Type", width=20)
                table.add_column("Process", width=18)
                table.add_column("Target", width=25)
                table.add_column("Severity", width=10)
                for ev in events[:100]:
                    sev_style = _severity_style(ev.severity)
                    table.add_row(
                        ev.timestamp[:19],
                        ev.event_type.value,
                        ev.source_process[:16] if ev.source_process else "—",
                        ev.target[:23] if ev.target else "—",
                        Text(ev.severity.upper(), style=sev_style),
                    )
                console.print(table)
                console.print(f"[dim]Showing {min(len(events), 100)} of {len(events)} events[/]")
        except ImportError:
            console.print("[yellow]EDR timeline module not available.[/]")
        return 0

    # Rule update commands
    if args.rules_info:
        try:
            from scanners.rule_manager import RuleManager
            mgr = RuleManager()
            info = mgr.get_info()
            table = Table(title="Malware Rule Set", box=box.ROUNDED, border_style="cyan")
            table.add_column("Setting", style="bold", width=25)
            table.add_column("Value", width=45)
            table.add_row("Total Rules", str(info.rule_count))
            table.add_row("Custom Rules Version", info.version or "(none)")
            table.add_row("Last Updated", info.last_updated or "(never)")
            table.add_row("Source URL", info.source_url or "(not configured)")
            console.print(table)
        except ImportError:
            console.print("[yellow]Rule manager not available.[/]")
        return 0

    if args.update_rules:
        try:
            from scanners.rule_manager import RuleManager
            config_temp = AgentConfig()
            url = config_temp.rules.update_url
            if not url:
                console.print("[red]No rule update URL configured.[/]")
                console.print("[dim]Set rules.update_url in your configuration.[/]")
                return 1
            mgr = RuleManager()
            console.print(f"[cyan]Fetching rules from {url}...[/]")
            success, message = mgr.update_rules(url)
            if success:
                console.print(f"[green]{message}[/]")
            else:
                console.print(f"[red]{message}[/]")
        except ImportError:
            console.print("[yellow]Rule manager not available.[/]")
        return 0

    # Endpoint isolation commands
    if args.isolate:
        try:
            from response.actions.endpoint_isolation import EndpointIsolationManager
            mgr = EndpointIsolationManager(AgentConfig())
            console.print("[bold red]ENDPOINT ISOLATION[/] — blocking all network traffic...")
            success, message = mgr.isolate()
            if success:
                console.print(f"[green]{message}[/]")
                console.print("[dim]Release with: sentinel --isolate-release[/]")
            else:
                console.print(f"[red]{message}[/]")
        except ImportError:
            console.print("[yellow]Endpoint isolation module not available.[/]")
        return 0

    if args.isolate_release:
        try:
            from response.actions.endpoint_isolation import EndpointIsolationManager
            mgr = EndpointIsolationManager(AgentConfig())
            success, message = mgr.release()
            if success:
                console.print(f"[green]{message}[/]")
            else:
                console.print(f"[red]{message}[/]")
        except ImportError:
            console.print("[yellow]Endpoint isolation module not available.[/]")
        return 0

    if args.isolate_status:
        try:
            from response.actions.endpoint_isolation import EndpointIsolationManager
            mgr = EndpointIsolationManager(AgentConfig())
            status = mgr.get_isolation_status()
            if status.get("isolated"):
                console.print("[bold red]ISOLATED[/] — endpoint is network-isolated")
                console.print(f"  Isolated since: {status.get('isolated_at', 'unknown')}")
                console.print(f"  Mode: {status.get('mode', 'full')}")
                if status.get("timeout_at"):
                    console.print(f"  Auto-release at: {status['timeout_at']}")
            else:
                console.print("[green]Not isolated[/] — network connectivity is normal")
        except ImportError:
            console.print("[yellow]Endpoint isolation module not available.[/]")
        return 0

    # Playbook commands
    if args.playbooks:
        try:
            from response.playbooks.engine import PlaybookEngine
            engine = PlaybookEngine()
            playbooks = engine.list_playbooks()
            if not playbooks:
                console.print("[dim]No playbooks available.[/]")
            else:
                table = Table(title="Response Playbooks", box=box.ROUNDED, border_style="cyan")
                table.add_column("Name", width=28, style="bold")
                table.add_column("Description", width=45)
                table.add_column("Actions", width=8, justify="center")
                for pb in playbooks:
                    table.add_row(pb["name"], pb.get("description", "—"), str(pb.get("action_count", 0)))
                console.print(table)
                console.print(f"\n[dim]{len(playbooks)} playbooks available. "
                             f"Playbooks auto-execute during threat response when enabled.[/]")
        except ImportError:
            console.print("[yellow]Playbook module not available.[/]")
        return 0

    # Application control commands
    if args.appcontrol_status:
        try:
            from edr.app_control import ApplicationControl
            ac = ApplicationControl()
            status = ac.get_status()
            table = Table(title="Application Control", box=box.ROUNDED, border_style="cyan")
            table.add_column("Setting", style="bold", width=25)
            table.add_column("Value", width=45)
            mode_style = {"enforce": "bold red", "alert": "bold yellow", "learning": "bold cyan"}.get(
                status.get("mode", "disabled"), "dim")
            table.add_row("Mode", Text(status.get("mode", "disabled").upper(), style=mode_style))
            table.add_row("Whitelisted Apps", str(status.get("whitelist_count", 0)))
            if status.get("learning_start"):
                table.add_row("Learning Since", status["learning_start"])
            if status.get("learning_days_remaining") is not None:
                table.add_row("Learning Days Left", str(status["learning_days_remaining"]))
            table.add_row("Blocked (24h)", str(status.get("blocked_24h", 0)))
            table.add_row("Alerts (24h)", str(status.get("alerts_24h", 0)))
            console.print(table)
        except ImportError:
            console.print("[yellow]Application control module not available.[/]")
        return 0

    # USB device control commands
    if args.usb_status:
        try:
            from edr.device_control import DeviceControlManager
            dcm = DeviceControlManager()
            status = dcm.get_status()
            table = Table(title="USB Device Control", box=box.ROUNDED, border_style="cyan")
            table.add_column("Setting", style="bold", width=25)
            table.add_column("Value", width=45)
            table.add_row("Default Policy", status.get("default_policy", "alert").upper())
            table.add_row("Allow HID", "[green]Yes[/]" if status.get("allow_hid", True) else "[red]No[/]")
            table.add_row("Allow Storage", "[green]Yes[/]" if status.get("allow_storage", True) else "[red]No[/]")
            table.add_row("Connected Devices", str(status.get("connected_count", 0)))
            devices = status.get("devices", [])
            if devices:
                console.print(table)
                dev_table = Table(title="Connected USB Devices", box=box.ROUNDED, border_style="cyan")
                dev_table.add_column("Device", width=30)
                dev_table.add_column("Class", width=12)
                dev_table.add_column("Status", width=12)
                for dev in devices:
                    status_style = {"allowed": "green", "blocked": "red", "alert": "yellow"}.get(
                        dev.get("status", ""), "white")
                    dev_table.add_row(
                        dev.get("name", "Unknown"),
                        dev.get("class", "unknown"),
                        Text(dev.get("status", "unknown").upper(), style=status_style),
                    )
                console.print(dev_table)
            else:
                console.print(table)
        except ImportError:
            console.print("[yellow]Device control module not available.[/]")
        return 0

    # Build config — start from profile if specified, then override with CLI flags
    config = AgentConfig()

    if args.profile:
        profile_enum = SecurityProfile(args.profile)
        custom_path = Path(args.profile_config) if args.profile_config else None
        profile_spec = get_profile(profile_enum, custom_path)
        config.scan = profile_spec.to_scan_config()
        config.profile = args.profile

        # Profile-driven hardening and auto-mode
        if profile_spec.enable_hardening and not args.harden:
            # Profile says harden, but only if user is running a scan
            pass  # Don't force hardening, just enable it in scan config
        if profile_spec.auto_remediate:
            config.scan.auto_mode = True

        console.print(f"[cyan]Profile:[/] [bold]{profile_spec.name}[/] — {profile_spec.description}")
        console.print()

    # --hunt enables all threat hunting scanners
    if args.hunt:
        config.scan.enable_malware_scan = True
        config.scan.enable_memory_scan = True
        config.scan.enable_persistence_scan = True
        config.scan.enable_heuristic_scan = True
        config.scan.enable_ioc_scan = True
        config.scan.enable_yara_scan = True
        config.scan.enable_amsi_scan = True
        config.scan.depth = ScanDepth.DEEP
        if not args.scan and not args.deep_scan:
            args.scan = True  # --hunt implies scan
        console.print("[bold cyan]Threat hunting mode enabled[/] — all 7 hunting scanners active")
        console.print()

    # Explicit CLI flags override profile settings
    if args.deep_scan:
        config.scan.depth = ScanDepth.DEEP

    if args.dry_run:
        config.scan.dry_run = True
    if args.auto:
        config.scan.auto_mode = True
    if args.server_mode:
        config.scan.server_mode = True

    if args.server_mode:
        config.edition = AgentEdition.SERVER

    if args.output_dir:
        config.report.output_dir = Path(args.output_dir)

    # Permission notice
    if args.harden and not args.dry_run:
        console.print(Panel(
            "[bold yellow]PERMISSION NOTICE[/]\n\n"
            "Hardening operations may modify system configuration.\n"
            "All changes are logged and use vendor-recommended settings.\n"
            f"Mode: {'AUTOMATIC' if args.auto else 'MANUAL (confirmation required)'}\n"
            f"Dry Run: {'YES' if args.dry_run else 'NO'}",
            border_style="yellow",
        ))
        if not args.auto:
            console.print("[dim]Use --auto to apply changes without confirmation, or --dry-run to preview.[/]")
            console.print()

    # Initialize agent
    from core.agent import SentinelAgent
    agent = SentinelAgent(config)

    result = None

    # Scan
    if args.scan or args.deep_scan:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning system security posture...", total=None)
            result = agent.scan()
            progress.update(task, completed=True)

        _display_results(result, config)

    # Respond
    if args.respond:
        if result is None:
            console.print("[yellow]Running scan first to identify threats...[/]")
            result = agent.scan()
            _display_results(result, config)

        console.print("[cyan]Executing threat response...[/]")
        response_result = agent.respond(result)

        # Display response results
        table = Table(title="Threat Response Results", box=box.ROUNDED, border_style="cyan")
        table.add_column("Action", width=20)
        table.add_column("Status", width=12)
        table.add_column("Target", width=25)
        table.add_column("Details", width=40)

        for item in response_result.get("executed", []):
            status_style = "green" if item["status"] == "executed" else "yellow"
            table.add_row(
                item["action_name"],
                Text(item["status"], style=status_style),
                item.get("target", ""),
                item.get("message", ""),
            )

        for item in response_result.get("errors", []):
            table.add_row(
                item["action_name"],
                Text("FAILED", style="red"),
                item.get("target", ""),
                item.get("message", ""),
            )

        if response_result.get("executed") or response_result.get("errors"):
            console.print(table)

        console.print(f"\n  Policy: {response_result.get('policy_level', 'unknown')}")
        console.print(f"  Actions executed: {response_result.get('total_actions', 0)}")
        console.print(f"  Skipped: {response_result.get('total_skipped', 0)}")
        if response_result.get("total_errors", 0) > 0:
            console.print(f"  [red]Errors: {response_result['total_errors']}[/]")
        console.print()

    # Kill chain analysis
    if args.kill_chain and result:
        from core.config import Severity as _Sev
        actionable = [f for f in result.findings if f.severity in (_Sev.CRITICAL, _Sev.HIGH)]
        if actionable:
            try:
                from response.actions.kill_chain import KillChainAnalyzer
                analyzer = KillChainAnalyzer(config)
                console.print(f"[cyan]Running kill chain analysis on {len(actionable)} CRITICAL/HIGH findings...[/]")
                for finding in actionable[:5]:  # Limit to top 5 to avoid excessive analysis
                    report = analyzer.analyze(finding)
                    console.print(f"\n[bold]Kill Chain: {finding.title}[/]")
                    console.print(f"  Risk Level: [{'red' if report.risk_level == 'critical' else 'yellow'}]{report.risk_level.upper()}[/]")
                    console.print(f"  Process Tree: {len(report.process_tree)} processes")
                    console.print(f"  Related Files: {len(report.related_files)}")
                    console.print(f"  Persistence Entries: {len(report.persistence_entries)}")
                    console.print(f"  Network Targets: {len(report.network_targets)}")
                    console.print(f"  Auto-cleanable: {'[green]Yes[/]' if report.auto_cleanable else '[yellow]No[/]'}")
                    if report.remediation_steps:
                        console.print("  [bold]Remediation Steps:[/]")
                        for i, step in enumerate(report.remediation_steps, 1):
                            console.print(f"    {i}. {step}")
                console.print()
            except ImportError:
                console.print("[yellow]Kill chain analyzer not available.[/]")
        else:
            console.print("[green]No CRITICAL/HIGH findings — kill chain analysis not needed.[/]")

    # Harden
    if args.harden:
        if result is None:
            console.print("[yellow]Running scan first to identify hardening targets...[/]")
            result = agent.scan()
            _display_results(result, config)

        harden_result = agent.harden(result)
        _display_hardening_results(harden_result)

    # Reports
    if args.report:
        if result is None:
            console.print("[yellow]Running scan first for report generation...[/]")
            result = agent.scan()
            _display_results(result, config)

        console.print("[cyan]Generating reports...[/]")
        reports = agent.generate_reports(result)
        for r in reports:
            console.print(f"  [green]Report saved:[/] {r}")

    # Update
    if args.update:
        from remediation.updater import SystemUpdater
        updater = SystemUpdater(dry_run=args.dry_run)
        console.print("[cyan]Checking for system updates...[/]")
        update_info = updater.check_updates()
        pending = update_info.get("pending", 0)
        console.print(f"  Pending updates: {pending}")

        if pending > 0 and not args.dry_run:
            if args.auto:
                console.print("[yellow]Installing updates...[/]")
                success, msg = updater.install_updates()
                console.print(f"  {'[green]Success' if success else '[red]Failed'}: {msg}[/]")
            else:
                console.print("[dim]Use --auto to install updates automatically.[/]")

    console.print("[dim]Sentinel scan complete.[/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Sentinel Agent — Kill Chain Analyzer

Traces complete attack chains from a single finding by analyzing
process trees, file artifacts, persistence mechanisms, and network
connections.  Produces a structured KillChainReport with ordered
remediation steps and auto-cleanup feasibility assessment.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from core.config import AgentConfig, Severity, is_windows, is_linux, is_macos
from core.logging import get_logger
from core.telemetry import Finding


# ---------------------------------------------------------------------------
# Directories commonly used by malware / temp-staged payloads
# ---------------------------------------------------------------------------
_SUSPICIOUS_DIRS_WINDOWS = {
    "temp", "tmp", "appdata", "programdata", "downloads",
    "public", "recycle.bin",
}
_SUSPICIOUS_DIRS_UNIX = {
    "/tmp", "/var/tmp", "/dev/shm", "/run/shm",
}

# System-critical process names that should never be auto-killed
_SYSTEM_CRITICAL = {
    # Windows
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
    # Unix / macOS
    "init", "systemd", "launchd", "kernel_task", "loginwindow",
    "WindowServer", "sshd",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class KillChainReport:
    """Complete analysis of an attack chain triggered by a single finding."""

    trigger_finding: Finding
    process_tree: list[dict] = field(default_factory=list)
    related_files: list[str] = field(default_factory=list)
    persistence_entries: list[dict] = field(default_factory=list)
    network_targets: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    auto_cleanable: bool = False
    risk_level: str = "low"


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class KillChainAnalyzer:
    """Traces complete attack chains from a trigger finding.

    The analyzer walks five stages in order:
      1. Process tree analysis   — parent/child relationships
      2. File artifact discovery  — related payloads on disk
      3. Persistence trace        — registry / cron / launchd entries
      4. Network trace            — active outbound connections
      5. Remediation plan         — ordered human-readable steps

    All system interactions are isolated so they can be mocked in tests.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, finding: Finding) -> KillChainReport:
        """Trace complete kill chain from a trigger finding."""
        report = KillChainReport(trigger_finding=finding)

        # Step 1 — Process tree
        self._trace_process_tree(finding, report)

        # Step 2 — File artifacts
        self._discover_file_artifacts(finding, report)

        # Step 3 — Persistence
        self._trace_persistence(finding, report)

        # Step 4 — Network
        self._trace_network(finding, report)

        # Step 5 — Build remediation plan + risk assessment
        self._build_remediation_plan(report)
        self._assess_risk(finding, report)
        self._assess_auto_cleanable(report)

        return report

    # ------------------------------------------------------------------
    # Step 1: Process Tree Analysis
    # ------------------------------------------------------------------

    def _trace_process_tree(self, finding: Finding, report: KillChainReport) -> None:
        """Walk the process tree for the PID referenced in the finding."""
        pid = finding.evidence.get("pid")
        if pid is None:
            self.log.debug("No PID in finding evidence — skipping process tree")
            return

        try:
            proc = psutil.Process(int(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as exc:
            self.log.warning(f"Cannot access PID {pid}: {exc}")
            return

        # Collect the trigger process itself
        self._add_process_info(proc, report)

        # Walk parents
        try:
            for parent in proc.parents():
                self._add_process_info(parent, report)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Walk children (recursive)
        try:
            for child in proc.children(recursive=True):
                self._add_process_info(child, report)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _add_process_info(self, proc: psutil.Process, report: KillChainReport) -> None:
        """Record a single process entry, flagging suspicious characteristics."""
        try:
            info: dict[str, Any] = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe_path": proc.exe(),
                "cmdline": proc.cmdline(),
                "create_time": proc.create_time(),
                "status": proc.status(),
                "suspicious": False,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            info = {
                "pid": proc.pid,
                "name": "unknown",
                "exe_path": "",
                "cmdline": [],
                "create_time": 0.0,
                "status": "unknown",
                "suspicious": False,
            }

        # Flag if the executable lives in a temp / suspicious directory
        exe = info.get("exe_path", "") or ""
        if exe:
            info["suspicious"] = self._is_suspicious_path(exe)

        # Avoid duplicates
        existing_pids = {p["pid"] for p in report.process_tree}
        if info["pid"] not in existing_pids:
            report.process_tree.append(info)

    @staticmethod
    def _is_suspicious_path(path_str: str) -> bool:
        """Return True if the path resides in a commonly-abused directory."""
        lower = path_str.lower().replace("\\", "/")
        for d in _SUSPICIOUS_DIRS_WINDOWS:
            if f"/{d}/" in lower or lower.endswith(f"/{d}"):
                return True
        for d in _SUSPICIOUS_DIRS_UNIX:
            if lower.startswith(d + "/") or lower == d:
                return True
        return False

    # ------------------------------------------------------------------
    # Step 2: File Artifact Discovery
    # ------------------------------------------------------------------

    def _discover_file_artifacts(self, finding: Finding, report: KillChainReport) -> None:
        """Scan the directory of the threat file for related artifacts."""
        threat_path = self._extract_path(finding)
        if threat_path is None:
            self.log.debug("No file path in finding evidence — skipping file discovery")
            return

        threat = Path(threat_path)
        if not threat.exists():
            # Even if the file is gone, record it
            report.related_files.append(str(threat))
            return

        report.related_files.append(str(threat))

        containing_dir = threat.parent
        try:
            entries = list(containing_dir.iterdir())
        except (PermissionError, OSError) as exc:
            self.log.warning(f"Cannot scan directory {containing_dir}: {exc}")
            return

        # Reference creation time of the threat file
        try:
            threat_ctime = threat.stat().st_ctime
        except OSError:
            threat_ctime = None

        for entry in entries:
            if not entry.is_file() or entry == threat:
                continue

            related = False

            # Same creation time (within 60 seconds)
            if threat_ctime is not None:
                try:
                    delta = abs(entry.stat().st_ctime - threat_ctime)
                    if delta <= 60.0:
                        related = True
                except OSError:
                    pass

            # Same extension
            if entry.suffix and entry.suffix == threat.suffix:
                related = True

            # Similar name (shares a stem prefix of >= 4 characters)
            if len(threat.stem) >= 4 and entry.stem.startswith(threat.stem[:4]):
                related = True

            if related:
                file_str = str(entry)
                if file_str not in report.related_files:
                    report.related_files.append(file_str)

    def _compute_sha256(self, filepath: str) -> str:
        """Compute the SHA-256 digest of a file."""
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except OSError as exc:
            self.log.warning(f"Cannot hash {filepath}: {exc}")
            return ""

    # ------------------------------------------------------------------
    # Step 3: Persistence Trace
    # ------------------------------------------------------------------

    def _trace_persistence(self, finding: Finding, report: KillChainReport) -> None:
        """Search common persistence locations for references to the threat."""
        threat_path = self._extract_path(finding)
        if threat_path is None:
            self.log.debug("No threat path — skipping persistence trace")
            return

        threat_name = Path(threat_path).name

        if is_windows():
            self._trace_persistence_windows(threat_path, threat_name, report)
        elif is_macos():
            self._trace_persistence_macos(threat_path, threat_name, report)
        else:
            self._trace_persistence_linux(threat_path, threat_name, report)

    def _trace_persistence_windows(
        self, threat_path: str, threat_name: str, report: KillChainReport
    ) -> None:
        """Check Windows registry Run keys and scheduled tasks."""
        run_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]

        for key in run_keys:
            try:
                result = subprocess.run(
                    ["reg", "query", key],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and threat_name.lower() in result.stdout.lower():
                    report.persistence_entries.append({
                        "mechanism": "registry_run_key",
                        "path": key,
                        "command": threat_path,
                        "detail": result.stdout.strip(),
                    })
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                self.log.debug(f"Registry check failed for {key}: {exc}")

        # Scheduled tasks
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and threat_name.lower() in result.stdout.lower():
                for line in result.stdout.splitlines():
                    if threat_name.lower() in line.lower():
                        report.persistence_entries.append({
                            "mechanism": "scheduled_task",
                            "path": "schtasks",
                            "command": threat_path,
                            "detail": line.strip(),
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self.log.debug(f"Scheduled-task check failed: {exc}")

    def _trace_persistence_linux(
        self, threat_path: str, threat_name: str, report: KillChainReport
    ) -> None:
        """Check crontab, systemd services, and shell rc files."""
        # Crontab
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and threat_name in result.stdout:
                for line in result.stdout.splitlines():
                    if threat_name in line:
                        report.persistence_entries.append({
                            "mechanism": "crontab",
                            "path": "crontab",
                            "command": threat_path,
                            "detail": line.strip(),
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self.log.debug(f"Crontab check failed: {exc}")

        # Systemd service files
        systemd_dirs = [
            Path("/etc/systemd/system"),
            Path("/usr/lib/systemd/system"),
            Path.home() / ".config" / "systemd" / "user",
        ]
        for sdir in systemd_dirs:
            self._scan_directory_for_reference(
                sdir, threat_name, "systemd_service", report,
            )

        # Shell rc files
        home = Path.home()
        rc_files = [
            home / ".bashrc",
            home / ".bash_profile",
            home / ".profile",
            home / ".zshrc",
        ]
        for rc in rc_files:
            try:
                if rc.exists() and threat_name in rc.read_text():
                    report.persistence_entries.append({
                        "mechanism": "shell_rc",
                        "path": str(rc),
                        "command": threat_path,
                        "detail": f"Reference found in {rc.name}",
                    })
            except OSError:
                pass

    def _trace_persistence_macos(
        self, threat_path: str, threat_name: str, report: KillChainReport
    ) -> None:
        """Check LaunchAgent and LaunchDaemon plists."""
        plist_dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
            Path("/System/Library/LaunchDaemons"),
        ]
        for pdir in plist_dirs:
            self._scan_directory_for_reference(
                pdir, threat_name, "launch_agent", report,
            )

    def _scan_directory_for_reference(
        self,
        directory: Path,
        search_term: str,
        mechanism: str,
        report: KillChainReport,
    ) -> None:
        """Scan text files in *directory* for *search_term*."""
        try:
            if not directory.exists():
                return
            for entry in directory.iterdir():
                if not entry.is_file():
                    continue
                try:
                    content = entry.read_text(errors="ignore")
                    if search_term in content:
                        report.persistence_entries.append({
                            "mechanism": mechanism,
                            "path": str(entry),
                            "command": search_term,
                            "detail": f"Reference found in {entry.name}",
                        })
                except OSError:
                    pass
        except (PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # Step 4: Network Trace
    # ------------------------------------------------------------------

    def _trace_network(self, finding: Finding, report: KillChainReport) -> None:
        """Capture active network connections from the threat process."""
        pid = finding.evidence.get("pid")
        if pid is None:
            self.log.debug("No PID in finding evidence — skipping network trace")
            return

        try:
            proc = psutil.Process(int(pid))
            connections = proc.net_connections()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError) as exc:
            self.log.debug(f"Cannot get connections for PID {pid}: {exc}")
            return

        for conn in connections:
            if conn.raddr:
                target = f"{conn.raddr.ip}:{conn.raddr.port}"
                if target not in report.network_targets:
                    report.network_targets.append(target)

    # ------------------------------------------------------------------
    # Step 5: Remediation Plan & Risk Assessment
    # ------------------------------------------------------------------

    def _build_remediation_plan(self, report: KillChainReport) -> None:
        """Generate ordered human-readable remediation steps."""
        steps: list[str] = []

        # 1. Process termination
        if report.process_tree:
            root = report.process_tree[0]
            children_count = max(0, len(report.process_tree) - 1)
            steps.append(
                f"Terminate process tree: PID {root['pid']} ({root['name']}) "
                f"and {children_count} children"
            )

        # 2. File quarantine
        if report.related_files:
            file_list = ", ".join(report.related_files)
            steps.append(f"Quarantine files: {file_list}")

        # 3. Persistence removal
        for entry in report.persistence_entries:
            steps.append(
                f"Remove persistence: {entry['mechanism']} at {entry['path']}"
            )

        # 4. Network blocking
        if report.network_targets:
            targets = ", ".join(report.network_targets)
            steps.append(f"Block network: {targets}")

        # 5. Full system scan
        steps.append("Scan system for additional indicators")

        report.remediation_steps = steps

    def _assess_risk(self, finding: Finding, report: KillChainReport) -> None:
        """Determine the risk_level based on the finding and collected data."""
        severity = finding.severity
        has_persistence = len(report.persistence_entries) > 0
        has_network = len(report.network_targets) > 0
        has_multiple_files = len(report.related_files) > 1

        # Count how many secondary indicators are present
        indicator_count = sum([has_persistence, has_network, has_multiple_files])

        if severity == Severity.CRITICAL and has_network and has_persistence:
            report.risk_level = "critical"
        elif severity in (Severity.CRITICAL, Severity.HIGH) and indicator_count >= 2:
            report.risk_level = "high"
        elif indicator_count <= 1 and severity in (Severity.MEDIUM, Severity.HIGH):
            report.risk_level = "medium"
        elif severity in (Severity.LOW, Severity.INFO) and indicator_count == 0:
            report.risk_level = "low"
        else:
            # Default fallback based on severity alone
            if severity == Severity.CRITICAL:
                report.risk_level = "high"
            elif severity == Severity.HIGH:
                report.risk_level = "medium"
            else:
                report.risk_level = "low"

    def _assess_auto_cleanable(self, report: KillChainReport) -> None:
        """Decide whether the kill chain can be cleaned automatically.

        Auto-clean is safe when:
        - All artifacts come from temp / suspicious directories
        - No system-critical processes are in the process tree
        - The process tree is contained (not spreading to system services)
        """
        # Must have *something* to clean
        if not report.process_tree and not report.related_files:
            report.auto_cleanable = False
            return

        # Check: no system-critical processes
        for proc_info in report.process_tree:
            name = (proc_info.get("name") or "").lower()
            if name in _SYSTEM_CRITICAL:
                report.auto_cleanable = False
                return

        # Check: all files are from suspicious directories
        all_suspicious_files = True
        for fpath in report.related_files:
            if not self._is_suspicious_path(fpath):
                all_suspicious_files = False
                break

        # Check: all processes are from suspicious paths
        all_suspicious_procs = True
        for proc_info in report.process_tree:
            exe = proc_info.get("exe_path", "") or ""
            if exe and not self._is_suspicious_path(exe):
                all_suspicious_procs = False
                break

        report.auto_cleanable = all_suspicious_files and all_suspicious_procs

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_path(finding: Finding) -> str | None:
        """Extract a file-system path from the finding evidence."""
        for key in ("path", "exe_path", "filepath"):
            val = finding.evidence.get(key)
            if val and isinstance(val, str):
                return val
        return None

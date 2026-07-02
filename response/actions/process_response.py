"""
Sentinel Agent — Process Response Handler

Kills suspicious processes with safety checks.
Maintains a system process safelist that must NEVER be killed.
"""

from __future__ import annotations

import platform

import psutil

from core.logging import get_logger
from core.telemetry import Finding


SYSTEM_PROCESS_SAFELIST_WINDOWS = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "spoolsv.exe",
    "lsaiso.exe", "searchindexer.exe", "msdtc.exe", "wuauclt.exe",
}

SYSTEM_PROCESS_SAFELIST_UNIX = {
    "init", "systemd", "kthreadd", "ksoftirqd", "migration", "rcu_sched",
    "sshd", "login", "agetty", "getty", "cron", "crond", "launchd",
    "kernel_task", "loginwindow", "WindowServer", "opendirectoryd",
}


class ProcessResponseHandler:
    """Handles process-related threat responses."""

    def __init__(self) -> None:
        self.log = get_logger()
        self.safelist = self._build_safelist()

    @staticmethod
    def _build_safelist() -> set[str]:
        system = platform.system().lower()
        if system == "windows":
            return SYSTEM_PROCESS_SAFELIST_WINDOWS
        return SYSTEM_PROCESS_SAFELIST_UNIX

    def can_respond(self, finding: Finding) -> tuple[bool, str]:
        """Check if we can safely respond to this finding."""
        pid = finding.evidence.get("pid")
        name = finding.evidence.get("name", "").lower()

        if not pid:
            return False, "No PID in finding evidence"
        if name in self.safelist:
            return False, f"Process '{name}' is on system safelist"

        try:
            proc = psutil.Process(int(pid))
            current_name = proc.name().lower()
            if current_name != name:
                return False, f"PID {pid} no longer matches expected process '{name}' (now '{current_name}')"
            return True, f"Process '{name}' (PID {pid}) can be terminated"
        except psutil.NoSuchProcess:
            return False, f"Process PID {pid} no longer exists"
        except (psutil.AccessDenied, psutil.ZombieProcess) as e:
            return False, f"Cannot access process PID {pid}: {e}"

    def execute(self, finding: Finding) -> tuple[bool, str]:
        """Kill the suspicious process."""
        pid = finding.evidence.get("pid")
        name = finding.evidence.get("name", "unknown")

        try:
            proc = psutil.Process(int(pid))
            proc.terminate()
            try:
                proc.wait(timeout=5)
                self.log.info(f"Process '{name}' (PID {pid}) terminated")
                return True, f"Process '{name}' (PID {pid}) terminated"
            except psutil.TimeoutExpired:
                proc.kill()
                self.log.info(f"Process '{name}' (PID {pid}) force-killed")
                return True, f"Process '{name}' (PID {pid}) force-killed"
        except psutil.NoSuchProcess:
            return False, f"Process PID {pid} no longer exists"
        except psutil.AccessDenied:
            return False, f"Permission denied killing PID {pid}. Run with elevated privileges."
        except Exception as e:
            return False, f"Failed to kill PID {pid}: {e}"

    def is_applicable(self, finding: Finding) -> bool:
        """Check if this handler applies to a given finding."""
        return (
            finding.category in ("Malware Indicators", "Process Anomaly", "Threat Intelligence")
            and "pid" in finding.evidence
        )

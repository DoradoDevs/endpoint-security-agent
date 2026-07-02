"""
Sentinel Agent — System Updater

Safe abstraction for triggering system updates.
Only invokes vendor-recommended update mechanisms.
"""

from __future__ import annotations

import platform
import subprocess

from core.logging import get_logger, log_action


def _run_cmd(args: list[str], timeout: int = 300) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return False, str(e)


class SystemUpdater:
    """Cross-platform system update management."""

    def __init__(self, dry_run: bool = False):
        self.log = get_logger()
        self.dry_run = dry_run
        self.system = platform.system().lower()

    def check_updates(self) -> dict:
        """Check for available updates without installing."""
        if self.system == "windows":
            return self._win_check()
        elif self.system == "darwin":
            return self._mac_check()
        elif self.system == "linux":
            return self._linux_check()
        return {"error": "Unsupported platform"}

    def install_updates(self) -> tuple[bool, str]:
        """Trigger update installation."""
        if self.dry_run:
            log_action("Install Updates", self.system, "Would install", dry_run=True)
            return True, "Dry-run: would install updates"

        if self.system == "linux":
            return self._linux_install()
        elif self.system == "darwin":
            return self._mac_install()

        return False, "Automated update installation not supported on this platform"

    def _win_check(self) -> dict:
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "$s = New-Object -ComObject Microsoft.Update.Session; "
            "$searcher = $s.CreateUpdateSearcher(); "
            "try { $r = $searcher.Search('IsInstalled=0'); $r.Updates.Count } catch { 'error' }"
        ], timeout=120)
        return {"pending": int(output) if output.isdigit() else 0}

    def _mac_check(self) -> dict:
        success, output = _run_cmd(["softwareupdate", "--list"], timeout=60)
        count = output.count("* Label:") if output else 0
        return {"pending": count, "details": output[:2000] if output else ""}

    def _linux_check(self) -> dict:
        # Try apt first
        success, output = _run_cmd(["apt", "list", "--upgradable"])
        if success and output:
            lines = [l for l in output.splitlines() if "/" in l and "Listing" not in l]
            return {"pending": len(lines), "manager": "apt"}

        # Try dnf
        success, output = _run_cmd(["dnf", "check-update", "--quiet"])
        if output:
            lines = [l for l in output.splitlines() if l.strip()]
            return {"pending": len(lines), "manager": "dnf"}

        return {"pending": 0, "manager": "unknown"}

    def _linux_install(self) -> tuple[bool, str]:
        # Try apt first
        success, output = _run_cmd(["apt", "upgrade", "-y"], timeout=300)
        if success:
            return True, "Updates installed via apt"

        # Try dnf
        success, output = _run_cmd(["dnf", "upgrade", "-y"], timeout=300)
        if success:
            return True, "Updates installed via dnf"

        return False, "Could not install updates"

    def _mac_install(self) -> tuple[bool, str]:
        return _run_cmd(["softwareupdate", "--install", "--all"], timeout=600)

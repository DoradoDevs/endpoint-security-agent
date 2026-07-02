"""
Sentinel Agent — Firewall Manager

Safe firewall management abstraction across platforms.
Only adds rules — never removes existing rules without explicit request.
"""

from __future__ import annotations

import platform
import subprocess
from typing import Any

from core.logging import get_logger, log_action


def _run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return False, str(e)


class FirewallManager:
    """Cross-platform firewall management."""

    def __init__(self, dry_run: bool = False):
        self.log = get_logger()
        self.dry_run = dry_run
        self.system = platform.system().lower()

    def get_status(self) -> dict[str, Any]:
        """Get current firewall status."""
        if self.system == "windows":
            return self._win_status()
        elif self.system == "darwin":
            return self._mac_status()
        elif self.system == "linux":
            return self._linux_status()
        return {"error": f"Unsupported platform: {self.system}"}

    def enable(self) -> tuple[bool, str]:
        """Enable the firewall."""
        if self.dry_run:
            log_action("Enable Firewall", self.system, "Would enable", dry_run=True)
            return True, "Dry-run: would enable firewall"

        if self.system == "windows":
            return self._win_enable()
        elif self.system == "darwin":
            return self._mac_enable()
        elif self.system == "linux":
            return self._linux_enable()
        return False, f"Unsupported platform: {self.system}"

    def _win_status(self) -> dict[str, Any]:
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        ])
        return {"raw": output, "success": success}

    def _win_enable(self) -> tuple[bool, str]:
        return _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        ])

    def _mac_status(self) -> dict[str, Any]:
        success, output = _run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        return {"raw": output, "enabled": "enabled" in output.lower() if output else False}

    def _mac_enable(self) -> tuple[bool, str]:
        return _run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"])

    def _linux_status(self) -> dict[str, Any]:
        success, output = _run_cmd(["ufw", "status", "verbose"])
        return {"raw": output, "enabled": "active" in output.lower() if output else False}

    def _linux_enable(self) -> tuple[bool, str]:
        _run_cmd(["ufw", "allow", "ssh"])
        _run_cmd(["ufw", "default", "deny", "incoming"])
        return _run_cmd(["ufw", "--force", "enable"])

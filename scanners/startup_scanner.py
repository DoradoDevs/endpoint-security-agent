"""
Sentinel Agent — Startup Persistence Scanner

Checks startup/persistence mechanisms for suspicious entries:
- Registry Run keys (Windows)
- LaunchAgents/Daemons (macOS)
- Systemd services and cron jobs (Linux)
- Scheduled tasks

Heuristic-based detection of suspicious persistence entries.
"""

from __future__ import annotations

import platform
from pathlib import Path

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from os_modules.loader import load_os_module
from scanners.base import BaseScanner

# Heuristic patterns for suspicious startup commands
SUSPICIOUS_COMMAND_PATTERNS = [
    "powershell -enc",
    "powershell -e ",
    "powershell -nop",
    "powershell -w hidden",
    "cmd /c echo",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32 /s /n /u /i:",
    "rundll32",
    "certutil -urlcache",
    "bitsadmin /transfer",
    "curl | bash",
    "wget -q -O - | sh",
    "python -c",
    "base64 --decode",
    "/dev/tcp/",
    "nc -e",
    "ncat -e",
]

# Suspicious launch locations
SUSPICIOUS_STARTUP_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
]


class StartupScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "Startup Scanner"

    @property
    def description(self) -> str:
        return "Detect suspicious startup persistence mechanisms"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        os_module = load_os_module()
        entries = os_module.get_startup_entries()

        for entry in entries:
            cmd_lower = entry.command.lower()
            name_lower = entry.name.lower()

            # Check 1: Suspicious command patterns
            for pattern in SUSPICIOUS_COMMAND_PATTERNS:
                if pattern.lower() in cmd_lower:
                    findings.append(Finding(
                        title=f"Suspicious startup entry: {entry.name}",
                        description=(
                            f"Startup entry '{entry.name}' uses suspicious command pattern: "
                            f"'{pattern}'. Command: {entry.command[:200]}"
                        ),
                        severity=Severity.HIGH,
                        category="Persistence",
                        scanner=self.name,
                        evidence={
                            "name": entry.name,
                            "command": entry.command,
                            "location": entry.location,
                            "pattern_matched": pattern,
                        },
                        remediation="Investigate this startup entry. Remove if not recognized.",
                    ))
                    break

            # Check 2: Startup entries pointing to suspicious paths
            for sus_path in SUSPICIOUS_STARTUP_PATHS:
                if sus_path.lower() in cmd_lower:
                    findings.append(Finding(
                        title=f"Startup entry from suspicious path: {entry.name}",
                        description=(
                            f"Startup entry '{entry.name}' references a temporary or "
                            f"world-writable directory. Command: {entry.command[:200]}"
                        ),
                        severity=Severity.MEDIUM,
                        category="Persistence",
                        scanner=self.name,
                        evidence={
                            "name": entry.name,
                            "command": entry.command,
                            "location": entry.location,
                            "suspicious_path": sus_path,
                        },
                        remediation="Verify this startup entry is legitimate.",
                    ))
                    break

            # Check 3: Obfuscated or encoded commands
            obfuscation_indicators = [
                "base64", "-enc ", "-encodedcommand",
                "frombase64", "iex(", "invoke-expression",
                "\\x", "\\u00", "chr(",
            ]
            for indicator in obfuscation_indicators:
                if indicator.lower() in cmd_lower:
                    findings.append(Finding(
                        title=f"Potentially obfuscated startup entry: {entry.name}",
                        description=(
                            f"Startup entry '{entry.name}' appears to use obfuscation/encoding. "
                            f"Indicator: '{indicator}'. This is commonly used by malware."
                        ),
                        severity=Severity.HIGH,
                        category="Persistence",
                        scanner=self.name,
                        evidence={
                            "name": entry.name,
                            "command": entry.command[:500],
                            "indicator": indicator,
                        },
                        remediation="Decode and investigate this startup command.",
                    ))
                    break

        # Report total count for visibility
        if entries:
            findings.append(Finding(
                title=f"Startup entry inventory: {len(entries)} entries found",
                description=(
                    f"Enumerated {len(entries)} startup/persistence entries across all locations."
                ),
                severity=Severity.INFO,
                category="Persistence",
                scanner=self.name,
                evidence={"total_entries": len(entries)},
            ))

        return findings

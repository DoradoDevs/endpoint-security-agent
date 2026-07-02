"""
Sentinel Agent — Process Scanner

Enumerates running processes and applies heuristic checks to detect:
- Suspicious process names
- Processes running from unusual locations
- High-privilege processes with anomalous behavior
- Known suspicious process characteristics

This is heuristic-based detection, NOT signature matching.
No process is terminated or modified.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

import psutil

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner

# Heuristic indicators — process names commonly associated with threats
# These are NOT signatures; they are patterns that warrant investigation
SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "lazagne", "procdump", "pwdump", "gsecdump",
    "wce", "fgdump", "ncat", "nc.exe", "netcat",
    "cobaltstrike", "meterpreter", "empire",
    "cryptominer", "xmrig", "minergate", "cpuminer",
    "keylogger", "screenlogger",
}

# Directories that are unusual for legitimate executables
SUSPICIOUS_DIRS_WINDOWS = [
    r"\temp\\", r"\tmp\\", r"\appdata\local\temp",
    r"\users\public\\", r"\programdata\\",
    r"\recycler\\", r"\\$recycle.bin\\",
]

SUSPICIOUS_DIRS_UNIX = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/dev/mqueue/", "/run/user/",
]


class ProcessScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "Process Scanner"

    @property
    def description(self) -> str:
        return "Enumerate running processes and detect suspicious behavior"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        system = platform.system().lower()
        suspicious_dirs = SUSPICIOUS_DIRS_WINDOWS if system == "windows" else SUSPICIOUS_DIRS_UNIX

        for proc in psutil.process_iter(["pid", "name", "exe", "username", "cmdline", "create_time"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                name = (info.get("name") or "").lower()
                exe = info.get("exe") or ""
                username = info.get("username") or ""
                cmdline = info.get("cmdline") or []

                # Check 1: Known suspicious process names
                if name.replace(".exe", "") in SUSPICIOUS_PROCESS_NAMES:
                    findings.append(Finding(
                        title=f"Suspicious process detected: {name}",
                        description=(
                            f"Process '{name}' (PID {pid}) matches a known suspicious pattern. "
                            f"Running as: {username}. Executable: {exe}"
                        ),
                        severity=Severity.HIGH,
                        category="Malware Indicators",
                        scanner=self.name,
                        evidence={"pid": pid, "name": name, "exe": exe, "user": username},
                        remediation="Investigate this process. Verify its legitimacy and source.",
                    ))

                # Check 2: Executables running from suspicious directories
                if exe:
                    exe_lower = exe.lower().replace("\\", "/") if system == "windows" else exe
                    for sus_dir in suspicious_dirs:
                        normalized = sus_dir.replace("\\\\", "/").replace("\\", "/")
                        if normalized in exe_lower.replace("\\", "/"):
                            findings.append(Finding(
                                title=f"Process running from suspicious location: {name}",
                                description=(
                                    f"Process '{name}' (PID {pid}) is running from '{exe}', "
                                    f"which is an unusual location for legitimate software."
                                ),
                                severity=Severity.MEDIUM,
                                category="Malware Indicators",
                                scanner=self.name,
                                evidence={"pid": pid, "exe": exe, "suspicious_dir": sus_dir},
                                remediation="Verify this executable's origin and purpose.",
                            ))
                            break

                # Check 3: Processes with no executable path (potential memory-only)
                if not exe and pid > 4:  # pid 0-4 are system processes
                    # Many legitimate processes have no exe, so this is LOW
                    pass  # Too noisy — only flag in deep scan mode
                    if self.config.scan.depth.value == "deep":
                        findings.append(Finding(
                            title=f"Process with no executable path: {name}",
                            description=(
                                f"Process '{name}' (PID {pid}) has no associated executable path. "
                                "This can indicate a memory-only process."
                            ),
                            severity=Severity.LOW,
                            category="Process Anomaly",
                            scanner=self.name,
                            evidence={"pid": pid, "name": name},
                            remediation="Investigate this process if you do not recognize it.",
                        ))

                # Check 4: Processes running as SYSTEM/root from user-writable dirs
                is_privileged = False
                if system == "windows":
                    is_privileged = "system" in username.lower() or "admin" in username.lower()
                else:
                    is_privileged = username in ("root",)

                if is_privileged and exe:
                    exe_norm = exe.lower().replace("\\", "/")
                    for sus_dir in suspicious_dirs:
                        normalized = sus_dir.replace("\\\\", "/").replace("\\", "/")
                        if normalized in exe_norm:
                            findings.append(Finding(
                                title=f"Privileged process in suspicious location: {name}",
                                description=(
                                    f"Process '{name}' (PID {pid}) is running with elevated privileges "
                                    f"({username}) from '{exe}'. This is a strong anomaly indicator."
                                ),
                                severity=Severity.CRITICAL,
                                category="Malware Indicators",
                                scanner=self.name,
                                evidence={"pid": pid, "exe": exe, "user": username},
                                remediation="Immediately investigate this process. It may indicate compromise.",
                            ))
                            break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

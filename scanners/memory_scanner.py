"""
Sentinel Agent — Memory Scanner

Scans process memory for injection indicators and fileless malware.
Detects:
- RWX (read-write-execute) memory regions indicating code injection
- Process masquerading (system binaries running from wrong paths)
- Suspicious parent-child process relationships
- Hidden network-connected processes running from temp directories
- Memory-only executables with no backing file on disk

SECURITY: This scanner is read-only. It never modifies, terminates,
or injects into any process. All analysis is observational.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Any

import psutil

from core.config import AgentConfig, Severity
from core.logging import get_logger
from core.telemetry import Finding
from scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Processes known to use JIT compilation or legitimately map RWX memory
JIT_PROCESSES = {
    "java", "javaw", "node", "python", "python3", "ruby",
    "dotnet", "mono", "chrome", "firefox", "msedge", "opera",
    "electron", "code",  # VS Code
}

# System processes — legitimate binary paths per platform
WINDOWS_SYSTEM_BINARIES: dict[str, list[str]] = {
    "svchost.exe": ["c:\\windows\\system32\\"],
    "csrss.exe": ["c:\\windows\\system32\\"],
    "lsass.exe": ["c:\\windows\\system32\\"],
    "services.exe": ["c:\\windows\\system32\\"],
    "smss.exe": ["c:\\windows\\system32\\"],
    "wininit.exe": ["c:\\windows\\system32\\"],
    "winlogon.exe": ["c:\\windows\\system32\\"],
    "explorer.exe": ["c:\\windows\\"],
    "taskhost.exe": ["c:\\windows\\system32\\"],
    "conhost.exe": ["c:\\windows\\system32\\"],
    "dwm.exe": ["c:\\windows\\system32\\"],
    "spoolsv.exe": ["c:\\windows\\system32\\"],
}

LINUX_SYSTEM_BINARIES: dict[str, list[str]] = {
    "sshd": ["/usr/sbin/", "/usr/bin/"],
    "cron": ["/usr/sbin/"],
    "systemd": ["/lib/systemd/", "/usr/lib/systemd/"],
    "dbus-daemon": ["/usr/bin/"],
    "rsyslogd": ["/usr/sbin/"],
}

# Suspicious parent -> child process relationships.
# If a parent process spawns one of these children it is a strong indicator
# of macro-based malware, phishing payload execution, or living-off-the-land
# binary exploitation.
SUSPICIOUS_PARENT_CHILD: dict[str, set[str]] = {
    # Parent name (lower) -> set of suspicious child names (lower)
    "winword.exe": {
        "cmd.exe", "powershell.exe", "wscript.exe",
        "cscript.exe", "mshta.exe",
    },
    "excel.exe": {
        "cmd.exe", "powershell.exe", "wscript.exe",
        "cscript.exe", "mshta.exe",
    },
    "outlook.exe": {
        "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe",
    },
    "powerpnt.exe": {
        "cmd.exe", "powershell.exe", "wscript.exe",
    },
    "acrobat.exe": {
        "cmd.exe", "powershell.exe",
    },
    "acrord32.exe": {
        "cmd.exe", "powershell.exe",
    },
}

# Directories considered temporary / suspicious for outbound connections
_TEMP_DIRS_WINDOWS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\downloads\\",
]
_TEMP_DIRS_LINUX = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
]
_TEMP_DIRS_MACOS = [
    "/tmp/", "/var/tmp/", "/private/tmp/",
]

# Well-known system services that normally hold outbound connections
_KNOWN_NETWORK_SERVICES = {
    "svchost.exe", "system", "lsass.exe", "services.exe",
    "dns.exe", "sshd", "systemd-resolved", "networkmanager",
    "dnsmasq", "dhclient", "avahi-daemon", "chronyd", "ntpd",
    "cups", "cupsd", "update-manager", "snapd",
}


class MemoryScanner(BaseScanner):
    """Scans process memory for injection indicators and fileless malware."""

    @property
    def name(self) -> str:
        return "MemoryScanner"

    @property
    def description(self) -> str:
        return "Detects fileless malware via process memory and behavior analysis"

    @property
    def supported_platforms(self) -> list[str]:
        return ["all"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_platform() -> str:
        return platform.system().lower()

    @staticmethod
    def _is_jit_process(name: str) -> bool:
        """Return True if the process is known to legitimately use RWX memory."""
        base = name.lower().split(".")[0]
        return base in JIT_PROCESSES

    # ------------------------------------------------------------------
    # Check 1 — RWX memory regions
    # ------------------------------------------------------------------

    def _check_rwx_memory(self) -> list[Finding]:
        """Detect processes with read-write-execute memory regions.

        RWX regions are a hallmark of shellcode injection and in-memory
        payload execution.  Legitimate JIT engines are excluded.
        """
        findings: list[Finding] = []
        system = self._get_platform()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                proc_name = info.get("name") or ""

                # Skip known JIT / interpreter processes
                if self._is_jit_process(proc_name):
                    continue

                rwx_count = 0

                if system == "linux":
                    rwx_count = self._count_rwx_linux(pid)
                elif system == "darwin":
                    rwx_count = self._count_rwx_macos(pid)
                elif system == "windows":
                    rwx_count = self._count_rwx_windows(pid)

                if rwx_count > 0:
                    findings.append(Finding(
                        title=f"RWX memory regions detected in process: {proc_name}",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) has {rwx_count} "
                            f"read-write-execute memory region(s). This may indicate "
                            f"code injection or in-memory payload execution."
                        ),
                        severity=Severity.HIGH,
                        category="Malware Indicators",
                        scanner=self.name,
                        evidence={
                            "pid": pid,
                            "process_name": proc_name,
                            "rwx_region_count": rwx_count,
                        },
                        remediation=(
                            "Investigate this process for signs of code injection. "
                            "Dump and analyze the RWX regions if possible."
                        ),
                    ))

            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue
            except Exception as exc:  # pragma: no cover — defensive
                self.log.debug(f"RWX check skipped for process: {exc}")
                continue

        return findings

    # -- platform-specific RWX helpers --

    @staticmethod
    def _count_rwx_linux(pid: int) -> int:
        """Parse /proc/{pid}/maps for rwxp regions."""
        count = 0
        try:
            with open(f"/proc/{pid}/maps", "r") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and "rwxp" in parts[1]:
                        count += 1
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return count

    @staticmethod
    def _count_rwx_macos(pid: int) -> int:
        """Use vmmap to detect rwx regions on macOS."""
        count = 0
        try:
            result = subprocess.run(
                ["vmmap", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                lower = line.lower()
                if "r" in lower and "w" in lower and "x" in lower:
                    # vmmap shows permissions like "r-x/rwx" — look for rwx
                    if re.search(r'\brwx\b', lower):
                        count += 1
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return count

    @staticmethod
    def _count_rwx_windows(pid: int) -> int:
        """Heuristic RWX check on Windows via PowerShell module inspection.

        A full Virtual Memory query would require ctypes / VirtualQueryEx.
        As a lightweight proxy we inspect loaded modules for anomalies.
        Returns 0 for most normal processes (conservative).
        """
        count = 0
        try:
            cmd = (
                f"Get-Process -Id {pid} -ErrorAction Stop | "
                f"Select-Object -ExpandProperty Modules -ErrorAction Stop | "
                f"Where-Object {{ $_.ModuleName -eq $null }} | "
                f"Measure-Object | Select-Object -ExpandProperty Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.strip()
            if output.isdigit():
                count = int(output)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return count

    # ------------------------------------------------------------------
    # Check 2 — Process masquerading
    # ------------------------------------------------------------------

    def _check_process_masquerading(self) -> list[Finding]:
        """Detect system-critical binaries running from unexpected paths.

        Attackers frequently name their malware after legitimate Windows or
        Linux system processes to evade visual inspection.
        """
        findings: list[Finding] = []
        system = self._get_platform()

        if system == "windows":
            known_binaries = WINDOWS_SYSTEM_BINARIES
        elif system == "linux":
            known_binaries = LINUX_SYSTEM_BINARIES
        else:
            # macOS — no masquerading table defined yet
            return findings

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                proc_name = (info.get("name") or "").lower()
                exe_path = (info.get("exe") or "").lower()

                if not exe_path:
                    continue

                if proc_name in known_binaries:
                    expected_paths = known_binaries[proc_name]
                    if not any(exe_path.startswith(p) for p in expected_paths):
                        findings.append(Finding(
                            title=f"Process masquerading detected: {proc_name}",
                            description=(
                                f"Process '{proc_name}' (PID {pid}) is running from "
                                f"'{info.get('exe', '')}' which is outside its expected "
                                f"location(s): {expected_paths}."
                            ),
                            severity=Severity.HIGH,
                            category="Malware Indicators",
                            scanner=self.name,
                            evidence={
                                "pid": pid,
                                "process_name": proc_name,
                                "exe_path": info.get("exe", ""),
                                "expected_paths": expected_paths,
                            },
                            remediation=(
                                "Verify this binary's digital signature and hash. "
                                "A system process running from a non-standard path "
                                "is a strong indicator of compromise."
                            ),
                        ))

            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue
            except Exception as exc:  # pragma: no cover
                self.log.debug(f"Masquerading check skipped for process: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Check 3 — Suspicious parent-child relationships
    # ------------------------------------------------------------------

    def _check_suspicious_parent_child(self) -> list[Finding]:
        """Detect suspicious process spawn chains.

        For example, Microsoft Word spawning PowerShell or cmd.exe is a
        classic indicator of macro-based malware execution.
        """
        findings: list[Finding] = []

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                proc_name = (info.get("name") or "").lower()
                cmdline = info.get("cmdline") or []

                # Get parent process info
                try:
                    parent = proc.parent()
                    if parent is None:
                        continue
                    parent_name = (parent.name() or "").lower()
                    parent_pid = parent.pid
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                if parent_name in SUSPICIOUS_PARENT_CHILD:
                    suspicious_children = SUSPICIOUS_PARENT_CHILD[parent_name]
                    if proc_name in suspicious_children:
                        cmdline_str = " ".join(cmdline) if cmdline else ""
                        findings.append(Finding(
                            title=f"Suspicious process spawn chain: {parent_name} -> {proc_name}",
                            description=(
                                f"Process '{parent_name}' (PID {parent_pid}) spawned "
                                f"'{proc_name}' (PID {pid}). This pattern is commonly "
                                f"associated with macro-based malware or exploit payloads."
                            ),
                            severity=Severity.MEDIUM,
                            category="Behavioral Analysis",
                            scanner=self.name,
                            evidence={
                                "pid": pid,
                                "process_name": proc_name,
                                "parent_pid": parent_pid,
                                "parent_name": parent_name,
                                "child_cmdline": cmdline_str,
                            },
                            remediation=(
                                "Investigate the parent process and the command line "
                                "of the child. Check for recently opened documents or "
                                "email attachments."
                            ),
                        ))

            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue
            except Exception as exc:  # pragma: no cover
                self.log.debug(f"Parent-child check skipped: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Check 4 — Hidden network-connected processes
    # ------------------------------------------------------------------

    def _check_hidden_network_processes(self) -> list[Finding]:
        """Detect processes with active outbound connections running from
        temporary or suspicious directories.

        Malware often drops executables into temp folders and immediately
        opens C2 (command-and-control) connections.
        """
        findings: list[Finding] = []
        system = self._get_platform()

        if system == "windows":
            temp_dirs = _TEMP_DIRS_WINDOWS
        elif system == "darwin":
            temp_dirs = _TEMP_DIRS_MACOS
        else:
            temp_dirs = _TEMP_DIRS_LINUX

        # Build a set of PIDs with established TCP connections and their
        # remote endpoints.
        pid_connections: dict[int, list[tuple[str, int]]] = {}
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == "ESTABLISHED" and conn.pid:
                    raddr = conn.raddr
                    if raddr:
                        pid_connections.setdefault(conn.pid, []).append(
                            (raddr.ip, raddr.port),
                        )
        except (psutil.AccessDenied, PermissionError, OSError):
            # Cannot enumerate connections — return empty
            return findings

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                proc_name = (info.get("name") or "").lower()
                exe_path = info.get("exe") or ""

                if pid not in pid_connections:
                    continue

                # Skip well-known system network services
                if proc_name in _KNOWN_NETWORK_SERVICES:
                    continue

                # Check if the executable resides in a temp / suspicious dir
                exe_lower = exe_path.lower().replace("/", "\\") if system == "windows" else exe_path.lower()
                in_temp = any(td in exe_lower for td in temp_dirs)

                if not in_temp:
                    continue

                for remote_ip, remote_port in pid_connections[pid]:
                    findings.append(Finding(
                        title=f"Suspicious network process: {proc_name}",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) is running from a "
                            f"temporary directory ('{exe_path}') and has an active "
                            f"outbound connection to {remote_ip}:{remote_port}."
                        ),
                        severity=Severity.HIGH,
                        category="Malware Indicators",
                        scanner=self.name,
                        evidence={
                            "pid": pid,
                            "process_name": proc_name,
                            "exe_path": exe_path,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                        },
                        remediation=(
                            "Immediately investigate this process. An executable "
                            "running from a temp directory with outbound connections "
                            "is a strong indicator of malware or a C2 beacon."
                        ),
                    ))
                    # One finding per process is sufficient
                    break

            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue
            except Exception as exc:  # pragma: no cover
                self.log.debug(f"Hidden network check skipped: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Check 5 — Memory-only executables
    # ------------------------------------------------------------------

    def _check_memory_only_executables(self) -> list[Finding]:
        """Detect processes that have no backing executable on disk.

        Fileless malware often runs entirely in memory with no on-disk
        binary.  Kernel threads and idle processes are excluded.
        """
        findings: list[Finding] = []
        system = self._get_platform()

        # PIDs to always exclude (system idle, kernel, etc.)
        excluded_pids = {0}
        if system == "windows":
            excluded_pids.add(4)  # System process on Windows

        for proc in psutil.process_iter(["pid", "name", "status"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                proc_name = info.get("name") or ""
                status = info.get("status") or ""

                if pid in excluded_pids:
                    continue

                # On Linux, kernel threads show up with no exe — skip them
                if system == "linux" and proc_name.startswith("["):
                    continue

                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    # Cannot determine — do not flag
                    continue

                if not exe_path:
                    findings.append(Finding(
                        title=f"Memory-only process detected: {proc_name}",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) has no executable "
                            f"file on disk. Status: {status}. This may indicate "
                            f"fileless malware or a transient system process."
                        ),
                        severity=Severity.LOW,
                        category="Process Anomaly",
                        scanner=self.name,
                        evidence={
                            "pid": pid,
                            "process_name": proc_name,
                            "status": status,
                        },
                        remediation=(
                            "Investigate this process if it is not a recognized "
                            "system thread. Fileless malware operates entirely "
                            "in memory with no on-disk footprint."
                        ),
                    ))

            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue
            except Exception as exc:  # pragma: no cover
                self.log.debug(f"Memory-only check skipped: {exc}")
                continue

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        """Execute all memory and process behaviour checks."""
        findings: list[Finding] = []

        findings.extend(self._check_rwx_memory())
        findings.extend(self._check_process_masquerading())
        findings.extend(self._check_suspicious_parent_child())
        findings.extend(self._check_hidden_network_processes())
        findings.extend(self._check_memory_only_executables())

        return findings

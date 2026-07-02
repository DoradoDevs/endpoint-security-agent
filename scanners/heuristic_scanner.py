"""
Sentinel Agent — Behavioral Heuristic Engine

Runtime behavioral analysis to detect active threats including:
- Ransomware activity (ransom notes, mass encryption)
- Cryptominer processes (high CPU, mining pool connections, CLI patterns)
- Remote Access Trojan (RAT) behavior (suspicious parent-child chains, reverse shells)
- Lateral movement (SMB/RDP/WinRM usage, PsExec, WMIC)
- DNS tunneling (excessively long subdomains)

SECURITY: This scanner performs read-only analysis of system state.
No processes are terminated or modified. All findings are advisory.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known mining pool domains
MINING_POOL_DOMAINS = {
    "pool.minexmr.com", "xmr.nanopool.org", "xmr.2miners.com",
    "pool.hashvault.pro", "gulf.moneroocean.stream",
    "xmr-eu1.nanopool.org", "xmr-eu2.nanopool.org",
    "pool.supportxmr.com", "xmrpool.eu",
    "ethermine.org", "ethpool.org", "f2pool.com",
    "nicehash.com", "minergate.com", "antpool.com",
    "slushpool.com", "poolin.com", "viabtc.com",
    "2miners.com", "unmineable.com",
}

# Mining-related command line arguments
MINING_CLI_PATTERNS = [
    "--algo", "--threads", "--donate-level",
    "stratum+tcp://", "stratum+ssl://",
    "-o pool.", "--coin", "--randomx",
    "cryptonight", "--cuda", "--opencl",
]

# Ransom note filename patterns (partial match, case-insensitive)
RANSOM_NOTE_NAMES = [
    "DECRYPT", "RECOVER", "RANSOM", "README_DECRYPT",
    "HOW_TO_RECOVER", "YOUR_FILES", "RESTORE_FILES",
    "HELP_DECRYPT", "HOW_TO_DECRYPT", "ATTENTION",
    "_readme.txt", "!README!", "DECRYPT_INSTRUCTION",
]

# File extensions indicating ransomware encryption
ENCRYPTED_EXTENSIONS = {
    ".encrypted", ".locked", ".crypted", ".crypt", ".enc",
    ".locky", ".cerber", ".zepto", ".thor", ".aaa",
    ".abc", ".xyz", ".zzz", ".micro", ".vvv",
}

# Suspicious parent-child process chains
SUSPICIOUS_SPAWNS = {
    "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "outlook.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "powerpnt.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
}

# Ports used for lateral movement
_LATERAL_MOVEMENT_PORTS = {
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}

# Shell process names used by reverse-shell detection
_SHELL_NAMES = {"bash", "sh", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh"}

# Reverse-shell cmdline indicators
_REVERSE_SHELL_INDICATORS = ["/dev/tcp", "0>&1", "2>&1", " -i"]

# Temp / download directories (lowercased for comparison)
_TEMP_DIRS_UNIX = ["/tmp/", "/var/tmp/", "/dev/shm/"]
_TEMP_DIRS_WINDOWS = ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class HeuristicScanner(BaseScanner):
    """Detects active threats by runtime behavioral analysis."""

    @property
    def name(self) -> str:
        return "HeuristicScanner"

    @property
    def description(self) -> str:
        return "Behavioral analysis for ransomware, cryptominers, RATs, and other active threats"

    @property
    def supported_platforms(self) -> list[str]:
        return ["all"]

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_ransomware())
        findings.extend(self._detect_cryptominers())
        findings.extend(self._detect_rat_behavior())
        findings.extend(self._detect_lateral_movement())
        findings.extend(self._detect_dns_tunneling())
        return findings

    # ------------------------------------------------------------------
    # Ransomware detection
    # ------------------------------------------------------------------

    def _detect_ransomware(self) -> list[Finding]:
        findings: list[Finding] = []
        home = Path.home()
        system = platform.system().lower()

        # Directories to scan for ransom notes and encrypted files
        scan_dirs: list[Path] = [home]
        if system == "windows":
            desktop = home / "Desktop"
            documents = home / "Documents"
        elif system == "darwin":
            desktop = home / "Desktop"
            documents = home / "Documents"
        else:
            desktop = home / "Desktop"
            documents = home / "Documents"
        for d in (desktop, documents):
            if d.exists():
                scan_dirs.append(d)

        # --- Ransom note check ---
        ransom_notes_found: list[str] = []
        for scan_dir in scan_dirs:
            try:
                with os.scandir(str(scan_dir)) as entries:
                    for entry in entries:
                        if not entry.is_file():
                            continue
                        fname_upper = entry.name.upper()
                        for pattern in RANSOM_NOTE_NAMES:
                            if pattern.upper() in fname_upper:
                                ransom_notes_found.append(entry.path)
                                break
            except (PermissionError, OSError):
                continue

        if ransom_notes_found:
            findings.append(Finding(
                title="Ransom note(s) detected on disk",
                description=(
                    f"Found {len(ransom_notes_found)} file(s) matching known ransom note "
                    f"naming patterns. This is a strong indicator of ransomware activity."
                ),
                severity=Severity.CRITICAL,
                category="Malware Indicators",
                scanner=self.name,
                evidence={
                    "ransom_notes": ransom_notes_found,
                    "path": ransom_notes_found[0],
                },
                remediation=(
                    "Immediately isolate this system from the network. Do NOT pay "
                    "the ransom. Preserve evidence and engage incident response."
                ),
            ))

        # --- Mass encryption check ---
        encrypted_count = 0
        sample_files: list[str] = []
        extensions_found: set[str] = set()

        mass_dirs = [d for d in (desktop, documents) if d.exists()]
        for scan_dir in mass_dirs:
            try:
                with os.scandir(str(scan_dir)) as entries:
                    for entry in entries:
                        if not entry.is_file():
                            continue
                        _, ext = os.path.splitext(entry.name)
                        if ext.lower() in ENCRYPTED_EXTENSIONS:
                            encrypted_count += 1
                            extensions_found.add(ext.lower())
                            if len(sample_files) < 10:
                                sample_files.append(entry.path)
            except (PermissionError, OSError):
                continue

        if encrypted_count > 5:
            findings.append(Finding(
                title="Mass file encryption detected",
                description=(
                    f"Found {encrypted_count} files with ransomware-associated "
                    f"extensions in user directories. Extensions: "
                    f"{', '.join(sorted(extensions_found))}"
                ),
                severity=Severity.CRITICAL,
                category="Malware Indicators",
                scanner=self.name,
                evidence={
                    "encrypted_count": encrypted_count,
                    "sample_files": sample_files,
                    "extensions": sorted(extensions_found),
                },
                remediation=(
                    "Immediately isolate this system. Determine the ransomware "
                    "variant and check for available decryptors."
                ),
            ))

        # --- Canary file check (sentinel data dir) ---
        data_dir = self.config.log_dir.parent if self.config.log_dir else None
        if data_dir:
            canary_path = data_dir / ".sentinel_canary"
            if canary_path.exists():
                try:
                    content = canary_path.read_text().strip()
                    if content != "SENTINEL_CANARY_OK":
                        findings.append(Finding(
                            title="Sentinel canary file tampered",
                            description=(
                                "The sentinel canary file has been modified, which may "
                                "indicate ransomware has encrypted files in the data directory."
                            ),
                            severity=Severity.CRITICAL,
                            category="Malware Indicators",
                            scanner=self.name,
                            evidence={
                                "canary_path": str(canary_path),
                                "canary_status": "tampered",
                            },
                            remediation="Investigate immediately — canary file modification suggests active ransomware.",
                        ))
                except (PermissionError, OSError):
                    pass

        return findings

    # ------------------------------------------------------------------
    # Cryptominer detection
    # ------------------------------------------------------------------

    def _detect_cryptominers(self) -> list[Finding]:
        findings: list[Finding] = []

        try:
            procs: list[Any] = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
                try:
                    proc.cpu_percent(interval=0)
                    procs.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Brief pause to allow cpu_percent to accumulate a meaningful delta
            time.sleep(0.1)

            # Collect top CPU consumers
            cpu_data: list[tuple[Any, float]] = []
            for proc in procs:
                try:
                    cpu = proc.cpu_percent(interval=0)
                    cpu_data.append((proc, cpu))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Sort descending by CPU and take top 10
            cpu_data.sort(key=lambda x: x[1], reverse=True)
            top_procs = cpu_data[:10]

            for proc, cpu in top_procs:
                if cpu <= 80.0:
                    continue

                pid = proc.pid
                try:
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                # Retrieve command line
                cmdline_str = ""
                try:
                    cmdline = proc.cmdline()
                    cmdline_str = " ".join(cmdline)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cmdline = []

                mining_indicators: list[str] = []

                # Check for mining CLI patterns
                cmdline_lower = cmdline_str.lower()
                for pattern in MINING_CLI_PATTERNS:
                    if pattern.lower() in cmdline_lower:
                        mining_indicators.append(f"cli:{pattern}")

                # Check network connections for mining pool domains
                connections_evidence: list[dict[str, Any]] = []
                try:
                    conns = proc.net_connections(kind="inet")
                    for conn in conns:
                        if conn.raddr:
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            connections_evidence.append({
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                            })
                            # Attempt reverse DNS lookup
                            try:
                                hostname = socket.gethostbyaddr(remote_ip)[0]
                                for domain in MINING_POOL_DOMAINS:
                                    if domain in hostname.lower():
                                        mining_indicators.append(f"pool:{domain}")
                            except (socket.herror, socket.gaierror, OSError):
                                pass
                            # Also check raw IP against domain set (in case
                            # the domain resolves differently)
                            for domain in MINING_POOL_DOMAINS:
                                if domain in remote_ip:
                                    mining_indicators.append(f"pool:{domain}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                evidence = {
                    "pid": pid,
                    "process_name": proc_name,
                    "cpu_percent": cpu,
                    "cmdline": cmdline_str,
                    "mining_indicators": mining_indicators,
                    "connections": connections_evidence,
                }

                if mining_indicators:
                    findings.append(Finding(
                        title=f"Cryptominer activity detected: {proc_name} (PID {pid})",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) is consuming {cpu:.0f}% CPU "
                            f"and exhibits mining indicators: {', '.join(mining_indicators)}."
                        ),
                        severity=Severity.HIGH,
                        category="Malware Indicators",
                        scanner=self.name,
                        evidence=evidence,
                        remediation="Terminate the process and investigate how it was installed.",
                    ))
                else:
                    findings.append(Finding(
                        title=f"Suspicious high CPU usage: {proc_name} (PID {pid})",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) is consuming {cpu:.0f}% CPU "
                            f"without clear mining indicators. Could be a miner or legitimate workload."
                        ),
                        severity=Severity.MEDIUM,
                        category="Behavioral Analysis",
                        scanner=self.name,
                        evidence=evidence,
                        remediation="Investigate the process to determine if it is legitimate.",
                    ))

        except (psutil.AccessDenied, PermissionError, OSError) as exc:
            self.log.debug(f"Cryptominer detection limited: {exc}")

        return findings

    # ------------------------------------------------------------------
    # RAT / reverse-shell detection
    # ------------------------------------------------------------------

    def _detect_rat_behavior(self) -> list[Finding]:
        findings: list[Finding] = []

        # --- 1. Suspicious parent-child chains ---
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    child_name = (proc.name() or "").lower()
                    parent = proc.parent()
                    if parent is None:
                        continue
                    parent_name = (parent.name() or "").lower()

                    if parent_name in SUSPICIOUS_SPAWNS:
                        allowed_children = SUSPICIOUS_SPAWNS[parent_name]
                        if child_name in allowed_children:
                            findings.append(Finding(
                                title=f"Suspicious process chain: {parent_name} -> {child_name}",
                                description=(
                                    f"'{parent_name}' spawned '{child_name}' (PID {proc.pid}). "
                                    f"Office applications spawning shell/script interpreters is "
                                    f"a common malware delivery technique."
                                ),
                                severity=Severity.HIGH,
                                category="Behavioral Analysis",
                                scanner=self.name,
                                evidence={
                                    "pid": proc.pid,
                                    "process_name": child_name,
                                    "parent_pid": parent.pid,
                                    "parent_name": parent_name,
                                },
                                remediation=(
                                    "Investigate the parent document for macros or exploits. "
                                    "Terminate the child process if unauthorized."
                                ),
                            ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        # --- 2. Reverse shell indicators ---
        try:
            now = time.time()
            for proc in psutil.process_iter(["pid", "name", "create_time"]):
                try:
                    proc_name = (proc.name() or "").lower()
                    if proc_name.replace(".exe", "") not in _SHELL_NAMES and proc_name not in _SHELL_NAMES:
                        continue

                    # Only look at recently started shells (< 1 hour)
                    create_time = proc.create_time()
                    if now - create_time > 3600:
                        continue

                    cmdline_str = ""
                    try:
                        cmdline_str = " ".join(proc.cmdline())
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    # Check for reverse-shell cmdline indicators
                    has_shell_indicator = False
                    for indicator in _REVERSE_SHELL_INDICATORS:
                        if indicator in cmdline_str:
                            has_shell_indicator = True
                            break

                    # Check for a single ESTABLISHED TCP connection
                    try:
                        conns = proc.net_connections(kind="inet")
                        established = [
                            c for c in conns
                            if c.status == "ESTABLISHED" and c.raddr
                        ]
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        established = []

                    if has_shell_indicator and len(established) >= 1:
                        conn = established[0]
                        findings.append(Finding(
                            title=f"Possible reverse shell: {proc_name} (PID {proc.pid})",
                            description=(
                                f"Shell process '{proc_name}' (PID {proc.pid}) has reverse-shell "
                                f"indicators in its command line and an established TCP connection "
                                f"to {conn.raddr.ip}:{conn.raddr.port}."
                            ),
                            severity=Severity.CRITICAL,
                            category="Behavioral Analysis",
                            scanner=self.name,
                            evidence={
                                "pid": proc.pid,
                                "process_name": proc_name,
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                                "cmdline": cmdline_str,
                            },
                            remediation=(
                                "Immediately terminate this process and block the remote IP. "
                                "Investigate for additional compromise."
                            ),
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        # --- 3. Suspicious outbound from temp directories ---
        system = platform.system().lower()
        temp_markers = _TEMP_DIRS_WINDOWS if system == "windows" else _TEMP_DIRS_UNIX

        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    exe_path = proc.exe() or ""
                    if not exe_path:
                        continue

                    exe_lower = exe_path.lower().replace("\\", "/")
                    in_temp = False
                    for marker in temp_markers:
                        normalized = marker.replace("\\", "/").lower()
                        if normalized in exe_lower:
                            in_temp = True
                            break

                    if not in_temp:
                        continue

                    # Check for active outbound TCP connections
                    try:
                        conns = proc.net_connections(kind="inet")
                        outbound = [
                            c for c in conns
                            if c.status == "ESTABLISHED" and c.raddr
                        ]
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        outbound = []

                    if outbound:
                        conn = outbound[0]
                        findings.append(Finding(
                            title=f"Temp-directory process with network activity: {proc.name()}",
                            description=(
                                f"Process '{proc.name()}' (PID {proc.pid}) is running from "
                                f"a temporary directory ('{exe_path}') and has active outbound "
                                f"connections. This is a common RAT/dropper pattern."
                            ),
                            severity=Severity.HIGH,
                            category="Behavioral Analysis",
                            scanner=self.name,
                            evidence={
                                "pid": proc.pid,
                                "exe_path": exe_path,
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                            },
                            remediation=(
                                "Investigate this process. Executables in temp directories "
                                "with network connections are suspicious."
                            ),
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        return findings

    # ------------------------------------------------------------------
    # Lateral movement detection
    # ------------------------------------------------------------------

    def _detect_lateral_movement(self) -> list[Finding]:
        findings: list[Finding] = []

        # --- 1. Connections on lateral-movement ports ---
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue

                remote_port = conn.raddr.port
                if remote_port not in _LATERAL_MOVEMENT_PORTS:
                    continue

                protocol = _LATERAL_MOVEMENT_PORTS[remote_port]
                pid = conn.pid
                proc_name = ""
                is_system_service = False

                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name() or ""
                        # Heuristic: consider certain well-known system processes
                        # as system services rather than user-initiated activity
                        system_procs = {"svchost.exe", "services.exe", "lsass.exe",
                                        "system", "systemd", "init", "launchd"}
                        if proc_name.lower() in system_procs:
                            is_system_service = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "unknown"

                if not is_system_service:
                    findings.append(Finding(
                        title=f"Lateral movement detected: {protocol} to {conn.raddr.ip}",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) has an established "
                            f"{protocol} connection to {conn.raddr.ip}:{remote_port}. "
                            f"This may indicate lateral movement activity."
                        ),
                        severity=Severity.MEDIUM,
                        category="Behavioral Analysis",
                        scanner=self.name,
                        evidence={
                            "pid": pid,
                            "process_name": proc_name,
                            "remote_ip": conn.raddr.ip,
                            "remote_port": remote_port,
                            "protocol": protocol,
                        },
                        remediation=f"Verify that the {protocol} connection is authorized.",
                    ))
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        # --- 2. PsExec detection ---
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pname = (proc.name() or "").lower()
                    if pname in ("psexesvc.exe", "psexesvc"):
                        findings.append(Finding(
                            title=f"PsExec service detected (PID {proc.pid})",
                            description=(
                                f"The PsExec remote execution service is running "
                                f"(PID {proc.pid}). PsExec is commonly abused for "
                                f"lateral movement."
                            ),
                            severity=Severity.HIGH,
                            category="Behavioral Analysis",
                            scanner=self.name,
                            evidence={
                                "pid": proc.pid,
                                "process_name": pname,
                            },
                            remediation="Verify PsExec usage is authorized. Remove if not needed.",
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        # --- 3. WMIC remote execution ---
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmdline = proc.cmdline() or []
                    cmdline_str = " ".join(cmdline).lower()
                    if "wmic" in cmdline_str and "/node:" in cmdline_str:
                        findings.append(Finding(
                            title=f"Remote WMIC execution detected (PID {proc.pid})",
                            description=(
                                f"Process '{proc.name()}' (PID {proc.pid}) is executing "
                                f"WMIC with /node: targeting a remote host. This is "
                                f"commonly used for lateral movement."
                            ),
                            severity=Severity.HIGH,
                            category="Behavioral Analysis",
                            scanner=self.name,
                            evidence={
                                "pid": proc.pid,
                                "process_name": proc.name(),
                                "cmdline": " ".join(cmdline),
                            },
                            remediation="Verify WMIC remote execution is authorized.",
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

        return findings

    # ------------------------------------------------------------------
    # DNS tunneling detection
    # ------------------------------------------------------------------

    def _detect_dns_tunneling(self) -> list[Finding]:
        findings: list[Finding] = []
        system = platform.system().lower()

        if system != "windows":
            # DNS cache inspection via ipconfig is Windows-only
            return findings

        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout

            # Parse record names from the output
            record_pattern = re.compile(r"Record Name[\s.]+:\s+(.+)", re.IGNORECASE)
            domain_counts: dict[str, int] = {}
            suspicious_domains: list[str] = []
            max_subdomain_length = 0

            for match in record_pattern.finditer(output):
                fqdn = match.group(1).strip()
                parts = fqdn.split(".")

                # Compute the longest subdomain label length
                for part in parts:
                    if len(part) > max_subdomain_length:
                        max_subdomain_length = len(part)

                # Check for excessively long subdomains (DNS tunneling indicator)
                for part in parts:
                    if len(part) > 50:
                        suspicious_domains.append(fqdn)
                        break

                # Track query frequency per base domain
                if len(parts) >= 2:
                    base_domain = ".".join(parts[-2:])
                    domain_counts[base_domain] = domain_counts.get(base_domain, 0) + 1

            # Flag domains with unusually high query frequency
            for domain, count in domain_counts.items():
                if count > 50:
                    suspicious_domains.append(f"{domain} (freq:{count})")

            if suspicious_domains:
                # Deduplicate
                unique_domains = sorted(set(suspicious_domains))
                findings.append(Finding(
                    title="Potential DNS tunneling activity detected",
                    description=(
                        f"Found {len(unique_domains)} suspicious DNS pattern(s): "
                        f"long subdomains or high-frequency queries that may indicate "
                        f"DNS tunneling or data exfiltration."
                    ),
                    severity=Severity.MEDIUM,
                    category="Behavioral Analysis",
                    scanner=self.name,
                    evidence={
                        "suspicious_domains": unique_domains[:20],
                        "max_subdomain_length": max_subdomain_length,
                    },
                    remediation=(
                        "Investigate the flagged domains. DNS tunneling is used "
                        "for C2 communication and data exfiltration."
                    ),
                ))

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as exc:
            self.log.debug(f"DNS tunneling detection failed: {exc}")

        return findings

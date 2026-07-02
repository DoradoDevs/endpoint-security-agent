"""
Sentinel Agent — Live IOC Correlator Scanner

Cross-references running system artifacts (processes, network connections,
DNS cache, loaded modules, listening ports) against the IOC threat
intelligence database. Produces CRITICAL/HIGH findings when live indicators
match known-bad entries.

Phase E of the Sentinel v3.5 threat hunting expansion.
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
from pathlib import Path
from typing import Any

from core.config import AgentConfig, Severity
from core.logging import get_logger
from core.telemetry import Finding
from scanners.base import BaseScanner

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

try:
    from threat_intel.ioc_database import IOCDatabase
except ImportError:  # pragma: no cover
    IOCDatabase = None  # type: ignore[assignment,misc]

logger = get_logger()

# ── Known RAT / backdoor default ports ──────────────────────────────────────
KNOWN_MALWARE_PORTS: dict[int, str] = {
    4444: "Metasploit default handler",
    1337: "Various backdoors / leet port",
    5555: "Android Debug Bridge (remote exploitation)",
    31337: "Back Orifice",
    8888: "Common backdoor / proxy port",
    9999: "Common backdoor / RAT port",
    12345: "NetBus trojan",
    65535: "Unusual high port (often used by malware)",
}

# ── System directories to exclude from loaded-module hashing ────────────────
_SYSTEM_DIRS_WINDOWS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\assembly",
    "c:\\program files",
    "c:\\program files (x86)",
]

_SYSTEM_DIRS_LINUX = [
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/local/lib",
]

_SYSTEM_DIRS_MACOS = [
    "/usr/lib",
    "/System/Library",
    "/Library/Apple",
]


def _system_dirs() -> list[str]:
    """Return normalised system directories for the current platform."""
    system = platform.system().lower()
    if system == "windows":
        return _SYSTEM_DIRS_WINDOWS
    if system == "darwin":
        return _SYSTEM_DIRS_MACOS
    return _SYSTEM_DIRS_LINUX


class IOCScanner(BaseScanner):
    """Cross-references running system against threat intelligence database."""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self._hash_cache: dict[str, str] = {}
        self._ioc_db: IOCDatabase | None = None

    # ── BaseScanner interface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "IOCScanner"

    @property
    def description(self) -> str:
        return "Cross-references running system against threat intelligence database"

    @property
    def supported_platforms(self) -> list[str]:
        return ["all"]

    # ── Main scan entry point ───────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """Execute all IOC correlation checks and return findings."""
        findings: list[Finding] = []

        if psutil is None:
            self.log.warning("psutil not available — IOCScanner cannot run")
            return findings

        # Initialise the IOC database (best-effort)
        self._init_ioc_db()
        if self._ioc_db is None:
            self.log.warning("IOC database unavailable — IOCScanner cannot run")
            return findings

        findings.extend(self._check_process_hashes())
        findings.extend(self._check_active_connections())
        findings.extend(self._check_dns_cache())
        findings.extend(self._check_loaded_modules())
        findings.extend(self._check_malware_ports())

        return findings

    # ── IOC database initialisation ─────────────────────────────────────────

    def _init_ioc_db(self) -> None:
        """Instantiate and load the IOCDatabase, swallowing errors."""
        if IOCDatabase is None:
            return
        try:
            self._ioc_db = IOCDatabase()
            self._ioc_db.load()
        except Exception as exc:
            self.log.debug(f"Failed to initialise IOC database: {exc}")
            self._ioc_db = None

    # ── Check 1: Process executable hash check ──────────────────────────────

    def _check_process_hashes(self) -> list[Finding]:
        """Hash each running process executable and look up in IOC database."""
        findings: list[Finding] = []

        for proc in psutil.process_iter():
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except OSError:
                continue

            if not exe_path:
                continue

            sha256 = self._hash_file(exe_path)
            if sha256 is None:
                continue

            entry = self._ioc_db.lookup_hash(sha256)
            if entry is not None:
                try:
                    proc_name = proc.name()
                    pid = proc.pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"
                    pid = 0

                findings.append(Finding(
                    title=f"Malicious process executable detected: {proc_name}",
                    description=(
                        f"Process '{proc_name}' (PID {pid}) executable matches "
                        f"known {entry.threat_category.value} indicator from "
                        f"'{entry.source}'. SHA-256: {sha256}"
                    ),
                    severity=Severity.CRITICAL,
                    category="Threat Intelligence",
                    scanner=self.name,
                    evidence={
                        "pid": pid,
                        "process_name": proc_name,
                        "exe_path": exe_path,
                        "sha256": sha256,
                        "ioc_type": entry.ioc_type.value,
                        "threat_category": entry.threat_category.value,
                        "source": entry.source,
                        "confidence": entry.confidence,
                    },
                    remediation=(
                        f"Immediately investigate PID {pid} ({proc_name}). "
                        f"The executable at '{exe_path}' matches known "
                        f"{entry.threat_category.value} malware. Consider "
                        "terminating the process and quarantining the file."
                    ),
                ))

        return findings

    # ── Check 2: Active connection IP check ─────────────────────────────────

    def _check_active_connections(self) -> list[Finding]:
        """Check remote IPs of established/SYN_SENT connections against IOCs."""
        findings: list[Finding] = []

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            self.log.debug(f"Cannot enumerate connections: {exc}")
            return findings

        for conn in connections:
            # Only interested in outbound / established connections
            if conn.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip if hasattr(conn.raddr, "ip") else conn.raddr[0]
            remote_port = conn.raddr.port if hasattr(conn.raddr, "port") else conn.raddr[1]

            entry = self._ioc_db.lookup_ip(remote_ip)
            if entry is None:
                continue

            # Try to resolve the owning process
            proc_name = "unknown"
            pid = conn.pid or 0
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"

            findings.append(Finding(
                title=f"Connection to known malicious IP: {remote_ip}",
                description=(
                    f"Process '{proc_name}' (PID {pid}) has an active connection "
                    f"to {remote_ip}:{remote_port}, which is a known "
                    f"{entry.threat_category.value} indicator from '{entry.source}'."
                ),
                severity=Severity.CRITICAL,
                category="Threat Intelligence",
                scanner=self.name,
                evidence={
                    "pid": pid,
                    "process_name": proc_name,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "ioc_type": entry.ioc_type.value,
                    "threat_category": entry.threat_category.value,
                    "source": entry.source,
                },
                remediation=(
                    f"Investigate the connection from PID {pid} ({proc_name}) "
                    f"to {remote_ip}:{remote_port}. This IP is associated with "
                    f"{entry.threat_category.value} activity. Consider blocking "
                    "the IP and terminating the process."
                ),
            ))

        return findings

    # ── Check 3: DNS cache domain check ─────────────────────────────────────

    def _check_dns_cache(self) -> list[Finding]:
        """Parse DNS cache / hosts file and check domains against IOCs."""
        findings: list[Finding] = []
        system = platform.system().lower()

        if system == "windows":
            findings.extend(self._check_windows_dns_cache())
        else:
            findings.extend(self._check_linux_hosts_file())

        return findings

    def _check_windows_dns_cache(self) -> list[Finding]:
        """Parse ``ipconfig /displaydns`` output for malicious domains."""
        findings: list[Finding] = []

        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self.log.debug(f"DNS cache retrieval failed: {exc}")
            return findings

        current_domain: str | None = None
        resolved_ip: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            # Record Name lines contain the domain
            if "Record Name" in stripped and ":" in stripped:
                current_domain = stripped.split(":", 1)[1].strip().rstrip(".")
                resolved_ip = None
            # A (Host) Record lines contain the resolved IP
            elif ("A (Host)" in stripped or "AAAA" in stripped) and ":" in stripped:
                resolved_ip = stripped.split(":", 1)[1].strip()
            # Section separator — check what we have so far
            elif stripped == "" and current_domain:
                self._check_domain_ioc(current_domain, resolved_ip, findings)
                current_domain = None
                resolved_ip = None

        # Handle last entry (no trailing blank line)
        if current_domain:
            self._check_domain_ioc(current_domain, resolved_ip, findings)

        return findings

    def _check_linux_hosts_file(self) -> list[Finding]:
        """Scan /etc/hosts for suspicious non-standard entries."""
        findings: list[Finding] = []
        hosts_path = Path("/etc/hosts")

        if not hosts_path.exists():
            return findings

        # Standard entries that are expected in /etc/hosts
        standard_hosts = {
            "localhost",
            "localhost.localdomain",
            "ip6-localhost",
            "ip6-loopback",
            "ip6-localnet",
            "ip6-mcastprefix",
            "ip6-allnodes",
            "ip6-allrouters",
        }

        try:
            content = hosts_path.read_text()
        except OSError as exc:
            self.log.debug(f"Cannot read /etc/hosts: {exc}")
            return findings

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            ip_addr = parts[0]
            for hostname in parts[1:]:
                hostname = hostname.lower().rstrip(".")
                if hostname in standard_hosts:
                    continue
                self._check_domain_ioc(hostname, ip_addr, findings)

        return findings

    def _check_domain_ioc(
        self,
        domain: str,
        resolved_ip: str | None,
        findings: list[Finding],
    ) -> None:
        """Look up a single domain in the IOC database and append finding."""
        entry = self._ioc_db.lookup_domain(domain)
        if entry is None:
            return

        evidence: dict[str, Any] = {
            "domain": domain,
            "ioc_type": entry.ioc_type.value,
            "threat_category": entry.threat_category.value,
        }
        if resolved_ip:
            evidence["resolved_ip"] = resolved_ip

        findings.append(Finding(
            title=f"Malicious domain in DNS cache: {domain}",
            description=(
                f"Domain '{domain}' found in DNS cache / hosts file matches "
                f"known {entry.threat_category.value} indicator from "
                f"'{entry.source}'."
            ),
            severity=Severity.HIGH,
            category="Threat Intelligence",
            scanner=self.name,
            evidence=evidence,
            remediation=(
                f"Investigate DNS resolution of '{domain}'. It is associated "
                f"with {entry.threat_category.value} activity. Flush the DNS "
                "cache and check for processes communicating with this domain."
            ),
        ))

    # ── Check 4: Loaded module check ────────────────────────────────────────

    def _check_loaded_modules(self) -> list[Finding]:
        """Hash non-system loaded modules and check against IOC database."""
        findings: list[Finding] = []
        system_dirs = _system_dirs()

        for proc in psutil.process_iter():
            try:
                pid = proc.pid
                proc_name = proc.name()
                maps = proc.memory_maps()
            except (
                psutil.AccessDenied,
                psutil.NoSuchProcess,
                psutil.ZombieProcess,
                OSError,
            ):
                continue

            for mmap in maps:
                module_path = mmap.path if hasattr(mmap, "path") else str(mmap)

                # Skip modules in known system directories
                if self._is_system_path(module_path, system_dirs):
                    continue

                # Skip non-file entries (e.g. [heap], [stack], anon regions)
                if not module_path or module_path.startswith("["):
                    continue

                sha256 = self._hash_file(module_path)
                if sha256 is None:
                    continue

                entry = self._ioc_db.lookup_hash(sha256)
                if entry is not None:
                    findings.append(Finding(
                        title=f"Malicious loaded module detected: {Path(module_path).name}",
                        description=(
                            f"Process '{proc_name}' (PID {pid}) has loaded module "
                            f"'{module_path}' which matches known "
                            f"{entry.threat_category.value} indicator."
                        ),
                        severity=Severity.HIGH,
                        category="Threat Intelligence",
                        scanner=self.name,
                        evidence={
                            "pid": pid,
                            "process_name": proc_name,
                            "module_path": module_path,
                            "sha256": sha256,
                            "ioc_type": entry.ioc_type.value,
                        },
                        remediation=(
                            f"Investigate module '{module_path}' loaded by "
                            f"process '{proc_name}' (PID {pid}). It matches "
                            "a known threat indicator. Consider terminating the "
                            "process and quarantining the module."
                        ),
                    ))

        return findings

    # ── Check 5: Known malware port check ───────────────────────────────────

    def _check_malware_ports(self) -> list[Finding]:
        """Check if any process is listening on known RAT/backdoor ports."""
        findings: list[Finding] = []

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            self.log.debug(f"Cannot enumerate connections for port check: {exc}")
            return findings

        for conn in connections:
            if conn.status != "LISTEN":
                continue
            if not conn.laddr:
                continue

            local_port = conn.laddr.port if hasattr(conn.laddr, "port") else conn.laddr[1]

            if local_port not in KNOWN_MALWARE_PORTS:
                continue

            known_threat = KNOWN_MALWARE_PORTS[local_port]
            pid = conn.pid or 0
            proc_name = "unknown"

            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"

            findings.append(Finding(
                title=f"Listening on known malware port: {local_port}",
                description=(
                    f"Process '{proc_name}' (PID {pid}) is listening on port "
                    f"{local_port}, commonly associated with {known_threat}."
                ),
                severity=Severity.MEDIUM,
                category="Threat Intelligence",
                scanner=self.name,
                evidence={
                    "pid": pid,
                    "process_name": proc_name,
                    "port": local_port,
                    "known_threat": known_threat,
                },
                remediation=(
                    f"Verify that the service on port {local_port} (PID {pid}, "
                    f"'{proc_name}') is legitimate. Port {local_port} is "
                    f"commonly used by {known_threat}."
                ),
            ))

        return findings

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _hash_file(self, file_path: str) -> str | None:
        """Compute SHA-256 hash of a file, using the cache when possible."""
        if file_path in self._hash_cache:
            return self._hash_cache[file_path]

        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            digest = h.hexdigest()
            self._hash_cache[file_path] = digest
            return digest
        except (OSError, PermissionError):
            return None

    @staticmethod
    def _is_system_path(path: str, system_dirs: list[str]) -> bool:
        """Check whether *path* resides inside a known system directory."""
        normalised = path.lower().replace("\\", "/")
        for sys_dir in system_dirs:
            if normalised.startswith(sys_dir.lower().replace("\\", "/")):
                return True
        return False

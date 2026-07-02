"""
Sentinel Agent — Service Audit Scanner

Audits running services for security risks:
- Known risky/unnecessary services
- Services running from writable paths
- Services with excessive privileges
"""

from __future__ import annotations

import platform
import subprocess

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner
from os_modules.loader import load_os_module


# Services that are risky if running unnecessarily
RISKY_SERVICES_WINDOWS = {
    "TlntSvr": ("Telnet Server", "critical", "Unencrypted remote access protocol"),
    "TFTP": ("TFTP Server", "high", "Trivial file transfer — no authentication"),
    "FTPSVC": ("FTP Server", "medium", "Consider SFTP instead"),
    "SNMP": ("SNMP Service", "medium", "Can expose system information"),
    "RemoteRegistry": ("Remote Registry", "high", "Allows remote registry editing"),
    "WinRM": ("WinRM", "medium", "Windows Remote Management — verify if needed"),
    "RasMan": ("Remote Access Service", "low", "Remote access connection manager"),
    "SharedAccess": ("Internet Connection Sharing", "medium", "ICS can expose network"),
    "W3SVC": ("World Wide Web Publishing", "medium", "IIS web server — verify if needed"),
    "SSDPSRV": ("SSDP Discovery", "low", "Universal Plug and Play discovery"),
    "upnphost": ("UPnP Device Host", "low", "UPnP can be exploited for network attacks"),
}

RISKY_SERVICES_LINUX = {
    "telnet": ("Telnet", "critical", "Unencrypted remote access — use SSH instead"),
    "vsftpd": ("FTP Server", "medium", "Consider SFTP instead"),
    "proftpd": ("ProFTPD", "medium", "FTP server — consider SFTP"),
    "pure-ftpd": ("Pure-FTPd", "medium", "FTP server — consider SFTP"),
    "rsh": ("Remote Shell", "critical", "No encryption — use SSH"),
    "rlogin": ("Remote Login", "critical", "No encryption — use SSH"),
    "finger": ("Finger", "medium", "Exposes user information"),
    "rpcbind": ("RPC Bind", "low", "Required by NFS but can be exploited"),
    "nfs-server": ("NFS Server", "medium", "Verify NFS exports are restricted"),
    "smbd": ("Samba", "medium", "Verify SMB shares are properly secured"),
    "snmpd": ("SNMP Daemon", "medium", "Can expose system information"),
    "avahi-daemon": ("Avahi/mDNS", "low", "mDNS can leak network information"),
    "cups": ("CUPS Print Server", "low", "Print server — disable if not needed"),
}

RISKY_SERVICES_MACOS = {
    "ftp": ("FTP Server", "medium", "Unencrypted file transfer"),
    "telnet": ("Telnet", "critical", "Unencrypted remote access"),
    "finger": ("Finger", "medium", "Exposes user information"),
}


def _run_cmd(args: list[str], timeout: int = 15) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


class ServiceAuditScanner(BaseScanner):
    """Audits running services for security risks."""

    @property
    def name(self) -> str:
        return "Service Audit Scanner"

    @property
    def description(self) -> str:
        return "Audit running services for unnecessary or risky services"

    def scan(self) -> list[Finding]:
        system = platform.system().lower()
        findings: list[Finding] = []

        try:
            os_module = load_os_module()
            services = os_module.get_running_services()
        except Exception:
            services = []

        if system == "windows":
            findings.extend(self._audit_windows_services(services))
        elif system == "darwin":
            findings.extend(self._audit_macos_services(services))
        elif system == "linux":
            findings.extend(self._audit_linux_services(services))

        # Service count summary
        findings.append(Finding(
            title=f"Running services inventory: {len(services)} services",
            description=f"Found {len(services)} running services on this system.",
            severity=Severity.INFO,
            category="Service Audit",
            scanner=self.name,
            evidence={"service_count": len(services)},
            remediation="Disable services that are not needed to reduce attack surface.",
        ))

        return findings

    def _audit_windows_services(self, services) -> list[Finding]:
        """Check for risky Windows services."""
        findings: list[Finding] = []

        service_names = {s.name.lower(): s for s in services}

        for risky_name, (display, severity, reason) in RISKY_SERVICES_WINDOWS.items():
            if risky_name.lower() in service_names:
                svc = service_names[risky_name.lower()]
                sev = Severity(severity)
                findings.append(Finding(
                    title=f"Risky service running: {display}",
                    description=f"Service '{display}' ({risky_name}) is running. {reason}",
                    severity=sev,
                    category="Service Audit",
                    scanner=self.name,
                    evidence={
                        "service_name": risky_name,
                        "display_name": display,
                        "status": getattr(svc, "status", "running"),
                    },
                    remediation=f"If {display} is not needed, disable it: "
                                f"Stop-Service {risky_name}; "
                                f"Set-Service {risky_name} -StartupType Disabled",
                ))

        # Check for services running as SYSTEM from non-standard paths
        findings.extend(self._check_service_paths_windows())

        return findings

    def _check_service_paths_windows(self) -> list[Finding]:
        """Check Windows service binary paths for suspicious locations."""
        findings: list[Finding] = []
        suspicious_services: list[dict] = []

        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' -and "
            "$_.PathName -ne $null } | Select-Object Name, PathName, StartName | "
            "ConvertTo-Json -Depth 1"
        ], timeout=30)

        if success and output:
            try:
                import json
                services = json.loads(output)
                if isinstance(services, dict):
                    services = [services]

                for svc in services:
                    path = svc.get("PathName", "").lower()
                    name = svc.get("Name", "")
                    # Check if running from temp or user directories
                    suspicious_paths = ["\\temp\\", "\\tmp\\", "\\users\\public\\",
                                       "\\appdata\\", "\\downloads\\"]
                    for sp in suspicious_paths:
                        if sp in path:
                            suspicious_services.append({
                                "name": name,
                                "path": svc.get("PathName", ""),
                                "user": svc.get("StartName", ""),
                            })
                            break
            except Exception:
                pass

        if suspicious_services:
            findings.append(Finding(
                title=f"Services running from suspicious paths: {len(suspicious_services)}",
                description="Found services running executables from user or temporary directories. "
                            "This is unusual and could indicate malware persistence.",
                severity=Severity.HIGH,
                category="Service Audit",
                scanner=self.name,
                evidence={"services": suspicious_services[:10]},
                remediation="Investigate each service. Verify the binaries are legitimate. "
                            "Remove any unauthorized services.",
            ))

        return findings

    def _audit_linux_services(self, services) -> list[Finding]:
        """Check for risky Linux services."""
        findings: list[Finding] = []

        service_names = {s.name.lower().replace(".service", ""): s for s in services}

        for risky_name, (display, severity, reason) in RISKY_SERVICES_LINUX.items():
            if risky_name.lower() in service_names:
                sev = Severity(severity)
                findings.append(Finding(
                    title=f"Risky service running: {display}",
                    description=f"Service '{display}' ({risky_name}) is active. {reason}",
                    severity=sev,
                    category="Service Audit",
                    scanner=self.name,
                    evidence={
                        "service_name": risky_name,
                        "display_name": display,
                    },
                    remediation=f"If {display} is not needed, disable it: "
                                f"systemctl stop {risky_name} && "
                                f"systemctl disable {risky_name}",
                ))

        return findings

    def _audit_macos_services(self, services) -> list[Finding]:
        """Check for risky macOS services."""
        findings: list[Finding] = []

        service_names = {s.name.lower(): s for s in services}

        for risky_name, (display, severity, reason) in RISKY_SERVICES_MACOS.items():
            if risky_name.lower() in service_names:
                sev = Severity(severity)
                findings.append(Finding(
                    title=f"Risky service running: {display}",
                    description=f"Service '{display}' is active. {reason}",
                    severity=sev,
                    category="Service Audit",
                    scanner=self.name,
                    evidence={"service_name": risky_name},
                    remediation=f"Disable {display} if not needed.",
                ))

        return findings

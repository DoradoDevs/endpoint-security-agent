"""
Sentinel Agent — Network Scanner

Audits local network security posture:
- Open/listening ports inventory
- Connections to known suspicious ports
- Firewall status verification
- Exposed service detection

LOCAL ANALYSIS ONLY — no external probing or port scanning of remote hosts.
"""

from __future__ import annotations

import platform

import psutil

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from os_modules.loader import load_os_module
from scanners.base import BaseScanner

# Ports commonly associated with suspicious activity when unexpectedly open
HIGH_RISK_PORTS = {
    4444: "Metasploit default",
    5555: "Android Debug Bridge (remote)",
    6666: "IRC backdoor common",
    6667: "IRC (often used by botnets)",
    8888: "Alternative HTTP (sometimes malware C2)",
    9001: "Tor default",
    9050: "Tor SOCKS proxy",
    9090: "Alternative web admin",
    31337: "Back Orifice / 'elite' backdoor",
    12345: "NetBus trojan",
    65535: "Common backdoor port",
}

# Known service ports — not inherently suspicious but worth inventorying
KNOWN_SERVICE_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    27017: "MongoDB",
}

# Ports that should NOT be exposed on a server without good reason
RISKY_SERVICE_PORTS = {
    23: ("Telnet", "Unencrypted remote access — use SSH instead"),
    135: ("RPC", "Windows RPC endpoint — often targeted by worms"),
    139: ("NetBIOS", "Legacy Windows networking — should be disabled if not needed"),
    445: ("SMB", "File sharing — high-value target for attacks like EternalBlue"),
    3389: ("RDP", "Remote Desktop — should be tunneled through VPN if needed"),
    5900: ("VNC", "Remote access — often unencrypted, should be tunneled"),
    6379: ("Redis", "Database — should not be exposed to network"),
    27017: ("MongoDB", "Database — should not be exposed to network"),
}


class NetworkScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "Network Scanner"

    @property
    def description(self) -> str:
        return "Audit local network posture, open ports, and firewall status"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Firewall check
        findings.extend(self._check_firewall())

        # 2. Listening ports inventory
        findings.extend(self._check_listening_ports())

        # 3. Suspicious outbound connections
        findings.extend(self._check_connections())

        return findings

    def _check_firewall(self) -> list[Finding]:
        findings: list[Finding] = []
        os_module = load_os_module()
        fw = os_module.get_firewall_status()

        if not fw.enabled:
            findings.append(Finding(
                title="Firewall is disabled",
                description=f"The system firewall is not active. Details: {fw.details}",
                severity=Severity.CRITICAL,
                category="Network Security",
                scanner=self.name,
                evidence={"details": fw.details},
                remediation="Enable the system firewall immediately.",
            ))
        else:
            findings.append(Finding(
                title="Firewall is active",
                description=f"System firewall is enabled. {fw.details}",
                severity=Severity.INFO,
                category="Network Security",
                scanner=self.name,
                evidence={"details": fw.details},
            ))

        return findings

    def _check_listening_ports(self) -> list[Finding]:
        findings: list[Finding] = []
        listening: list[dict] = []

        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                port = conn.laddr.port
                addr = conn.laddr.ip
                pid = conn.pid

                proc_name = ""
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "unknown"

                listening.append({
                    "port": port,
                    "address": addr,
                    "pid": pid,
                    "process": proc_name,
                })

                # Check for high-risk ports
                if port in HIGH_RISK_PORTS:
                    findings.append(Finding(
                        title=f"High-risk port open: {port} ({HIGH_RISK_PORTS[port]})",
                        description=(
                            f"Port {port} is listening ({HIGH_RISK_PORTS[port]}). "
                            f"Process: {proc_name} (PID {pid}). Address: {addr}"
                        ),
                        severity=Severity.HIGH,
                        category="Network Security",
                        scanner=self.name,
                        evidence={"port": port, "process": proc_name, "pid": pid, "address": addr},
                        remediation=f"Investigate why port {port} is open. Close it if not needed.",
                    ))

                # Check for risky service ports exposed on all interfaces
                if port in RISKY_SERVICE_PORTS and addr in ("0.0.0.0", "::", ""):
                    svc_name, reason = RISKY_SERVICE_PORTS[port]
                    findings.append(Finding(
                        title=f"Risky service exposed: {svc_name} (port {port})",
                        description=(
                            f"{svc_name} on port {port} is listening on all interfaces. "
                            f"{reason}. Process: {proc_name}"
                        ),
                        severity=Severity.MEDIUM,
                        category="Network Security",
                        scanner=self.name,
                        evidence={"port": port, "service": svc_name, "process": proc_name},
                        remediation=f"Restrict {svc_name} to localhost or use a VPN/tunnel.",
                    ))

        # Summary finding
        findings.append(Finding(
            title=f"Open port inventory: {len(listening)} listening ports",
            description=f"Found {len(listening)} listening ports on this system.",
            severity=Severity.INFO,
            category="Network Security",
            scanner=self.name,
            evidence={"ports": listening[:50]},  # Cap evidence size
        ))

        return findings

    def _check_connections(self) -> list[Finding]:
        """Check established connections for suspicious patterns."""
        findings: list[Finding] = []
        suspicious_remote_ports = {4444, 5555, 6666, 6667, 8888, 9001, 31337, 12345}

        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                remote_port = conn.raddr.port
                if remote_port in suspicious_remote_ports:
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "unknown"

                    findings.append(Finding(
                        title=f"Connection to suspicious port: {conn.raddr.ip}:{remote_port}",
                        description=(
                            f"Established connection to {conn.raddr.ip}:{remote_port}. "
                            f"Process: {proc_name} (PID {conn.pid}). "
                            "This port is commonly associated with malicious tools."
                        ),
                        severity=Severity.HIGH,
                        category="Network Security",
                        scanner=self.name,
                        evidence={
                            "remote_ip": conn.raddr.ip,
                            "remote_port": remote_port,
                            "process": proc_name,
                            "pid": conn.pid,
                        },
                        remediation="Investigate this connection immediately.",
                    ))

        return findings

"""
Sentinel Agent — Network Vulnerability Scanner

TCP port scanning, service banner grabbing, SSL/TLS certificate analysis,
and DNS security checks for target hosts.
"""

from __future__ import annotations

import socket
import subprocess
from typing import Any

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner
from scanners.ssl_analyzer import SSLAnalyzer, SSLResult


# Well-known service ports and expected services
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 9200, 27017,
]

# Ports that should generally not be exposed to the network
HIGH_RISK_PORTS = {
    23: "Telnet (unencrypted remote access)",
    135: "MSRPC (Windows RPC)",
    139: "NetBIOS (SMB legacy)",
    445: "SMB (file sharing — often targeted)",
    1433: "MSSQL (database)",
    1521: "Oracle DB",
    3306: "MySQL (database)",
    3389: "RDP (remote desktop)",
    5432: "PostgreSQL (database)",
    5900: "VNC (remote desktop — often unencrypted)",
    6379: "Redis (in-memory database — often no auth)",
    9200: "Elasticsearch (REST API)",
    27017: "MongoDB (database — often no auth)",
}

# Known vulnerable service versions (simplified patterns)
VULNERABLE_BANNERS = [
    ("OpenSSH_7.", "OpenSSH 7.x may be vulnerable to CVE-2023-38408"),
    ("Apache/2.4.49", "Apache 2.4.49 vulnerable to path traversal (CVE-2021-41773)"),
    ("Apache/2.4.50", "Apache 2.4.50 incomplete fix for CVE-2021-41773"),
    ("nginx/1.1", "nginx 1.1.x is end-of-life"),
    ("ProFTPD 1.3.5", "ProFTPD 1.3.5 has known vulnerabilities"),
    ("Microsoft-IIS/7", "IIS 7.x is end-of-life"),
    ("vsftpd 2.3.4", "vsftpd 2.3.4 contains known backdoor"),
]


class NetworkVulnScanner(BaseScanner):
    """Scans network targets for open ports, vulnerable services, and SSL issues."""

    @property
    def name(self) -> str:
        return "NetworkVulnScanner"

    @property
    def description(self) -> str:
        return "TCP port scan, service detection, SSL/TLS analysis, DNS checks"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        targets = self._get_targets()

        if not targets:
            findings.append(Finding(
                title="No network scan targets configured",
                description="Configure network_scan_targets in config to enable vulnerability scanning.",
                severity=Severity.INFO,
                category="Network Vulnerability",
                scanner=self.name,
                evidence={},
            ))
            return findings

        for target in targets:
            findings.extend(self._scan_target(target))

        return findings

    def _get_targets(self) -> list[str]:
        """Get configured scan targets."""
        targets = getattr(self.config.scan, "network_scan_targets", [])
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split(",") if t.strip()]
        return targets

    def _scan_target(self, target: str) -> list[Finding]:
        """Scan a single target host."""
        findings: list[Finding] = []
        host = target.strip()

        # Resolve hostname
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            findings.append(Finding(
                title=f"DNS resolution failed: {host}",
                description=f"Could not resolve hostname '{host}'.",
                severity=Severity.MEDIUM,
                category="Network Vulnerability",
                scanner=self.name,
                evidence={"host": host},
            ))
            return findings

        # Port scan
        open_ports = self._tcp_scan(host, ip)

        if not open_ports:
            findings.append(Finding(
                title=f"No open ports found on {host}",
                description=f"No common ports are open on {host} ({ip}).",
                severity=Severity.INFO,
                category="Network Vulnerability",
                scanner=self.name,
                evidence={"host": host, "ip": ip},
            ))
            return findings

        # Inventory finding
        findings.append(Finding(
            title=f"Open ports on {host}: {len(open_ports)}",
            description=f"Found {len(open_ports)} open ports: {', '.join(str(p) for p in open_ports)}",
            severity=Severity.INFO,
            category="Network Vulnerability",
            scanner=self.name,
            evidence={"host": host, "ip": ip, "open_ports": open_ports},
        ))

        # Check high-risk ports
        for port in open_ports:
            if port in HIGH_RISK_PORTS:
                findings.append(Finding(
                    title=f"High-risk port open: {port} ({HIGH_RISK_PORTS[port]})",
                    description=f"{host}:{port} — {HIGH_RISK_PORTS[port]}. "
                                "This service is frequently targeted by attackers.",
                    severity=Severity.HIGH if port in (23, 445, 3389, 6379, 27017) else Severity.MEDIUM,
                    category="Network Vulnerability",
                    scanner=self.name,
                    evidence={"host": host, "ip": ip, "port": port, "service": HIGH_RISK_PORTS[port]},
                    remediation=f"Restrict access to port {port} via firewall rules, "
                                "or disable the service if not needed.",
                ))

        # Banner grabbing and version detection
        for port in open_ports:
            banner = self._grab_banner(host, port)
            if banner:
                findings.extend(self._check_banner(host, ip, port, banner))

        # SSL/TLS analysis on HTTPS ports
        ssl_ports = [p for p in open_ports if p in (443, 8443, 993, 995)]
        if not ssl_ports and 443 in open_ports:
            ssl_ports = [443]

        for port in ssl_ports:
            findings.extend(self._analyze_ssl(host, port))

        # DNS checks
        findings.extend(self._check_dns(host))

        return findings

    def _tcp_scan(self, host: str, ip: str) -> list[int]:
        """Perform TCP connect scan on common ports."""
        open_ports: list[int] = []

        for port in COMMON_PORTS:
            try:
                with socket.create_connection((ip, port), timeout=2.0):
                    open_ports.append(port)
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue

        return open_ports

    def _grab_banner(self, host: str, port: int, timeout: float = 3.0) -> str:
        """Attempt to grab a service banner."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                # For HTTP ports, send a HEAD request
                if port in (80, 8080, 443, 8443):
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                else:
                    # Many services send a banner on connect
                    pass

                sock.settimeout(timeout)
                data = sock.recv(1024)
                return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    def _check_banner(self, host: str, ip: str, port: int, banner: str) -> list[Finding]:
        """Check banner for known vulnerable versions."""
        findings: list[Finding] = []

        for pattern, description in VULNERABLE_BANNERS:
            if pattern in banner:
                findings.append(Finding(
                    title=f"Potentially vulnerable service on {host}:{port}",
                    description=description,
                    severity=Severity.HIGH,
                    category="Network Vulnerability",
                    scanner=self.name,
                    evidence={
                        "host": host, "ip": ip, "port": port,
                        "banner": banner[:200], "vulnerability": description,
                    },
                    remediation="Update the service to the latest version.",
                ))

        # Extract Server header from HTTP responses
        if "Server:" in banner:
            for line in banner.split("\r\n"):
                if line.lower().startswith("server:"):
                    server_info = line.split(":", 1)[1].strip()
                    findings.append(Finding(
                        title=f"Server version exposed on {host}:{port}",
                        description=f"Server header reveals: {server_info}",
                        severity=Severity.LOW,
                        category="Network Vulnerability",
                        scanner=self.name,
                        evidence={"host": host, "port": port, "server": server_info},
                        remediation="Consider hiding server version headers.",
                    ))
                    break

        return findings

    def _analyze_ssl(self, host: str, port: int) -> list[Finding]:
        """Run SSL/TLS analysis on a host:port."""
        findings: list[Finding] = []
        analyzer = SSLAnalyzer()
        result = analyzer.analyze(host, port)

        if result.is_expired:
            findings.append(Finding(
                title=f"Expired SSL certificate on {host}:{port}",
                description=f"Certificate expired {abs(result.days_until_expiry)} days ago.",
                severity=Severity.CRITICAL,
                category="Network Vulnerability",
                scanner=self.name,
                evidence=result.to_dict(),
                remediation="Renew the SSL certificate immediately.",
            ))
        elif result.days_until_expiry > 0 and result.days_until_expiry < 30:
            findings.append(Finding(
                title=f"SSL certificate expiring soon on {host}:{port}",
                description=f"Certificate expires in {result.days_until_expiry} days.",
                severity=Severity.MEDIUM,
                category="Network Vulnerability",
                scanner=self.name,
                evidence=result.to_dict(),
                remediation="Renew the SSL certificate before it expires.",
            ))

        if result.is_self_signed:
            findings.append(Finding(
                title=f"Self-signed SSL certificate on {host}:{port}",
                description="Self-signed certificates are not trusted by clients.",
                severity=Severity.MEDIUM,
                category="Network Vulnerability",
                scanner=self.name,
                evidence=result.to_dict(),
                remediation="Use a certificate from a trusted CA.",
            ))

        if result.weak_cipher:
            findings.append(Finding(
                title=f"Weak SSL cipher on {host}:{port}",
                description=f"Cipher: {result.cipher_name} ({result.cipher_bits} bits)",
                severity=Severity.HIGH,
                category="Network Vulnerability",
                scanner=self.name,
                evidence=result.to_dict(),
                remediation="Configure the server to use strong cipher suites.",
            ))

        for issue in result.issues:
            if "Deprecated protocol" in issue:
                findings.append(Finding(
                    title=f"Deprecated TLS protocol on {host}:{port}",
                    description=issue,
                    severity=Severity.HIGH,
                    category="Network Vulnerability",
                    scanner=self.name,
                    evidence=result.to_dict(),
                    remediation="Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ only.",
                ))

        return findings

    def _check_dns(self, host: str) -> list[Finding]:
        """Perform basic DNS security checks."""
        findings: list[Finding] = []

        # Check for DNS zone transfer vulnerability
        try:
            result = subprocess.run(
                ["nslookup", "-type=AXFR", host],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout + result.stderr
            if "Transfer failed" not in output and "refused" not in output.lower():
                if "Name:" in output and output.count("Name:") > 2:
                    findings.append(Finding(
                        title=f"DNS zone transfer may be allowed for {host}",
                        description="Zone transfers can leak internal DNS records to attackers.",
                        severity=Severity.HIGH,
                        category="Network Vulnerability",
                        scanner=self.name,
                        evidence={"host": host, "check": "AXFR"},
                        remediation="Restrict DNS zone transfers to authorized servers only.",
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings

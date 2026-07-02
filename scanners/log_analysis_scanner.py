"""
Sentinel Agent — Log Analysis Scanner

Parses system security logs for indicators of attack or compromise:
- Failed login attempts (brute force detection)
- Privilege escalation events
- Account creation/modification
- Suspicious authentication patterns

Windows: Windows Security Event Log
Linux: /var/log/auth.log or journalctl
"""

from __future__ import annotations

import platform
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner


def _run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


class LogAnalysisScanner(BaseScanner):
    """Parses security logs for indicators of attack or compromise."""

    @property
    def name(self) -> str:
        return "Log Analysis Scanner"

    @property
    def description(self) -> str:
        return "Analyze security logs for failed logins, privilege escalation, and suspicious events"

    @property
    def supported_platforms(self) -> list[str]:
        return ["windows", "linux"]

    def scan(self) -> list[Finding]:
        system = platform.system().lower()
        if system == "windows":
            return self._scan_windows_events()
        elif system == "linux":
            return self._scan_linux_logs()
        return []

    def _scan_windows_events(self) -> list[Finding]:
        """Parse Windows Security Event Log for suspicious events."""
        findings: list[Finding] = []

        # Event IDs of interest:
        # 4625 = Failed logon
        # 4648 = Logon using explicit credentials
        # 4672 = Special privileges assigned to new logon
        # 4720 = User account created
        # 4724 = Password reset attempt
        # 4732 = Member added to security-enabled local group

        # Check failed logins (last 24 hours)
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "try { "
            "$cutoff = (Get-Date).AddHours(-24); "
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$cutoff} "
            "-ErrorAction SilentlyContinue; "
            "if ($events) { $events.Count } else { '0' } "
            "} catch { '0' }"
        ], timeout=30)

        failed_count = 0
        if success:
            try:
                failed_count = int(output.strip())
            except ValueError:
                pass

        if failed_count > 50:
            findings.append(Finding(
                title=f"Brute force indicator: {failed_count} failed logins in 24h",
                description=f"Detected {failed_count} failed login attempts in the last 24 hours. "
                            "This is a strong indicator of a brute force attack.",
                severity=Severity.CRITICAL,
                category="Log Analysis",
                scanner=self.name,
                evidence={"event_id": 4625, "count_24h": failed_count},
                remediation="Investigate the source of failed logins. Enable account lockout "
                            "policy. Consider enabling MFA.",
            ))
        elif failed_count > 10:
            findings.append(Finding(
                title=f"Elevated failed logins: {failed_count} in 24h",
                description=f"Detected {failed_count} failed login attempts in the last 24 hours. "
                            "Monitor for brute force patterns.",
                severity=Severity.HIGH,
                category="Log Analysis",
                scanner=self.name,
                evidence={"event_id": 4625, "count_24h": failed_count},
                remediation="Review failed login sources. Enable account lockout policy if not set.",
            ))
        elif failed_count > 0:
            findings.append(Finding(
                title=f"Failed login attempts: {failed_count} in 24h",
                description=f"Detected {failed_count} failed login attempt(s) in the last 24 hours.",
                severity=Severity.LOW,
                category="Log Analysis",
                scanner=self.name,
                evidence={"event_id": 4625, "count_24h": failed_count},
                remediation="Monitor for recurring patterns.",
            ))

        # Check for new user accounts created (last 7 days)
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "try { "
            "$cutoff = (Get-Date).AddDays(-7); "
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720;StartTime=$cutoff} "
            "-ErrorAction SilentlyContinue; "
            "if ($events) { $events.Count } else { '0' } "
            "} catch { '0' }"
        ], timeout=30)

        if success:
            try:
                new_accounts = int(output.strip())
                if new_accounts > 0:
                    findings.append(Finding(
                        title=f"New user accounts created: {new_accounts} in last 7 days",
                        description=f"Detected {new_accounts} new user account(s) created recently. "
                                    "Verify these are legitimate.",
                        severity=Severity.MEDIUM,
                        category="Log Analysis",
                        scanner=self.name,
                        evidence={"event_id": 4720, "count_7d": new_accounts},
                        remediation="Verify all new accounts are authorized. "
                                    "Remove any unauthorized accounts.",
                    ))
            except ValueError:
                pass

        # Check for privilege escalation events (last 24h)
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "try { "
            "$cutoff = (Get-Date).AddHours(-24); "
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672;StartTime=$cutoff} "
            "-ErrorAction SilentlyContinue; "
            "if ($events) { $events.Count } else { '0' } "
            "} catch { '0' }"
        ], timeout=30)

        if success:
            try:
                priv_events = int(output.strip())
                if priv_events > 100:
                    findings.append(Finding(
                        title=f"High privilege assignment activity: {priv_events} events",
                        description=f"Detected {priv_events} special privilege assignment events "
                                    "in the last 24 hours. Unusually high volume may indicate compromise.",
                        severity=Severity.MEDIUM,
                        category="Log Analysis",
                        scanner=self.name,
                        evidence={"event_id": 4672, "count_24h": priv_events},
                        remediation="Review which accounts are receiving elevated privileges.",
                    ))
            except ValueError:
                pass

        if not findings:
            findings.append(Finding(
                title="Security event log analysis clean",
                description="No suspicious patterns detected in Windows Security Event Log.",
                severity=Severity.INFO,
                category="Log Analysis",
                scanner=self.name,
                evidence={"status": "clean"},
                remediation="",
            ))

        return findings

    def _scan_linux_logs(self) -> list[Finding]:
        """Parse Linux auth logs for suspicious events."""
        findings: list[Finding] = []

        # Try journalctl first, then fall back to auth.log
        log_content = ""
        success, output = _run_cmd([
            "journalctl", "-u", "ssh", "-u", "sshd", "--since", "24 hours ago",
            "--no-pager", "-q"
        ], timeout=15)

        if success and output:
            log_content = output
        else:
            # Fall back to auth.log
            try:
                from pathlib import Path
                auth_log = Path("/var/log/auth.log")
                if auth_log.exists():
                    log_content = auth_log.read_text(errors="replace")
                    # Only keep last 24h worth (approximate: last 5000 lines)
                    lines = log_content.splitlines()
                    log_content = "\n".join(lines[-5000:])
            except (OSError, PermissionError):
                pass

        if not log_content:
            findings.append(Finding(
                title="Unable to read authentication logs",
                description="Could not access journalctl or /var/log/auth.log. "
                            "Log analysis requires appropriate permissions.",
                severity=Severity.LOW,
                category="Log Analysis",
                scanner=self.name,
                evidence={"status": "no_access"},
                remediation="Run sentinel with sudo for full log analysis.",
            ))
            return findings

        # Analyze failed SSH logins
        failed_pattern = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')
        failed_matches = failed_pattern.findall(log_content)
        failed_count = len(failed_matches)

        # Count by source IP
        source_ips: Counter = Counter()
        for user, ip in failed_matches:
            source_ips[ip] += 1

        if failed_count > 50:
            top_sources = source_ips.most_common(5)
            findings.append(Finding(
                title=f"SSH brute force indicator: {failed_count} failed logins",
                description=f"Detected {failed_count} failed SSH login attempts. "
                            f"Top sources: {', '.join(f'{ip} ({c}x)' for ip, c in top_sources)}",
                severity=Severity.CRITICAL,
                category="Log Analysis",
                scanner=self.name,
                evidence={
                    "failed_count": failed_count,
                    "top_sources": dict(top_sources),
                    "unique_ips": len(source_ips),
                },
                remediation="Install fail2ban to auto-block attackers. "
                            "Consider changing SSH port or using key-only authentication.",
            ))
        elif failed_count > 10:
            findings.append(Finding(
                title=f"Elevated failed SSH logins: {failed_count}",
                description=f"Detected {failed_count} failed SSH login attempts from "
                            f"{len(source_ips)} unique IP(s).",
                severity=Severity.HIGH,
                category="Log Analysis",
                scanner=self.name,
                evidence={
                    "failed_count": failed_count,
                    "unique_ips": len(source_ips),
                },
                remediation="Monitor login attempts. Consider installing fail2ban.",
            ))
        elif failed_count > 0:
            findings.append(Finding(
                title=f"Failed SSH login attempts: {failed_count}",
                description=f"Detected {failed_count} failed SSH login attempt(s).",
                severity=Severity.LOW,
                category="Log Analysis",
                scanner=self.name,
                evidence={"failed_count": failed_count},
                remediation="Monitor for recurring patterns.",
            ))

        # Check for invalid user attempts (username enumeration)
        invalid_user_pattern = re.compile(r'Invalid user (\S+) from (\S+)')
        invalid_users = invalid_user_pattern.findall(log_content)
        if len(invalid_users) > 10:
            unique_users = set(u for u, _ in invalid_users)
            findings.append(Finding(
                title=f"Username enumeration detected: {len(invalid_users)} attempts",
                description=f"Detected {len(invalid_users)} login attempts with invalid usernames "
                            f"({len(unique_users)} unique). This suggests automated scanning.",
                severity=Severity.MEDIUM,
                category="Log Analysis",
                scanner=self.name,
                evidence={
                    "attempts": len(invalid_users),
                    "unique_usernames": len(unique_users),
                },
                remediation="Enable fail2ban. Ensure SSH does not expose valid usernames.",
            ))

        # Check for successful root logins
        root_login_pattern = re.compile(r'Accepted (?:password|publickey) for root from (\S+)')
        root_logins = root_login_pattern.findall(log_content)
        if root_logins:
            findings.append(Finding(
                title=f"Direct root SSH login detected: {len(root_logins)} occurrence(s)",
                description=f"Root logged in directly via SSH from: "
                            f"{', '.join(set(root_logins[:5]))}",
                severity=Severity.HIGH,
                category="Log Analysis",
                scanner=self.name,
                evidence={
                    "root_login_count": len(root_logins),
                    "source_ips": list(set(root_logins[:10])),
                },
                remediation="Disable root SSH login in /etc/ssh/sshd_config. "
                            "Use a regular user and sudo instead.",
            ))

        if not findings:
            findings.append(Finding(
                title="Authentication log analysis clean",
                description="No suspicious patterns detected in authentication logs.",
                severity=Severity.INFO,
                category="Log Analysis",
                scanner=self.name,
                evidence={"status": "clean"},
                remediation="",
            ))

        return findings

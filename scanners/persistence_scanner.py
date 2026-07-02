"""
Sentinel Agent — Deep Persistence Hunter

Comprehensive detection of 30+ persistence mechanisms across Windows, Linux,
and macOS. Scans registry keys, scheduled tasks, WMI subscriptions, IFEO,
AppInit DLLs, Winlogon hijacks, boot execute, LSA packages, crontabs,
systemd services, shell RC injection, LD_PRELOAD, kernel modules, SSH keys,
PAM modules, XDG autostart, LaunchAgents/Daemons, login items, and kexts.

All checks are read-only and non-destructive.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Suspicious path indicators (case-insensitive matching)
# ---------------------------------------------------------------------------
SUSPICIOUS_PATHS_WINDOWS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\programdata\\",
    "$recycle.bin",
]

SUSPICIOUS_PATHS_UNIX = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/dev/mqueue/",
    "/run/user/",
]

# ---------------------------------------------------------------------------
# Suspicious command patterns (regex, for any platform)
# ---------------------------------------------------------------------------
SUSPICIOUS_COMMAND_PATTERNS = [
    r"-[Ee]nc(?:oded)?[Cc]?(?:ommand)?",       # PowerShell encoded
    r"base64\s+--?d",                            # base64 decode
    r"curl.*\|\s*(?:bash|sh)",                   # curl pipe to shell
    r"wget.*\|\s*(?:bash|sh)",                   # wget pipe to shell
    r"python\s+-c\s+['\"]import",                # python one-liner
    r"\\x[0-9a-fA-F]{2}",                       # hex escape sequences
    r"eval\s*\(",                                # eval() calls
    r"IEX\s*\(",                                 # PowerShell Invoke-Expression
    r"Invoke-Expression",
    r"iex\s*\(",
]

# Known-good LSA security packages
KNOWN_LSA_PACKAGES = [
    "kerberos",
    "msv1_0",
    "schannel",
    "wdigest",
    "tspkg",
    "pku2u",
    "cloudap",
    "",
]


# ===================================================================
# Scanner
# ===================================================================
class PersistenceScanner(BaseScanner):
    """Comprehensive persistence mechanism detection across all platforms."""

    @property
    def name(self) -> str:
        return "PersistenceScanner"

    @property
    def description(self) -> str:
        return "Deep scan of 30+ persistence mechanisms for hidden threats"

    @property
    def supported_platforms(self) -> list[str]:
        return ["all"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        system = platform.system().lower()
        if system == "windows":
            findings.extend(self._scan_windows())
        elif system == "linux":
            findings.extend(self._scan_linux())
        elif system == "darwin":
            findings.extend(self._scan_macos())
        return findings

    # ==================================================================
    #  Helpers
    # ==================================================================
    def _run_command(self, cmd: list[str], timeout: int = 30) -> str | None:
        """Run a subprocess and return stdout, or *None* on any failure."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return result.stdout.strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _is_suspicious_path(self, path_str: str) -> bool:
        """Return True if *path_str* contains a suspicious path marker."""
        low = path_str.lower()
        system = platform.system().lower()
        markers = SUSPICIOUS_PATHS_WINDOWS if system == "windows" else SUSPICIOUS_PATHS_UNIX
        return any(m.lower() in low for m in markers)

    def _has_suspicious_command(self, command: str) -> list[str]:
        """Return list of suspicious-command pattern names matched."""
        matched: list[str] = []
        for pat in SUSPICIOUS_COMMAND_PATTERNS:
            if re.search(pat, command, re.IGNORECASE):
                matched.append(pat)
        return matched

    # Helper: build a Finding consistently
    def _finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        evidence: dict[str, Any],
        remediation: str = "",
    ) -> Finding:
        return Finding(
            title=title,
            description=description,
            severity=severity,
            category="Persistence",
            scanner="PersistenceScanner",
            evidence=evidence,
            remediation=remediation,
        )

    # ==================================================================
    #  WINDOWS
    # ==================================================================
    def _scan_windows(self) -> list[Finding]:
        findings: list[Finding] = []
        checks = [
            self._check_registry_run,
            self._check_scheduled_tasks,
            self._check_wmi_subscriptions,
            self._check_ifeo,
            self._check_appinit_dlls,
            self._check_winlogon,
            self._check_services_suspicious_paths,
            self._check_startup_folder,
            self._check_boot_execute,
            self._check_lsa_security_packages,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as exc:
                self.log.debug(f"  [PersistenceScanner] {check.__name__} error: {exc}")
        return findings

    # -- Registry Run keys --
    def _check_registry_run(self) -> list[Finding]:
        findings: list[Finding] = []
        keys = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        for key in keys:
            output = self._run_command(["reg", "query", key])
            if output is None:
                continue
            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith("HK") or line.startswith("End"):
                    continue
                parts = line.split(None, 2)
                if len(parts) < 3:
                    continue
                entry_name = parts[0]
                entry_value = parts[2]

                suspicious_cmds = self._has_suspicious_command(entry_value)
                if self._is_suspicious_path(entry_value):
                    findings.append(self._finding(
                        title=f"Registry Run entry in suspicious path: {entry_name}",
                        description=(
                            f"Registry Run entry '{entry_name}' points to a suspicious "
                            f"location: {entry_value}"
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "path": entry_value,
                            "command": entry_value,
                            "registry_key": key,
                            "mechanism": "Registry Run",
                        },
                        remediation="Investigate and remove if not recognized.",
                    ))
                elif suspicious_cmds:
                    findings.append(self._finding(
                        title=f"Registry Run entry with suspicious command: {entry_name}",
                        description=(
                            f"Registry Run entry '{entry_name}' contains suspicious "
                            f"command patterns: {', '.join(suspicious_cmds)}"
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "path": entry_value,
                            "command": entry_value,
                            "registry_key": key,
                            "mechanism": "Registry Run",
                            "patterns_matched": suspicious_cmds,
                        },
                        remediation="Decode / investigate the command. Remove if malicious.",
                    ))
                else:
                    findings.append(self._finding(
                        title=f"Registry Run entry: {entry_name}",
                        description=f"Startup entry '{entry_name}' registered via {key}.",
                        severity=Severity.INFO,
                        evidence={
                            "path": entry_value,
                            "command": entry_value,
                            "registry_key": key,
                            "mechanism": "Registry Run",
                        },
                    ))
        return findings

    # -- Scheduled Tasks --
    def _check_scheduled_tasks(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command(["schtasks", "/query", "/fo", "CSV", "/v"])
        if output is None:
            return findings

        lines = output.splitlines()
        if len(lines) < 2:
            return findings

        headers = [h.strip('"') for h in lines[0].split(",")]
        col = {h: i for i, h in enumerate(headers)}

        for row_line in lines[1:]:
            # Crude CSV parse (Windows schtasks output)
            cols = [c.strip('"') for c in row_line.split('","')]
            if len(cols) < len(headers):
                continue
            task_name = cols[col.get("TaskName", 0)] if "TaskName" in col else ""
            action = cols[col.get("Task To Run", 0)] if "Task To Run" in col else ""
            next_run = cols[col.get("Next Run Time", 0)] if "Next Run Time" in col else ""

            if not task_name or task_name.lower() == "taskname":
                continue

            suspicious_cmds = self._has_suspicious_command(action)
            if self._is_suspicious_path(action):
                findings.append(self._finding(
                    title=f"Scheduled task in suspicious path: {task_name}",
                    description=f"Scheduled task '{task_name}' runs from a suspicious path.",
                    severity=Severity.HIGH,
                    evidence={
                        "task_name": task_name,
                        "command": action,
                        "path": action,
                        "next_run": next_run,
                        "mechanism": "Scheduled Task",
                    },
                    remediation="Investigate this scheduled task and remove if unauthorized.",
                ))
            elif suspicious_cmds:
                findings.append(self._finding(
                    title=f"Scheduled task with suspicious command: {task_name}",
                    description=(
                        f"Scheduled task '{task_name}' uses suspicious patterns: "
                        f"{', '.join(suspicious_cmds)}"
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "task_name": task_name,
                        "command": action,
                        "path": action,
                        "next_run": next_run,
                        "mechanism": "Scheduled Task",
                    },
                    remediation="Decode and investigate the scheduled task command.",
                ))
        return findings

    # -- WMI Event Subscriptions --
    def _check_wmi_subscriptions(self) -> list[Finding]:
        findings: list[Finding] = []
        # Event filters
        filter_out = self._run_command([
            "powershell", "-NoProfile", "-Command",
            "Get-WmiObject -Namespace root\\subscription "
            "-Class __EventFilter 2>$null | "
            "Select Name,Query | ConvertTo-Json",
        ])
        # Command-line consumers
        consumer_out = self._run_command([
            "powershell", "-NoProfile", "-Command",
            "Get-WmiObject -Namespace root\\subscription "
            "-Class CommandLineEventConsumer 2>$null | "
            "Select Name,CommandLineTemplate | ConvertTo-Json",
        ])

        for label, raw in [("EventFilter", filter_out), ("Consumer", consumer_out)]:
            if not raw:
                continue
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("Name", "unknown")
                    query = item.get("Query", item.get("CommandLineTemplate", ""))
                    findings.append(self._finding(
                        title=f"WMI {label} detected: {name}",
                        description=(
                            f"WMI event subscription '{name}' found. WMI persistence is "
                            f"rarely legitimate and commonly used by advanced malware."
                        ),
                        severity=Severity.CRITICAL,
                        evidence={
                            "subscription_name": name,
                            "query": query,
                            "command": query,
                            "mechanism": "WMI Subscription",
                        },
                        remediation=(
                            "Remove with: Get-WmiObject -Namespace root\\subscription "
                            f"-Class {label} | Where-Object {{$_.Name -eq '{name}'}} | "
                            "Remove-WmiObject"
                        ),
                    ))
            except (json.JSONDecodeError, TypeError):
                continue
        return findings

    # -- Image File Execution Options --
    def _check_ifeo(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command([
            "reg", "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "/s", "/v", "Debugger",
        ])
        if output is None:
            return findings
        current_key = ""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("HKLM"):
                current_key = line
            elif "Debugger" in line:
                parts = line.split(None, 2)
                debugger_path = parts[2] if len(parts) >= 3 else line
                target = current_key.rsplit("\\", 1)[-1] if current_key else "unknown"
                findings.append(self._finding(
                    title=f"IFEO debugger hijack: {target}",
                    description=(
                        f"Image File Execution Options debugger set for '{target}'. "
                        f"This is a known persistence / evasion technique."
                    ),
                    severity=Severity.CRITICAL,
                    evidence={
                        "target_executable": target,
                        "debugger_path": debugger_path,
                        "mechanism": "IFEO",
                    },
                    remediation=(
                        f"Remove the Debugger value: reg delete \"{current_key}\" "
                        "/v Debugger /f"
                    ),
                ))
        return findings

    # -- AppInit_DLLs --
    def _check_appinit_dlls(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command([
            "reg", "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "/v", "AppInit_DLLs",
        ])
        if output is None:
            return findings
        for line in output.splitlines():
            if "AppInit_DLLs" in line:
                parts = line.strip().split(None, 2)
                value = parts[2] if len(parts) >= 3 else ""
                if value.strip():
                    findings.append(self._finding(
                        title="AppInit_DLLs persistence detected",
                        description=(
                            f"AppInit_DLLs is set to '{value}'. This DLL will be loaded "
                            f"into every user-mode process."
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "dll_path": value,
                            "mechanism": "AppInit_DLLs",
                        },
                        remediation="Clear AppInit_DLLs unless explicitly required.",
                    ))
        return findings

    # -- Winlogon Shell / Userinit --
    def _check_winlogon(self) -> list[Finding]:
        findings: list[Finding] = []
        key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        for value_name, expected in [
            ("Shell", "explorer.exe"),
            ("Userinit", r"C:\Windows\system32\userinit.exe,"),
        ]:
            output = self._run_command(["reg", "query", key, "/v", value_name])
            if output is None:
                continue
            for line in output.splitlines():
                if value_name in line:
                    parts = line.strip().split(None, 2)
                    actual = parts[2] if len(parts) >= 3 else ""
                    if actual.strip().lower() != expected.lower():
                        findings.append(self._finding(
                            title=f"Winlogon {value_name} hijacked",
                            description=(
                                f"Winlogon {value_name} expected '{expected}' but "
                                f"found '{actual}'. This is a critical persistence vector."
                            ),
                            severity=Severity.CRITICAL,
                            evidence={
                                "key": value_name,
                                "expected_value": expected,
                                "actual_value": actual,
                                "mechanism": "Winlogon",
                            },
                            remediation=f"Restore {value_name} to '{expected}'.",
                        ))
        return findings

    # -- Services from suspicious paths --
    def _check_services_suspicious_paths(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command([
            "powershell", "-NoProfile", "-Command",
            "Get-WmiObject win32_service | Where-Object { $_.PathName } | "
            "Select Name,PathName,StartMode | ConvertTo-Json",
        ])
        if output is None:
            return findings
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            for svc in data:
                svc_name = svc.get("Name", "")
                binary_path = svc.get("PathName", "")
                start_mode = svc.get("StartMode", "")
                if self._is_suspicious_path(binary_path):
                    findings.append(self._finding(
                        title=f"Service from suspicious path: {svc_name}",
                        description=(
                            f"Service '{svc_name}' binary is located in a suspicious "
                            f"directory: {binary_path}"
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "service_name": svc_name,
                            "binary_path": binary_path,
                            "start_mode": start_mode,
                            "mechanism": "Service",
                        },
                        remediation="Verify this service is legitimate. Remove if unauthorized.",
                    ))
        except (json.JSONDecodeError, TypeError):
            pass
        return findings

    # -- Startup Folder --
    def _check_startup_folder(self) -> list[Finding]:
        findings: list[Finding] = []
        folders = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows"
            / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "Microsoft"
            / "Windows" / "Start Menu" / "Programs" / "Startup",
        ]
        suspicious_exts = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".wsf"}
        for folder in folders:
            try:
                if not folder.is_dir():
                    continue
                for item in folder.iterdir():
                    if item.suffix.lower() in suspicious_exts:
                        severity = Severity.HIGH if self._is_suspicious_path(str(item)) else Severity.MEDIUM
                        findings.append(self._finding(
                            title=f"Executable in Startup folder: {item.name}",
                            description=(
                                f"Found '{item.name}' in Startup folder '{folder}'. "
                                f"Startup folder items run automatically at login."
                            ),
                            severity=severity,
                            evidence={
                                "path": str(item),
                                "filename": item.name,
                                "mechanism": "Startup Folder",
                            },
                            remediation="Verify this file is legitimate. Remove if not recognized.",
                        ))
            except OSError:
                continue
        return findings

    # -- Boot Execute --
    def _check_boot_execute(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "/v", "BootExecute",
        ])
        if output is None:
            return findings
        for line in output.splitlines():
            if "BootExecute" in line:
                parts = line.strip().split(None, 2)
                value = parts[2] if len(parts) >= 3 else ""
                if value.strip().lower() not in (
                    "autocheck autochk *",
                    "autocheck autochk *\\0",
                    "",
                ):
                    findings.append(self._finding(
                        title="Boot Execute value modified",
                        description=(
                            f"BootExecute is set to '{value}'. Default is "
                            f"'autocheck autochk *'. Modifications may indicate "
                            f"a bootkit or persistence mechanism."
                        ),
                        severity=Severity.CRITICAL,
                        evidence={
                            "value": value,
                            "mechanism": "Boot Execute",
                        },
                        remediation="Restore BootExecute to 'autocheck autochk *'.",
                    ))
        return findings

    # -- LSA Security Packages --
    def _check_lsa_security_packages(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "/v", "Security Packages",
        ])
        if output is None:
            return findings
        for line in output.splitlines():
            if "Security Packages" in line:
                parts = line.strip().split(None, 2)
                value = parts[2] if len(parts) >= 3 else ""
                packages = [p.strip().lower() for p in value.replace("\\0", "\n").splitlines() if p.strip()]
                unknown = [p for p in packages if p not in KNOWN_LSA_PACKAGES]
                if unknown:
                    findings.append(self._finding(
                        title="Unknown LSA Security Package detected",
                        description=(
                            f"LSA Security Packages contains non-standard entries: "
                            f"{', '.join(unknown)}. This is a known credential-theft "
                            f"persistence technique (e.g., mimikatz SSP)."
                        ),
                        severity=Severity.CRITICAL,
                        evidence={
                            "packages": value,
                            "unknown_packages": unknown,
                            "mechanism": "LSA Security Packages",
                        },
                        remediation="Remove unknown SSP DLLs from Security Packages.",
                    ))
        return findings

    # ==================================================================
    #  LINUX
    # ==================================================================
    def _scan_linux(self) -> list[Finding]:
        findings: list[Finding] = []
        checks = [
            self._check_crontabs,
            self._check_systemd_services,
            self._check_shell_rc_injection,
            self._check_ld_preload,
            self._check_kernel_modules,
            self._check_ssh_authorized_keys,
            self._check_pam_modules,
            self._check_xdg_autostart,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as exc:
                self.log.debug(f"  [PersistenceScanner] {check.__name__} error: {exc}")
        return findings

    # -- Crontabs --
    def _check_crontabs(self) -> list[Finding]:
        findings: list[Finding] = []
        cron_files: list[tuple[str, str]] = []

        # System crontab
        etc_crontab = Path("/etc/crontab")
        if etc_crontab.is_file():
            try:
                cron_files.append(("/etc/crontab", etc_crontab.read_text()))
            except OSError:
                pass

        # /etc/cron.d/
        cron_d = Path("/etc/cron.d")
        if cron_d.is_dir():
            try:
                for entry in cron_d.iterdir():
                    if entry.is_file():
                        try:
                            cron_files.append((str(entry), entry.read_text()))
                        except OSError:
                            pass
            except OSError:
                pass

        # Current user crontab
        user_crontab = self._run_command(["crontab", "-l"])
        if user_crontab:
            cron_files.append(("user crontab", user_crontab))

        for source, content in cron_files:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                suspicious = self._has_suspicious_command(line)
                if suspicious:
                    findings.append(self._finding(
                        title=f"Suspicious cron entry in {source}",
                        description=(
                            f"Cron entry contains suspicious patterns: "
                            f"{', '.join(suspicious)}. Entry: {line[:200]}"
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "cron_entry": line,
                            "source_file": source,
                            "mechanism": "Crontab",
                            "patterns_matched": suspicious,
                        },
                        remediation="Investigate this cron entry and remove if unauthorized.",
                    ))
                elif self._is_suspicious_path(line):
                    findings.append(self._finding(
                        title=f"Cron entry from suspicious path in {source}",
                        description=f"Cron entry references suspicious path: {line[:200]}",
                        severity=Severity.HIGH,
                        evidence={
                            "cron_entry": line,
                            "source_file": source,
                            "mechanism": "Crontab",
                        },
                        remediation="Verify this cron entry is legitimate.",
                    ))
        return findings

    # -- Systemd services --
    def _check_systemd_services(self) -> list[Finding]:
        findings: list[Finding] = []
        search_dirs = [
            Path("/etc/systemd/system"),
            Path.home() / ".config" / "systemd" / "user",
        ]
        now = time.time()
        seven_days = 7 * 86400

        for sdir in search_dirs:
            if not sdir.is_dir():
                continue
            try:
                for item in sdir.iterdir():
                    if not item.name.endswith(".service") or not item.is_file():
                        continue
                    try:
                        content = item.read_text()
                    except OSError:
                        continue

                    exec_start = ""
                    for cline in content.splitlines():
                        cline = cline.strip()
                        if cline.startswith("ExecStart="):
                            exec_start = cline[len("ExecStart="):]
                            break

                    is_recent = (now - item.stat().st_mtime) < seven_days
                    suspicious_cmds = self._has_suspicious_command(exec_start)
                    suspicious_path = self._is_suspicious_path(exec_start)

                    if suspicious_cmds or suspicious_path:
                        findings.append(self._finding(
                            title=f"Suspicious systemd service: {item.name}",
                            description=(
                                f"Systemd unit '{item.name}' has suspicious ExecStart: "
                                f"{exec_start[:200]}"
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "unit_name": item.name,
                                "exec_start": exec_start,
                                "path": str(item),
                                "mechanism": "systemd Service",
                            },
                            remediation="Investigate and disable: systemctl disable " + item.name,
                        ))
                    elif is_recent:
                        findings.append(self._finding(
                            title=f"Recently created systemd service: {item.name}",
                            description=(
                                f"Systemd unit '{item.name}' was created/modified in the "
                                f"last 7 days. ExecStart: {exec_start[:200]}"
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "unit_name": item.name,
                                "exec_start": exec_start,
                                "path": str(item),
                                "mechanism": "systemd Service",
                            },
                            remediation="Verify this service was intentionally installed.",
                        ))
            except OSError:
                continue
        return findings

    # -- Shell RC injection --
    def _check_shell_rc_injection(self) -> list[Finding]:
        findings: list[Finding] = []
        home = Path.home()
        rc_files = [
            home / ".bashrc",
            home / ".bash_profile",
            home / ".profile",
            home / ".zshrc",
        ]
        for rc in rc_files:
            if not rc.is_file():
                continue
            try:
                content = rc.read_text()
            except OSError:
                continue
            suspicious_lines: list[str] = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if self._has_suspicious_command(line):
                    suspicious_lines.append(line[:200])
            if suspicious_lines:
                findings.append(self._finding(
                    title=f"Suspicious content in {rc.name}",
                    description=(
                        f"Shell RC file '{rc}' contains {len(suspicious_lines)} "
                        f"suspicious line(s) that may indicate persistence."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "file": str(rc),
                        "suspicious_lines": suspicious_lines[:10],
                        "mechanism": "Shell RC",
                    },
                    remediation="Review the flagged lines and remove any unauthorized entries.",
                ))
        return findings

    # -- LD_PRELOAD --
    def _check_ld_preload(self) -> list[Finding]:
        findings: list[Finding] = []
        preload_file = Path("/etc/ld.so.preload")
        if preload_file.is_file():
            try:
                content = preload_file.read_text().strip()
                if content:
                    findings.append(self._finding(
                        title="LD_PRELOAD persistence via /etc/ld.so.preload",
                        description=(
                            f"/etc/ld.so.preload contains entries: {content[:200]}. "
                            f"This causes libraries to be injected into every process."
                        ),
                        severity=Severity.CRITICAL,
                        evidence={
                            "path_or_env": "/etc/ld.so.preload",
                            "value": content,
                            "mechanism": "LD_PRELOAD",
                        },
                        remediation="Remove /etc/ld.so.preload unless explicitly required.",
                    ))
            except OSError:
                pass

        env_preload = os.environ.get("LD_PRELOAD", "")
        if env_preload:
            findings.append(self._finding(
                title="LD_PRELOAD environment variable set",
                description=(
                    f"LD_PRELOAD is set to '{env_preload}'. This injects shared "
                    f"libraries into processes and is a common rootkit technique."
                ),
                severity=Severity.CRITICAL,
                evidence={
                    "path_or_env": "LD_PRELOAD",
                    "value": env_preload,
                    "mechanism": "LD_PRELOAD",
                },
                remediation="Unset LD_PRELOAD unless explicitly required.",
            ))
        return findings

    # -- Kernel modules --
    def _check_kernel_modules(self) -> list[Finding]:
        findings: list[Finding] = []
        lsmod_output = self._run_command(["lsmod"])
        if lsmod_output:
            for line in lsmod_output.splitlines()[1:]:  # skip header
                parts = line.split()
                if not parts:
                    continue
                module_name = parts[0]
                if self._is_suspicious_path(module_name):
                    findings.append(self._finding(
                        title=f"Suspicious kernel module: {module_name}",
                        description=f"Kernel module '{module_name}' has a suspicious name.",
                        severity=Severity.HIGH,
                        evidence={
                            "module_name": module_name,
                            "source": "lsmod",
                            "mechanism": "Kernel Module",
                        },
                        remediation=f"Investigate: modinfo {module_name}",
                    ))

        modules_dir = Path("/etc/modules-load.d")
        if modules_dir.is_dir():
            try:
                for entry in modules_dir.iterdir():
                    if not entry.is_file():
                        continue
                    try:
                        content = entry.read_text()
                    except OSError:
                        continue
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        suspicious = self._has_suspicious_command(line)
                        if suspicious or self._is_suspicious_path(line):
                            findings.append(self._finding(
                                title=f"Suspicious module autoload: {line}",
                                description=(
                                    f"Module '{line}' in {entry} is set to autoload "
                                    f"and appears suspicious."
                                ),
                                severity=Severity.HIGH,
                                evidence={
                                    "module_name": line,
                                    "source": str(entry),
                                    "mechanism": "Kernel Module",
                                },
                                remediation="Investigate this autoloaded kernel module.",
                            ))
            except OSError:
                pass
        return findings

    # -- SSH authorized_keys --
    def _check_ssh_authorized_keys(self) -> list[Finding]:
        findings: list[Finding] = []
        auth_keys = Path.home() / ".ssh" / "authorized_keys"
        if not auth_keys.is_file():
            return findings
        try:
            content = auth_keys.read_text()
        except OSError:
            return findings

        keys = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        has_command = any(l.startswith("command=") for l in keys)

        if has_command:
            findings.append(self._finding(
                title="SSH authorized_keys with command restriction",
                description=(
                    "authorized_keys contains entries with 'command=' restrictions. "
                    "While sometimes legitimate, this can be used for persistence."
                ),
                severity=Severity.HIGH,
                evidence={
                    "key_count": len(keys),
                    "has_command_restriction": True,
                    "mechanism": "SSH Authorized Keys",
                },
                remediation="Review command= entries in authorized_keys.",
            ))

        # Check modification time
        try:
            mtime = auth_keys.stat().st_mtime
            if (time.time() - mtime) < 7 * 86400:
                findings.append(self._finding(
                    title="SSH authorized_keys recently modified",
                    description=(
                        "authorized_keys was modified in the last 7 days. "
                        "Verify no unauthorized keys were added."
                    ),
                    severity=Severity.MEDIUM,
                    evidence={
                        "key_count": len(keys),
                        "has_command_restriction": has_command,
                        "mechanism": "SSH Authorized Keys",
                    },
                    remediation="Review recent changes to authorized_keys.",
                ))
        except OSError:
            pass
        return findings

    # -- PAM modules --
    def _check_pam_modules(self) -> list[Finding]:
        findings: list[Finding] = []
        pam_dir = Path("/etc/pam.d")
        if not pam_dir.is_dir():
            return findings
        standard_paths = ["/lib/security/", "/lib64/security/", "/usr/lib/security/",
                          "/usr/lib64/security/"]
        try:
            for pam_file in pam_dir.iterdir():
                if not pam_file.is_file():
                    continue
                try:
                    content = pam_file.read_text()
                except OSError:
                    continue
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Look for module paths
                    if "/" in line:
                        # Extract token that looks like a path
                        for token in line.split():
                            if "/" in token and not any(sp in token for sp in standard_paths):
                                findings.append(self._finding(
                                    title=f"Non-standard PAM module in {pam_file.name}",
                                    description=(
                                        f"PAM config '{pam_file.name}' references a "
                                        f"non-standard module path: {token}"
                                    ),
                                    severity=Severity.HIGH,
                                    evidence={
                                        "pam_file": str(pam_file),
                                        "suspicious_module": token,
                                        "mechanism": "PAM Module",
                                    },
                                    remediation="Verify this PAM module is legitimate.",
                                ))
                                break
        except OSError:
            pass
        return findings

    # -- XDG Autostart --
    def _check_xdg_autostart(self) -> list[Finding]:
        findings: list[Finding] = []
        autostart_dir = Path.home() / ".config" / "autostart"
        if not autostart_dir.is_dir():
            return findings
        try:
            for desktop_file in autostart_dir.iterdir():
                if not desktop_file.name.endswith(".desktop") or not desktop_file.is_file():
                    continue
                try:
                    content = desktop_file.read_text()
                except OSError:
                    continue
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("Exec="):
                        exec_cmd = line[len("Exec="):]
                        suspicious = self._has_suspicious_command(exec_cmd)
                        if suspicious or self._is_suspicious_path(exec_cmd):
                            findings.append(self._finding(
                                title=f"Suspicious XDG autostart: {desktop_file.name}",
                                description=(
                                    f"Desktop file '{desktop_file.name}' has a suspicious "
                                    f"Exec command: {exec_cmd[:200]}"
                                ),
                                severity=Severity.HIGH,
                                evidence={
                                    "desktop_file": str(desktop_file),
                                    "exec_command": exec_cmd,
                                    "mechanism": "XDG Autostart",
                                },
                                remediation="Remove this .desktop file if not recognized.",
                            ))
                        break
        except OSError:
            pass
        return findings

    # ==================================================================
    #  macOS
    # ==================================================================
    def _scan_macos(self) -> list[Finding]:
        findings: list[Finding] = []
        checks = [
            self._check_launch_agents,
            self._check_launch_daemons,
            self._check_login_items,
            self._check_kext,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as exc:
                self.log.debug(f"  [PersistenceScanner] {check.__name__} error: {exc}")
        return findings

    # -- LaunchAgents --
    def _check_launch_agents(self) -> list[Finding]:
        findings: list[Finding] = []
        agent_dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
        ]
        for agent_dir in agent_dirs:
            if not agent_dir.is_dir():
                continue
            try:
                for plist in agent_dir.iterdir():
                    if not plist.name.endswith(".plist") or not plist.is_file():
                        continue
                    try:
                        content = plist.read_text()
                    except OSError:
                        continue
                    program = self._extract_plist_program(content)
                    suspicious_cmds = self._has_suspicious_command(program)
                    if suspicious_cmds or self._is_suspicious_path(program):
                        findings.append(self._finding(
                            title=f"Suspicious LaunchAgent: {plist.name}",
                            description=(
                                f"LaunchAgent '{plist.name}' executes suspicious "
                                f"program: {program[:200]}"
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "plist_path": str(plist),
                                "program": program,
                                "mechanism": "LaunchAgent",
                            },
                            remediation=f"Remove {plist} if not recognized.",
                        ))
            except OSError:
                continue
        return findings

    # -- LaunchDaemons --
    def _check_launch_daemons(self) -> list[Finding]:
        findings: list[Finding] = []
        daemon_dir = Path("/Library/LaunchDaemons")
        if not daemon_dir.is_dir():
            return findings
        try:
            for plist in daemon_dir.iterdir():
                if not plist.name.endswith(".plist") or not plist.is_file():
                    continue
                # Non-Apple daemons are significant — they run as root
                if not plist.name.startswith("com.apple."):
                    try:
                        content = plist.read_text()
                    except OSError:
                        content = ""
                    program = self._extract_plist_program(content)
                    findings.append(self._finding(
                        title=f"Non-Apple LaunchDaemon: {plist.name}",
                        description=(
                            f"LaunchDaemon '{plist.name}' is not an Apple system "
                            f"daemon. Daemons run as root and should be verified. "
                            f"Program: {program[:200]}"
                        ),
                        severity=Severity.CRITICAL,
                        evidence={
                            "plist_path": str(plist),
                            "program": program,
                            "mechanism": "LaunchDaemon",
                        },
                        remediation=f"Verify {plist.name} is from a trusted vendor.",
                    ))
        except OSError:
            pass
        return findings

    # -- Login Items --
    def _check_login_items(self) -> list[Finding]:
        findings: list[Finding] = []
        output = self._run_command([
            "osascript", "-e",
            'tell application "System Events" to get the name of every login item',
        ])
        if output is None:
            return findings
        items = [i.strip() for i in output.split(",") if i.strip()]
        for item in items:
            severity = Severity.HIGH if self._is_suspicious_path(item) else Severity.MEDIUM
            findings.append(self._finding(
                title=f"Login item detected: {item}",
                description=f"Login item '{item}' runs at user login.",
                severity=severity,
                evidence={
                    "item_name": item,
                    "mechanism": "Login Item",
                },
                remediation="Remove from System Settings > Login Items if not needed.",
            ))
        return findings

    # -- Kernel Extensions --
    def _check_kext(self) -> list[Finding]:
        findings: list[Finding] = []
        kext_dir = Path("/Library/Extensions")
        if not kext_dir.is_dir():
            return findings
        try:
            for item in kext_dir.iterdir():
                if item.name.endswith(".kext"):
                    if not item.name.startswith("com.apple."):
                        findings.append(self._finding(
                            title=f"Non-Apple kernel extension: {item.name}",
                            description=(
                                f"Kernel extension '{item.name}' is not from Apple. "
                                f"Third-party kexts run with kernel privileges and can "
                                f"be used for rootkit persistence."
                            ),
                            severity=Severity.CRITICAL,
                            evidence={
                                "kext_path": str(item),
                                "mechanism": "Kernel Extension",
                            },
                            remediation=f"Verify '{item.name}' is from a trusted vendor.",
                        ))
        except OSError:
            pass
        return findings

    # -- plist helper --
    @staticmethod
    def _extract_plist_program(content: str) -> str:
        """Best-effort extraction of the program from an XML plist."""
        # Try ProgramArguments first
        match = re.search(
            r"<key>ProgramArguments</key>\s*<array>\s*<string>(.*?)</string>",
            content,
            re.DOTALL,
        )
        if match:
            return match.group(1).strip()
        # Fall back to Program
        match = re.search(
            r"<key>Program</key>\s*<string>(.*?)</string>",
            content,
            re.DOTALL,
        )
        if match:
            return match.group(1).strip()
        return ""

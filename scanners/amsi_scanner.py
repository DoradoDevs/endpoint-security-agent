"""
Sentinel Agent — AMSI (Antimalware Scan Interface) Scanner

Integrates with Windows AMSI to inspect script content for malicious
patterns. AMSI provides visibility into:
- PowerShell script blocks (including obfuscated/encoded scripts)
- VBScript / JScript execution
- .NET assembly loading
- Office macro execution

AMSI sees the DEOBFUSCATED content — meaning even base64-encoded or
concatenated scripts are inspected in their final, executed form.

This scanner reads PowerShell Script Block Logging events from the
Windows Event Log (Event ID 4104) where AMSI results are recorded,
and analyzes them for malicious indicators.

SECURITY: Read-only. We only inspect script content already logged
by Windows, never hook into live execution.

PLATFORM: Windows only. No-op on other platforms.
"""

from __future__ import annotations

import platform
import re
import subprocess
from typing import Any

from core.config import AgentConfig, Severity
from core.logging import get_logger
from core.telemetry import Finding
from scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Malicious script patterns (post-deobfuscation)
# ---------------------------------------------------------------------------

AMSI_PATTERNS: list[dict[str, Any]] = [
    # Credential theft
    {
        "name": "credential_dump",
        "patterns": [
            r"sekurlsa::logonpasswords",
            r"invoke-mimikatz",
            r"get-credential",
            r"\bsam\s*dump\b",
            r"ntds\.dit",
            r"invoke-ninjacopy",
        ],
        "severity": Severity.CRITICAL,
        "description": "Script attempts to dump credentials or access credential stores",
        "mitre": "T1003",
    },
    # Download & execute
    {
        "name": "download_execute",
        "patterns": [
            r"downloadstring\s*\(",
            r"downloadfile\s*\(",
            r"downloaddata\s*\(",
            r"invoke-webrequest.*\|\s*invoke-expression",
            r"iwr.*\|\s*iex",
            r"wget.*\|\s*iex",
            r"curl.*\|\s*iex",
            r"net\.webclient.*download",
            r"start-bitstransfer",
            r"certutil\s+-urlcache",
        ],
        "severity": Severity.HIGH,
        "description": "Script downloads and executes remote content",
        "mitre": "T1059.001",
    },
    # Execution & evasion
    {
        "name": "execution_evasion",
        "patterns": [
            r"invoke-expression",
            r"\biex\b",
            r"set-executionpolicy\s+bypass",
            r"set-executionpolicy\s+unrestricted",
            r"-exec(?:utionpolicy)?\s+bypass",
            r"add-type.*dllimport",
            r"\[reflection\.assembly\]::load",
            r"invoke-reflectivepeinjection",
        ],
        "severity": Severity.HIGH,
        "description": "Script uses execution bypass or reflective loading techniques",
        "mitre": "T1059.001",
    },
    # Process injection
    {
        "name": "process_injection",
        "patterns": [
            r"virtualalloc(?:ex)?\s*\(",
            r"writeprocessmemory",
            r"createremotethread",
            r"ntwritevirtualmemory",
            r"rtlcreateuserthread",
            r"queueuserapc",
        ],
        "severity": Severity.CRITICAL,
        "description": "Script uses process injection API calls",
        "mitre": "T1055",
    },
    # Persistence
    {
        "name": "persistence",
        "patterns": [
            r"new-scheduledtask",
            r"register-scheduledtask",
            r"schtasks\s+/create",
            r"new-service",
            r"set-itemproperty.*\\run\\",
            r"wmi.*__eventfilter",
            r"wmi.*commandlineeventconsumer",
        ],
        "severity": Severity.HIGH,
        "description": "Script establishes persistence mechanisms",
        "mitre": "T1053",
    },
    # Reconnaissance
    {
        "name": "reconnaissance",
        "patterns": [
            r"get-adcomputer",
            r"get-aduser",
            r"get-adgroup",
            r"get-domain(?:controller)?",
            r"invoke-sharefinder",
            r"invoke-portscan",
            r"get-netcomputer",
            r"find-localadminaccess",
        ],
        "severity": Severity.MEDIUM,
        "description": "Script performs Active Directory or network reconnaissance",
        "mitre": "T1087",
    },
    # Lateral movement
    {
        "name": "lateral_movement",
        "patterns": [
            r"invoke-psexec",
            r"invoke-wmimethod",
            r"invoke-command\s+-computer",
            r"enter-pssession",
            r"new-pssession",
            r"invoke-smbexec",
            r"invoke-dcomexec",
        ],
        "severity": Severity.HIGH,
        "description": "Script performs lateral movement to other systems",
        "mitre": "T1021",
    },
    # Data exfiltration
    {
        "name": "exfiltration",
        "patterns": [
            r"invoke-restmethod.*post",
            r"invoke-webrequest.*-method\s+post",
            r"send-mailmessage",
            r"\[net\.dns\]::resolve",
            r"convertto-base64",
            r"compress-archive.*-path",
        ],
        "severity": Severity.HIGH,
        "description": "Script exfiltrates data via HTTP POST, email, or DNS",
        "mitre": "T1041",
    },
    # Ransomware
    {
        "name": "ransomware",
        "patterns": [
            r"encrypt.*file",
            r"\baes\b.*encrypt",
            r"rsa.*encrypt",
            r"bitcoin|btc\s*wallet",
            r"ransom\s*note",
            r"\.encrypted\b",
            r"your\s+files\s+have\s+been",
        ],
        "severity": Severity.CRITICAL,
        "description": "Script contains ransomware indicators",
        "mitre": "T1486",
    },
    # Defense evasion
    {
        "name": "defense_evasion",
        "patterns": [
            r"set-mppreference\s+-disable",
            r"remove-mppreference",
            r"add-mppreference\s+-exclusion",
            r"stop-service.*windefend",
            r"disable-windowsoptionalfeature.*defender",
            r"amsiutils",
            r"amsiinitfailed",
            r"amsi\.dll",
        ],
        "severity": Severity.CRITICAL,
        "description": "Script attempts to disable security tools or bypass AMSI",
        "mitre": "T1562.001",
    },
]


class AMSIScanner(BaseScanner):
    """Scans PowerShell Script Block Logs for malicious content via AMSI patterns."""

    @property
    def name(self) -> str:
        return "AMSIScanner"

    @property
    def description(self) -> str:
        return "Analyzes PowerShell script blocks for malicious patterns via AMSI"

    @property
    def supported_platforms(self) -> list[str]:
        return ["windows"]

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self._is_windows = platform.system().lower() == "windows"

    def scan(self) -> list[Finding]:
        """Read and analyze recent PowerShell Script Block Log entries."""
        if not self._is_windows:
            return []

        findings: list[Finding] = []
        script_blocks = self._read_script_block_logs()

        for block in script_blocks:
            block_findings = self._analyze_script_block(block)
            findings.extend(block_findings)

        return findings

    def _read_script_block_logs(self) -> list[dict[str, str]]:
        """Read PowerShell Script Block Logging events (Event ID 4104)."""
        blocks: list[dict[str, str]] = []

        try:
            # Query last 200 script block events from the last 24 hours
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{"
                "LogName='Microsoft-Windows-PowerShell/Operational';"
                "Id=4104;"
                "StartTime=(Get-Date).AddHours(-24)"
                "} -MaxEvents 200 -ErrorAction SilentlyContinue | "
                "ForEach-Object { @{"
                "  RecordId = $_.RecordId;"
                "  TimeCreated = $_.TimeCreated.ToString('o');"
                "  ScriptBlock = $_.Properties[2].Value;"
                "  Path = $_.Properties[4].Value"
                "} } | ConvertTo-Json -Compress -Depth 3"
            )

            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30,
            )

            if result.returncode != 0 or not result.stdout.strip():
                return blocks

            import json
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]

            for entry in data:
                script_text = entry.get("ScriptBlock", "")
                if script_text and len(script_text) > 10:
                    blocks.append({
                        "record_id": str(entry.get("RecordId", "")),
                        "timestamp": entry.get("TimeCreated", ""),
                        "content": script_text,
                        "path": entry.get("Path", ""),
                    })

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.log.debug(f"[AMSI] Script block log read failed: {e}")
        except Exception as e:
            self.log.debug(f"[AMSI] Unexpected error: {e}")

        return blocks

    def _analyze_script_block(self, block: dict[str, str]) -> list[Finding]:
        """Analyze a script block for malicious patterns."""
        findings: list[Finding] = []
        content = block.get("content", "")
        content_lower = content.lower()

        for rule in AMSI_PATTERNS:
            matched_patterns: list[str] = []
            for pattern in rule["patterns"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                # Extract a safe snippet (first 200 chars of match context)
                snippet = self._extract_snippet(content, matched_patterns[0])

                findings.append(Finding(
                    title=f"AMSI: {rule['name']} detected in PowerShell script",
                    description=rule["description"],
                    severity=rule["severity"],
                    category="Script Analysis",
                    scanner=self.name,
                    evidence={
                        "rule_name": rule["name"],
                        "matched_patterns": matched_patterns,
                        "match_count": len(matched_patterns),
                        "script_path": block.get("path", ""),
                        "record_id": block.get("record_id", ""),
                        "timestamp": block.get("timestamp", ""),
                        "snippet": snippet,
                        "mitre_technique": rule.get("mitre", ""),
                        "script_length": len(content),
                    },
                    remediation=(
                        f"Investigate the PowerShell script block (Record ID: "
                        f"{block.get('record_id', 'unknown')}). "
                        f"Path: {block.get('path', 'interactive')}. "
                        f"This script contains patterns associated with: {rule['name']}."
                    ),
                ))

        return findings

    @staticmethod
    def _extract_snippet(content: str, pattern: str) -> str:
        """Extract a 200-char snippet around the first pattern match."""
        match = re.search(pattern, content, re.IGNORECASE)
        if not match:
            return content[:200]
        start = max(0, match.start() - 50)
        end = min(len(content), match.end() + 150)
        snippet = content[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."
        return snippet

    def get_info(self) -> dict[str, Any]:
        """Return scanner info."""
        return {
            "platform": "windows",
            "pattern_count": sum(len(r["patterns"]) for r in AMSI_PATTERNS),
            "rule_count": len(AMSI_PATTERNS),
        }

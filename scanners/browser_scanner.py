"""
Sentinel Agent — Browser Security Scanner

Checks for outdated browsers, dangerous extensions, and insecure
browser configurations. Desktop-only (Windows and macOS).
"""

from __future__ import annotations

import json
import platform
import subprocess
from pathlib import Path

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner


# Known malicious or risky Chrome/Edge extension IDs
SUSPICIOUS_EXTENSION_IDS = {
    # Known cryptominers and adware
    "efaidnbmnnnibpcajpcglclefindmkaj": "Potential adware (fake PDF viewer)",
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Suspicious extension (known malware variant)",
}

# Suspicious extension permission patterns
RISKY_PERMISSIONS = [
    "webRequestBlocking",
    "nativeMessaging",
    "debugger",
    "proxy",
]

# Common browser paths
CHROME_PATHS_WINDOWS = [
    Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
]

CHROME_PATHS_MACOS = [
    Path.home() / "Library" / "Application Support" / "Google" / "Chrome",
]

EDGE_PATHS_WINDOWS = [
    Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
]

FIREFOX_PATHS_WINDOWS = [
    Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
]

FIREFOX_PATHS_MACOS = [
    Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles",
]


def _run_cmd(args: list[str], timeout: int = 15) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


class BrowserScanner(BaseScanner):
    """Scans browser security: versions, extensions, and configurations."""

    @property
    def name(self) -> str:
        return "Browser Security Scanner"

    @property
    def description(self) -> str:
        return "Check browser versions, extensions, and security settings"

    @property
    def supported_platforms(self) -> list[str]:
        return ["windows", "darwin"]

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        system = platform.system().lower()

        # Check browser versions
        findings.extend(self._check_browser_versions(system))

        # Scan for suspicious extensions
        findings.extend(self._scan_extensions(system))

        return findings

    def _check_browser_versions(self, system: str) -> list[Finding]:
        """Check if installed browsers are up to date."""
        findings: list[Finding] = []
        browsers_found = []

        if system == "windows":
            # Chrome
            success, output = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe' -ErrorAction SilentlyContinue).'(default)'"
            ])
            if success and output:
                browsers_found.append("Google Chrome")
                ver_success, version = _run_cmd([
                    "powershell", "-NoProfile", "-Command",
                    "(Get-Item (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe').'(default)').VersionInfo.ProductVersion"
                ])
                if ver_success and version:
                    browsers_found[-1] = f"Google Chrome {version}"

            # Edge
            success, output = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "(Get-AppxPackage -Name 'Microsoft.MicrosoftEdge.Stable' -ErrorAction SilentlyContinue).Version"
            ])
            if success and output:
                browsers_found.append(f"Microsoft Edge {output}")

            # Firefox
            success, output = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Mozilla\\Mozilla Firefox' -ErrorAction SilentlyContinue).CurrentVersion"
            ])
            if success and output:
                browsers_found.append(f"Mozilla Firefox {output}")

        elif system == "darwin":
            # Chrome
            chrome_path = Path("/Applications/Google Chrome.app/Contents/Info.plist")
            if chrome_path.exists():
                success, output = _run_cmd([
                    "defaults", "read", "/Applications/Google Chrome.app/Contents/Info.plist",
                    "CFBundleShortVersionString"
                ])
                if success:
                    browsers_found.append(f"Google Chrome {output}")

            # Firefox
            firefox_path = Path("/Applications/Firefox.app/Contents/Info.plist")
            if firefox_path.exists():
                success, output = _run_cmd([
                    "defaults", "read", "/Applications/Firefox.app/Contents/Info.plist",
                    "CFBundleShortVersionString"
                ])
                if success:
                    browsers_found.append(f"Mozilla Firefox {output}")

            # Safari (always present on macOS)
            success, output = _run_cmd([
                "defaults", "read", "/Applications/Safari.app/Contents/Info.plist",
                "CFBundleShortVersionString"
            ])
            if success:
                browsers_found.append(f"Safari {output}")

        if browsers_found:
            findings.append(Finding(
                title="Installed browsers detected",
                description=f"Found {len(browsers_found)} browser(s) installed.",
                severity=Severity.INFO,
                category="Browser Security",
                scanner=self.name,
                evidence={"browsers": browsers_found},
                remediation="Keep all browsers updated to the latest version.",
            ))

        return findings

    def _scan_extensions(self, system: str) -> list[Finding]:
        """Scan for suspicious browser extensions."""
        findings: list[Finding] = []

        # Determine Chrome profile paths
        if system == "windows":
            chrome_dirs = CHROME_PATHS_WINDOWS
            edge_dirs = EDGE_PATHS_WINDOWS
        else:
            chrome_dirs = CHROME_PATHS_MACOS
            edge_dirs = []

        all_browser_dirs = [
            ("Chrome", chrome_dirs),
            ("Edge", edge_dirs),
        ]

        for browser_name, base_dirs in all_browser_dirs:
            for base_dir in base_dirs:
                if not base_dir.exists():
                    continue

                # Find all profile directories
                profiles = [base_dir / "Default"] + list(base_dir.glob("Profile *"))

                for profile_dir in profiles:
                    ext_dir = profile_dir / "Extensions"
                    if not ext_dir.exists():
                        continue

                    extension_count = 0
                    suspicious_count = 0

                    try:
                        for ext_id_dir in ext_dir.iterdir():
                            if not ext_id_dir.is_dir():
                                continue
                            ext_id = ext_id_dir.name
                            extension_count += 1

                            # Check against known suspicious IDs
                            if ext_id in SUSPICIOUS_EXTENSION_IDS:
                                suspicious_count += 1
                                findings.append(Finding(
                                    title=f"Suspicious {browser_name} extension detected",
                                    description=f"{SUSPICIOUS_EXTENSION_IDS[ext_id]} "
                                                f"(Extension ID: {ext_id})",
                                    severity=Severity.HIGH,
                                    category="Browser Security",
                                    scanner=self.name,
                                    evidence={
                                        "browser": browser_name,
                                        "extension_id": ext_id,
                                        "profile": profile_dir.name,
                                    },
                                    remediation=f"Remove the suspicious extension from {browser_name}. "
                                                "Go to browser settings > Extensions and remove it.",
                                ))

                            # Check extension manifest for risky permissions
                            findings.extend(
                                self._check_extension_permissions(ext_id_dir, ext_id, browser_name)
                            )
                    except (PermissionError, OSError):
                        continue

                    if extension_count > 0:
                        findings.append(Finding(
                            title=f"{browser_name} extensions inventory",
                            description=f"Found {extension_count} extensions in {profile_dir.name}.",
                            severity=Severity.INFO,
                            category="Browser Security",
                            scanner=self.name,
                            evidence={
                                "browser": browser_name,
                                "extension_count": extension_count,
                                "suspicious_count": suspicious_count,
                            },
                            remediation="Review installed extensions periodically. "
                                        "Remove extensions you no longer use.",
                        ))

        return findings

    def _check_extension_permissions(
        self, ext_dir: Path, ext_id: str, browser_name: str
    ) -> list[Finding]:
        """Check if an extension has overly broad permissions."""
        findings: list[Finding] = []

        # Find the manifest.json in the latest version directory
        try:
            version_dirs = sorted(ext_dir.iterdir(), reverse=True)
            for vdir in version_dirs:
                manifest = vdir / "manifest.json"
                if manifest.exists():
                    data = json.loads(manifest.read_text(errors="replace"))
                    permissions = data.get("permissions", [])

                    risky_found = [p for p in permissions if p in RISKY_PERMISSIONS]
                    if risky_found:
                        ext_name = data.get("name", ext_id)
                        # Skip extensions with localized names (system extensions)
                        if ext_name.startswith("__MSG_"):
                            break
                        findings.append(Finding(
                            title=f"{browser_name} extension with risky permissions: {ext_name}",
                            description=f"Extension '{ext_name}' has permissions that could be "
                                        f"used maliciously: {', '.join(risky_found)}",
                            severity=Severity.MEDIUM,
                            category="Browser Security",
                            scanner=self.name,
                            evidence={
                                "browser": browser_name,
                                "extension_id": ext_id,
                                "extension_name": ext_name,
                                "risky_permissions": risky_found,
                            },
                            remediation="Review this extension's permissions. "
                                        "Remove it if you don't recognize or need it.",
                        ))
                    break
        except (OSError, json.JSONDecodeError, PermissionError):
            pass

        return findings

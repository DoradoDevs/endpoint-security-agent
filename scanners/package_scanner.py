"""
Sentinel Agent — Package & Software Scanner

Detects outdated software and packages, identifies known vulnerable versions,
and reports patch status:
- System packages (apt/dnf/brew/choco)
- Common software version checks
- CVE correlation via abstraction layer

Read-only — no packages are modified.
"""

from __future__ import annotations

import platform
import subprocess
from typing import Any

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner
from os_modules.loader import load_os_module


def _run_cmd(args: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


class PackageScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "Package Scanner"

    @property
    def description(self) -> str:
        return "Detect outdated software and known vulnerable package versions"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        system = platform.system().lower()

        if system == "linux":
            findings.extend(self._scan_linux_packages())
        elif system == "darwin":
            findings.extend(self._scan_macos_packages())
        elif system == "windows":
            findings.extend(self._scan_windows_packages())

        # OS patch level
        findings.extend(self._check_patch_level())

        # CVE lookup for detected packages
        if self.config.scan.enable_cve_lookup:
            findings.extend(self._cve_correlate())

        return findings

    def _scan_linux_packages(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check for upgradable packages (Debian/Ubuntu)
        apt_output = _run_cmd(["apt", "list", "--upgradable"])
        if apt_output:
            lines = [l for l in apt_output.splitlines() if "/" in l and "Listing" not in l]
            if lines:
                findings.append(Finding(
                    title=f"{len(lines)} packages have updates available",
                    description=(
                        f"Found {len(lines)} packages with available updates. "
                        f"First 10: {', '.join(l.split('/')[0] for l in lines[:10])}"
                    ),
                    severity=Severity.MEDIUM if len(lines) > 20 else Severity.LOW,
                    category="Patch Management",
                    scanner=self.name,
                    evidence={"upgradable_count": len(lines), "sample": lines[:20]},
                    remediation="Run 'apt upgrade' to install available updates.",
                ))

        # Check for security updates specifically
        sec_output = _run_cmd(["apt", "list", "--upgradable"])
        # On Debian/Ubuntu, security updates contain "-security" in the source
        if sec_output:
            security_updates = [l for l in sec_output.splitlines() if "-security" in l.lower()]
            if security_updates:
                findings.append(Finding(
                    title=f"{len(security_updates)} security updates pending",
                    description=(
                        f"Found {len(security_updates)} security-specific updates. "
                        "These should be applied promptly."
                    ),
                    severity=Severity.HIGH,
                    category="Patch Management",
                    scanner=self.name,
                    evidence={"security_updates": security_updates[:20]},
                    remediation="Apply security updates immediately with 'apt upgrade'.",
                ))

        # RHEL/CentOS fallback
        dnf_output = _run_cmd(["dnf", "check-update", "--quiet"])
        if dnf_output:
            lines = [l for l in dnf_output.splitlines() if l.strip() and not l.startswith("Last")]
            if lines:
                findings.append(Finding(
                    title=f"{len(lines)} packages have updates available (dnf)",
                    description=f"Found {len(lines)} packages with available updates via dnf.",
                    severity=Severity.MEDIUM if len(lines) > 20 else Severity.LOW,
                    category="Patch Management",
                    scanner=self.name,
                    evidence={"upgradable_count": len(lines)},
                    remediation="Run 'dnf upgrade' to install available updates.",
                ))

        return findings

    def _scan_macos_packages(self) -> list[Finding]:
        findings: list[Finding] = []

        # Homebrew
        brew_output = _run_cmd(["brew", "outdated", "--json=v2"])
        if brew_output:
            import json
            try:
                data = json.loads(brew_output)
                formulae = data.get("formulae", [])
                casks = data.get("casks", [])
                total = len(formulae) + len(casks)
                if total > 0:
                    findings.append(Finding(
                        title=f"{total} Homebrew packages outdated",
                        description=(
                            f"Found {len(formulae)} outdated formulae and {len(casks)} outdated casks."
                        ),
                        severity=Severity.LOW,
                        category="Patch Management",
                        scanner=self.name,
                        evidence={
                            "formulae": [f.get("name") for f in formulae[:20]],
                            "casks": [c.get("name") for c in casks[:20]],
                        },
                        remediation="Run 'brew upgrade' to update packages.",
                    ))
            except (json.JSONDecodeError, KeyError):
                pass

        # macOS software updates
        sw_output = _run_cmd(["softwareupdate", "--list"], timeout=60)
        if sw_output and "* Label:" in sw_output:
            count = sw_output.count("* Label:")
            findings.append(Finding(
                title=f"{count} macOS system updates available",
                description=f"Found {count} pending system updates.",
                severity=Severity.MEDIUM,
                category="Patch Management",
                scanner=self.name,
                evidence={"output": sw_output[:2000]},
                remediation="Install updates via System Preferences > Software Update.",
            ))

        return findings

    def _scan_windows_packages(self) -> list[Finding]:
        findings: list[Finding] = []

        # Windows Update status is handled by OS module
        os_module = load_os_module()
        update_status = os_module.get_update_status()

        if update_status.pending_updates > 0:
            severity = Severity.HIGH if update_status.pending_updates > 10 else Severity.MEDIUM
            findings.append(Finding(
                title=f"{update_status.pending_updates} Windows updates pending",
                description=(
                    f"Found {update_status.pending_updates} pending Windows updates. "
                    f"{update_status.details}"
                ),
                severity=severity,
                category="Patch Management",
                scanner=self.name,
                evidence={"pending": update_status.pending_updates, "details": update_status.details},
                remediation="Install pending Windows updates via Settings > Windows Update.",
            ))

        if not update_status.auto_updates_enabled:
            findings.append(Finding(
                title="Automatic Windows updates are disabled",
                description="Windows automatic updates are not configured. This leaves the system vulnerable.",
                severity=Severity.HIGH,
                category="Patch Management",
                scanner=self.name,
                remediation="Enable automatic updates in Settings > Windows Update.",
            ))

        return findings

    def _check_patch_level(self) -> list[Finding]:
        findings: list[Finding] = []
        os_module = load_os_module()
        patch_info = os_module.get_os_patch_level()

        findings.append(Finding(
            title=f"OS patch level: {patch_info.get('version', patch_info.get('product_version', 'unknown'))}",
            description=f"Current OS patch information collected.",
            severity=Severity.INFO,
            category="Patch Management",
            scanner=self.name,
            evidence=patch_info,
        ))

        return findings

    def _cve_correlate(self) -> list[Finding]:
        """Correlate detected software with known CVEs via abstraction layer."""
        findings: list[Finding] = []

        try:
            from vulnerability.cve_lookup import CVELookup
            cve_engine = CVELookup()

            # Get OS info for CVE lookup
            os_module = load_os_module()
            patch_info = os_module.get_os_patch_level()

            # Lookup CVEs for the current OS version
            system = platform.system().lower()
            if system == "windows":
                version = patch_info.get("version", "")
                cves = cve_engine.lookup_product("windows", version)
            elif system == "darwin":
                version = patch_info.get("product_version", "")
                cves = cve_engine.lookup_product("macos", version)
            else:
                version = patch_info.get("kernel", "")
                cves = cve_engine.lookup_product("linux_kernel", version)

            for cve in cves:
                findings.append(Finding(
                    title=f"Known vulnerability: {cve['id']}",
                    description=cve.get("description", "No description available"),
                    severity=Severity(cve.get("severity", "medium")),
                    category="Known Vulnerabilities",
                    scanner=self.name,
                    cve_ids=[cve["id"]],
                    evidence=cve,
                    remediation=cve.get("remediation", "Apply vendor patches."),
                ))

        except Exception as e:
            self.log.debug(f"CVE correlation skipped: {e}")

        return findings

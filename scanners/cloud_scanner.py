"""
Sentinel Agent — Cloud Security Scanner

Scans cloud environments (AWS, Azure, GCP) for security misconfigurations
by invoking CLI tools (aws, az, gcloud) via subprocess. No SDK dependencies.

Auto-detects which cloud CLIs are available and runs the relevant checks.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Callable

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner
from scanners.cloud_checks import aws as aws_checks
from scanners.cloud_checks import azure as azure_checks
from scanners.cloud_checks import gcp as gcp_checks

# Map of cloud provider -> (CLI executable, display name, check function names)
_CLOUD_PROVIDERS: dict[str, tuple[str, str, list[str]]] = {
    "aws": (
        "aws",
        "Amazon Web Services",
        [
            "check_s3_public_buckets",
            "check_iam_password_policy",
            "check_security_groups",
            "check_cloudtrail_status",
        ],
    ),
    "azure": (
        "az",
        "Microsoft Azure",
        [
            "check_nsg_rules",
            "check_storage_access",
            "check_activity_log",
        ],
    ),
    "gcp": (
        "gcloud",
        "Google Cloud Platform",
        [
            "check_iam_bindings",
            "check_firewall_rules",
            "check_audit_logging",
        ],
    ),
}

# Map provider to module for dynamic lookup
_PROVIDER_MODULES = {
    "aws": aws_checks,
    "azure": azure_checks,
    "gcp": gcp_checks,
}


class CloudScanner(BaseScanner):
    """Scans cloud environments for security misconfigurations via CLI tools."""

    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self._available_clis: dict[str, str] = {}

    @property
    def name(self) -> str:
        return "CloudScanner"

    @property
    def description(self) -> str:
        return "Cloud security posture checks for AWS, Azure, and GCP"

    @property
    def supported_platforms(self) -> list[str]:
        return ["all"]

    def _detect_cloud_clis(self) -> dict[str, str]:
        """Detect which cloud CLIs are installed and accessible.

        Returns a dict of provider_key -> cli_path for each available CLI.
        """
        available: dict[str, str] = {}

        for provider_key, (cli_executable, display_name, _checks) in _CLOUD_PROVIDERS.items():
            cli_path = shutil.which(cli_executable)
            if cli_path:
                # Verify CLI is actually runnable
                if self._verify_cli(cli_executable):
                    available[provider_key] = cli_path
                    self.log.debug(
                        f"  [{self.name}] Found {display_name} CLI: {cli_path}"
                    )

        return available

    def _verify_cli(self, cli_executable: str) -> bool:
        """Verify a CLI tool is runnable (returns version info)."""
        version_cmds: dict[str, list[str]] = {
            "aws": ["aws", "--version"],
            "az": ["az", "version"],
            "gcloud": ["gcloud", "version"],
        }
        cmd = version_cmds.get(cli_executable, [cli_executable, "--version"])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _run_provider_checks(
        self, provider_key: str
    ) -> list[Finding]:
        """Run all checks for a specific cloud provider."""
        findings: list[Finding] = []
        _cli_executable, display_name, check_fn_names = _CLOUD_PROVIDERS[provider_key]
        module = _PROVIDER_MODULES[provider_key]

        self.log.info(f"  [{self.name}] Running {display_name} security checks...")

        for fn_name in check_fn_names:
            check_fn = getattr(module, fn_name)
            try:
                check_findings = check_fn()
                findings.extend(check_findings)
            except Exception as exc:
                findings.append(Finding(
                    title=f"{display_name} check error: {fn_name}",
                    description=f"Error running {fn_name}: {exc}",
                    severity=Severity.INFO,
                    category="Cloud Security",
                    scanner=self.name,
                    evidence={"check": fn_name, "error": str(exc)},
                ))

        return findings

    def scan(self) -> list[Finding]:
        """Execute cloud security scans across all detected providers."""
        findings: list[Finding] = []

        # Step 1: Detect available cloud CLIs
        self._available_clis = self._detect_cloud_clis()

        # Step 2: If none found, return informational finding
        if not self._available_clis:
            findings.append(Finding(
                title="No cloud CLIs detected",
                description=(
                    "No cloud CLI tools (aws, az, gcloud) were found on this system. "
                    "Cloud security checks were skipped. Install a cloud CLI and "
                    "configure credentials to enable cloud posture scanning."
                ),
                severity=Severity.INFO,
                category="Cloud Security",
                scanner=self.name,
                evidence={"checked_clis": ["aws", "az", "gcloud"]},
            ))
            return findings

        # Step 3: Report detected providers
        provider_names = []
        for key in self._available_clis:
            _cli, display_name, _checks = _CLOUD_PROVIDERS[key]
            provider_names.append(display_name)

        findings.append(Finding(
            title=f"Cloud CLI(s) detected: {', '.join(provider_names)}",
            description=(
                f"Found {len(self._available_clis)} cloud CLI tool(s). "
                "Running security posture checks for each provider."
            ),
            severity=Severity.INFO,
            category="Cloud Security",
            scanner=self.name,
            evidence={
                "providers": list(self._available_clis.keys()),
                "cli_paths": self._available_clis,
            },
        ))

        # Step 4: Run checks for each available provider
        for provider_key in self._available_clis:
            provider_findings = self._run_provider_checks(provider_key)
            findings.extend(provider_findings)

        return findings

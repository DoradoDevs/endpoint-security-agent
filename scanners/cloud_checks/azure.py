"""
Sentinel Agent — Azure Cloud Security Checks

Checks Azure security posture via the `az` CLI:
- Network Security Group rules for overly permissive access
- Storage account public access settings
- Activity log / audit logging status

All checks use subprocess calls — no Azure SDK dependency required.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from core.config import Severity
from core.logging import get_logger
from core.telemetry import Finding

SCANNER_NAME = "CloudScanner"
CATEGORY = "Cloud Security"

log = get_logger()


def _run_az_cmd(args: list[str], timeout: int = 30) -> tuple[bool, Any]:
    """Run an Azure CLI command and return (success, parsed_json_or_error_str)."""
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            return False, stderr
        if not result.stdout.strip():
            return True, {}
        return True, json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except json.JSONDecodeError as exc:
        return False, f"Failed to parse JSON output: {exc}"
    except FileNotFoundError:
        return False, "az CLI not found"
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


def check_nsg_rules() -> list[Finding]:
    """Check Network Security Groups for overly permissive inbound rules."""
    findings: list[Finding] = []

    ok, data = _run_az_cmd(["network", "nsg", "list"])
    if not ok:
        findings.append(Finding(
            title="Azure NSG check could not complete",
            description=f"Unable to list Network Security Groups: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    if not isinstance(data, list):
        data = []

    permissive_rules: list[dict[str, Any]] = []
    for nsg in data:
        nsg_name = nsg.get("name", "")
        resource_group = nsg.get("resourceGroup", "")

        for rule in nsg.get("securityRules", []):
            if rule.get("direction", "").lower() != "inbound":
                continue
            if rule.get("access", "").lower() != "allow":
                continue

            source = rule.get("sourceAddressPrefix", "")
            if source in ("*", "0.0.0.0/0", "Internet", "Any"):
                dest_port = rule.get("destinationPortRange", "")
                permissive_rules.append({
                    "nsg": nsg_name,
                    "resource_group": resource_group,
                    "rule_name": rule.get("name", ""),
                    "source": source,
                    "destination_port": dest_port,
                    "protocol": rule.get("protocol", ""),
                })

    if permissive_rules:
        findings.append(Finding(
            title=f"{len(permissive_rules)} permissive NSG inbound rule(s) found",
            description=(
                "Network Security Group rules allowing inbound traffic from any source "
                "were detected. This may expose services to the internet."
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"permissive_rules": permissive_rules[:20]},
            remediation=(
                "Restrict NSG inbound rules to specific IP ranges or service tags. "
                "Avoid using '*' or '0.0.0.0/0' as source address prefix."
            ),
        ))
    else:
        findings.append(Finding(
            title="No permissive NSG inbound rules found",
            description=f"Checked {len(data)} NSG(s) — no unrestricted inbound rules detected.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"nsg_count": len(data)},
        ))

    return findings


def check_storage_access() -> list[Finding]:
    """Check Azure storage accounts for public access settings."""
    findings: list[Finding] = []

    ok, data = _run_az_cmd(["storage", "account", "list"])
    if not ok:
        findings.append(Finding(
            title="Azure storage account check could not complete",
            description=f"Unable to list storage accounts: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    if not isinstance(data, list):
        data = []

    if not data:
        findings.append(Finding(
            title="No Azure storage accounts found",
            description="This subscription has no storage accounts.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
        ))
        return findings

    public_accounts: list[dict[str, str]] = []
    for account in data:
        account_name = account.get("name", "")
        # allowBlobPublicAccess indicates whether public (anonymous) access to blobs is allowed
        allow_public = account.get("allowBlobPublicAccess", False)
        # Also check the network rule default action
        network_rules = account.get("networkRuleSet", {})
        default_action = network_rules.get("defaultAction", "Allow")

        if allow_public or default_action == "Allow":
            public_accounts.append({
                "name": account_name,
                "allow_blob_public_access": str(allow_public),
                "network_default_action": default_action,
            })

    if public_accounts:
        findings.append(Finding(
            title=f"{len(public_accounts)} storage account(s) allow public access",
            description=(
                "Storage accounts with public blob access or permissive network defaults: "
                + ", ".join(a["name"] for a in public_accounts[:10])
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"public_accounts": public_accounts[:20]},
            remediation=(
                "Disable public blob access on storage accounts and set network "
                "default action to 'Deny'. Use private endpoints or service endpoints."
            ),
        ))
    else:
        findings.append(Finding(
            title="All storage accounts restrict public access",
            description=f"Checked {len(data)} storage account(s) — all restrict public access.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"account_count": len(data)},
        ))

    return findings


def check_activity_log() -> list[Finding]:
    """Check Azure Monitor activity log for audit logging configuration."""
    findings: list[Finding] = []

    ok, data = _run_az_cmd([
        "monitor", "activity-log", "list",
        "--max-events", "5",
    ])
    if not ok:
        findings.append(Finding(
            title="Azure activity log check could not complete",
            description=f"Unable to query activity log: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    if not isinstance(data, list):
        data = []

    if not data:
        findings.append(Finding(
            title="No recent Azure activity log entries found",
            description=(
                "The activity log returned no recent entries. "
                "Ensure that diagnostic settings are configured to retain audit logs."
            ),
            severity=Severity.MEDIUM,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            remediation=(
                "Configure Azure Monitor diagnostic settings to send activity logs "
                "to a Log Analytics workspace or storage account for retention."
            ),
        ))
    else:
        findings.append(Finding(
            title="Azure activity log is recording events",
            description=f"Found {len(data)} recent activity log entries. Audit logging is active.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"recent_event_count": len(data)},
        ))

    return findings

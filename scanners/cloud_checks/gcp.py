"""
Sentinel Agent — GCP Cloud Security Checks

Checks GCP security posture via the `gcloud` CLI:
- IAM policy bindings for overly broad roles
- Firewall rules allowing unrestricted ingress (0.0.0.0/0)
- Audit logging sink configuration

All checks use subprocess calls — no Google Cloud SDK dependency required.
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

# Roles that grant excessively broad permissions
OVERLY_BROAD_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
}


def _run_gcloud_cmd(args: list[str], timeout: int = 30) -> tuple[bool, Any]:
    """Run a gcloud CLI command and return (success, parsed_json_or_error_str)."""
    cmd = ["gcloud"] + args + ["--format=json"]
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
        return False, "gcloud CLI not found"
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


def _get_current_project() -> str | None:
    """Get the currently configured GCP project ID."""
    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return None


def check_iam_bindings() -> list[Finding]:
    """Check IAM policy for overly broad role bindings."""
    findings: list[Finding] = []

    project = _get_current_project()
    if not project:
        findings.append(Finding(
            title="GCP IAM check skipped — no project configured",
            description="Could not determine the active GCP project.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
        ))
        return findings

    ok, data = _run_gcloud_cmd([
        "projects", "get-iam-policy", project,
    ])
    if not ok:
        findings.append(Finding(
            title="GCP IAM policy check could not complete",
            description=f"Unable to retrieve IAM policy: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    bindings = data.get("bindings", [])
    if isinstance(data, list):
        # Some gcloud versions return the bindings directly
        bindings = data

    broad_bindings: list[dict[str, Any]] = []
    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])
        if role in OVERLY_BROAD_ROLES:
            # Flag if allUsers or allAuthenticatedUsers is a member
            for member in members:
                if member in ("allUsers", "allAuthenticatedUsers"):
                    broad_bindings.append({
                        "role": role,
                        "member": member,
                    })
            # Also flag if too many individual users have broad roles
            if len(members) > 5:
                broad_bindings.append({
                    "role": role,
                    "member_count": len(members),
                    "note": "Many principals with broad role",
                })

    if broad_bindings:
        findings.append(Finding(
            title=f"{len(broad_bindings)} overly broad IAM binding(s) found",
            description=(
                "IAM bindings with overly permissive roles (e.g., roles/owner, roles/editor) "
                "were detected. These grant wide-ranging access to the project."
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"broad_bindings": broad_bindings[:20]},
            remediation=(
                "Replace broad roles with fine-grained roles following the principle of "
                "least privilege. Never grant roles/owner or roles/editor to allUsers."
            ),
        ))
    else:
        findings.append(Finding(
            title="GCP IAM bindings follow least privilege",
            description=f"Checked {len(bindings)} binding(s) — no overly broad roles detected.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"binding_count": len(bindings)},
        ))

    return findings


def check_firewall_rules() -> list[Finding]:
    """Check GCP firewall rules for unrestricted ingress (0.0.0.0/0)."""
    findings: list[Finding] = []

    ok, data = _run_gcloud_cmd(["compute", "firewall-rules", "list"])
    if not ok:
        findings.append(Finding(
            title="GCP firewall rules check could not complete",
            description=f"Unable to list firewall rules: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    if not isinstance(data, list):
        data = []

    open_rules: list[dict[str, Any]] = []
    for rule in data:
        if rule.get("direction", "").upper() != "INGRESS":
            continue
        if rule.get("disabled", False):
            continue

        source_ranges = rule.get("sourceRanges", [])
        if "0.0.0.0/0" in source_ranges:
            allowed = rule.get("allowed", [])
            ports_info: list[str] = []
            for allow_entry in allowed:
                protocol = allow_entry.get("IPProtocol", "")
                ports = allow_entry.get("ports", ["all"])
                ports_info.append(f"{protocol}/{','.join(str(p) for p in ports)}")

            open_rules.append({
                "name": rule.get("name", ""),
                "network": rule.get("network", ""),
                "allowed": ", ".join(ports_info),
                "priority": rule.get("priority", ""),
            })

    if open_rules:
        findings.append(Finding(
            title=f"{len(open_rules)} firewall rule(s) allow unrestricted ingress",
            description=(
                "GCP firewall rules allowing ingress from 0.0.0.0/0 were found. "
                "This exposes services to the entire internet."
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"open_rules": open_rules[:20]},
            remediation=(
                "Restrict firewall rules to specific source IP ranges. "
                "Use service accounts and tags to limit exposure."
            ),
        ))
    else:
        findings.append(Finding(
            title="No unrestricted GCP firewall ingress rules found",
            description=f"Checked {len(data)} firewall rule(s) — none allow 0.0.0.0/0 ingress.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"rule_count": len(data)},
        ))

    return findings


def check_audit_logging() -> list[Finding]:
    """Check that GCP logging sinks are configured for audit log export."""
    findings: list[Finding] = []

    ok, data = _run_gcloud_cmd(["logging", "sinks", "list"])
    if not ok:
        findings.append(Finding(
            title="GCP logging sinks check could not complete",
            description=f"Unable to list logging sinks: {data}",
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
            title="No GCP logging sinks configured",
            description=(
                "No logging sinks are configured in this project. "
                "Audit logs may not be exported to long-term storage."
            ),
            severity=Severity.MEDIUM,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            remediation=(
                "Configure a logging sink to export audit logs to Cloud Storage, "
                "BigQuery, or Pub/Sub for retention and analysis."
            ),
        ))
    else:
        sink_names = [s.get("name", "") for s in data]
        findings.append(Finding(
            title=f"{len(data)} GCP logging sink(s) configured",
            description=f"Logging sinks found: {', '.join(sink_names[:10])}.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"sinks": sink_names[:20]},
        ))

    return findings

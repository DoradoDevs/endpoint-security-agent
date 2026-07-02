"""
Sentinel Agent — AWS Cloud Security Checks

Checks AWS security posture via the `aws` CLI:
- S3 public bucket exposure
- IAM password policy compliance
- Security group ingress rules (0.0.0.0/0 exposure)
- CloudTrail audit logging status

All checks use subprocess calls — no AWS SDK dependency required.
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


def _run_aws_cmd(args: list[str], timeout: int = 30) -> tuple[bool, Any]:
    """Run an AWS CLI command and return (success, parsed_json_or_error_str)."""
    cmd = ["aws"] + args + ["--output", "json"]
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
        return False, "aws CLI not found"
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


def check_s3_public_buckets() -> list[Finding]:
    """Check for S3 buckets that lack public access blocks."""
    findings: list[Finding] = []

    ok, data = _run_aws_cmd(["s3api", "list-buckets"])
    if not ok:
        log.debug(f"AWS S3 check skipped: {data}")
        findings.append(Finding(
            title="AWS S3 bucket check could not complete",
            description=f"Unable to list S3 buckets: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    buckets = data.get("Buckets", [])
    if not buckets:
        findings.append(Finding(
            title="No S3 buckets found",
            description="This AWS account has no S3 buckets.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
        ))
        return findings

    public_buckets: list[str] = []
    for bucket in buckets:
        bucket_name = bucket.get("Name", "")
        ok_block, block_data = _run_aws_cmd([
            "s3api", "get-public-access-block",
            "--bucket", bucket_name,
        ])
        if not ok_block:
            # No public access block configured — potentially public
            public_buckets.append(bucket_name)
            continue

        config = block_data.get("PublicAccessBlockConfiguration", {})
        all_blocked = (
            config.get("BlockPublicAcls", False)
            and config.get("IgnorePublicAcls", False)
            and config.get("BlockPublicPolicy", False)
            and config.get("RestrictPublicBuckets", False)
        )
        if not all_blocked:
            public_buckets.append(bucket_name)

    if public_buckets:
        findings.append(Finding(
            title=f"{len(public_buckets)} S3 bucket(s) missing full public access block",
            description=(
                "The following S3 buckets do not have all four public access block "
                f"settings enabled: {', '.join(public_buckets[:10])}"
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"buckets": public_buckets[:20]},
            remediation=(
                "Enable all four public access block settings for each bucket: "
                "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
            ),
        ))
    else:
        findings.append(Finding(
            title="All S3 buckets have public access blocks enabled",
            description=f"Checked {len(buckets)} bucket(s) — all have public access blocked.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"bucket_count": len(buckets)},
        ))

    return findings


def check_iam_password_policy() -> list[Finding]:
    """Check the IAM account password policy for complexity requirements."""
    findings: list[Finding] = []

    ok, data = _run_aws_cmd(["iam", "get-account-password-policy"])
    if not ok:
        if "NoSuchEntity" in str(data):
            findings.append(Finding(
                title="No IAM password policy configured",
                description=(
                    "This AWS account does not have a custom IAM password policy. "
                    "The default policy has weak requirements."
                ),
                severity=Severity.HIGH,
                category=CATEGORY,
                scanner=SCANNER_NAME,
                remediation="Configure an IAM password policy with strong complexity requirements.",
            ))
        else:
            findings.append(Finding(
                title="IAM password policy check could not complete",
                description=f"Unable to retrieve IAM password policy: {data}",
                severity=Severity.INFO,
                category=CATEGORY,
                scanner=SCANNER_NAME,
                evidence={"error": str(data)},
            ))
        return findings

    policy = data.get("PasswordPolicy", {})
    issues: list[str] = []

    min_length = policy.get("MinimumPasswordLength", 0)
    if min_length < 14:
        issues.append(f"Minimum password length is {min_length} (should be >= 14)")

    if not policy.get("RequireSymbols", False):
        issues.append("Symbols not required")
    if not policy.get("RequireNumbers", False):
        issues.append("Numbers not required")
    if not policy.get("RequireUppercaseCharacters", False):
        issues.append("Uppercase characters not required")
    if not policy.get("RequireLowercaseCharacters", False):
        issues.append("Lowercase characters not required")
    if not policy.get("MaxPasswordAge", 0):
        issues.append("No password expiration configured")

    if issues:
        findings.append(Finding(
            title=f"IAM password policy has {len(issues)} weakness(es)",
            description="Weaknesses found: " + "; ".join(issues),
            severity=Severity.MEDIUM,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"policy": policy, "issues": issues},
            remediation="Strengthen the IAM password policy to meet CIS benchmark requirements.",
        ))
    else:
        findings.append(Finding(
            title="IAM password policy meets complexity requirements",
            description="The IAM password policy has strong complexity settings.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"policy": policy},
        ))

    return findings


def check_security_groups() -> list[Finding]:
    """Check EC2 security groups for overly permissive ingress rules (0.0.0.0/0)."""
    findings: list[Finding] = []

    ok, data = _run_aws_cmd(["ec2", "describe-security-groups"])
    if not ok:
        findings.append(Finding(
            title="Security group check could not complete",
            description=f"Unable to describe security groups: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    security_groups = data.get("SecurityGroups", [])
    open_groups: list[dict[str, Any]] = []

    for sg in security_groups:
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        for permission in sg.get("IpPermissions", []):
            for ip_range in permission.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    port_info = ""
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    protocol = permission.get("IpProtocol", "")
                    if protocol == "-1":
                        port_info = "all traffic"
                    elif from_port == to_port:
                        port_info = f"port {from_port}/{protocol}"
                    else:
                        port_info = f"ports {from_port}-{to_port}/{protocol}"

                    open_groups.append({
                        "group_id": sg_id,
                        "group_name": sg_name,
                        "port_info": port_info,
                    })
            for ip_range in permission.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    protocol = permission.get("IpProtocol", "")
                    if protocol == "-1":
                        port_info = "all traffic"
                    elif from_port == to_port:
                        port_info = f"port {from_port}/{protocol}"
                    else:
                        port_info = f"ports {from_port}-{to_port}/{protocol}"

                    open_groups.append({
                        "group_id": sg_id,
                        "group_name": sg_name,
                        "port_info": f"{port_info} (IPv6)",
                    })

    if open_groups:
        findings.append(Finding(
            title=f"{len(open_groups)} security group rule(s) allow unrestricted ingress",
            description=(
                "Security groups with ingress rules open to 0.0.0.0/0 or ::/0 were found. "
                "This exposes services to the entire internet."
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"open_rules": open_groups[:20]},
            remediation=(
                "Restrict security group ingress rules to specific IP ranges. "
                "Avoid using 0.0.0.0/0 unless absolutely necessary (e.g., public web servers on port 443)."
            ),
        ))
    else:
        findings.append(Finding(
            title="No unrestricted security group ingress rules found",
            description=f"Checked {len(security_groups)} security group(s) — none allow 0.0.0.0/0 ingress.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"group_count": len(security_groups)},
        ))

    return findings


def check_cloudtrail_status() -> list[Finding]:
    """Check that CloudTrail is enabled and logging."""
    findings: list[Finding] = []

    ok, data = _run_aws_cmd(["cloudtrail", "describe-trails"])
    if not ok:
        findings.append(Finding(
            title="CloudTrail check could not complete",
            description=f"Unable to describe CloudTrail trails: {data}",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"error": str(data)},
        ))
        return findings

    trails = data.get("trailList", [])
    if not trails:
        findings.append(Finding(
            title="No CloudTrail trails configured",
            description=(
                "This AWS account has no CloudTrail trails. "
                "API activity is not being audited."
            ),
            severity=Severity.CRITICAL,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            remediation="Enable CloudTrail with a multi-region trail to audit all API activity.",
        ))
        return findings

    inactive_trails: list[str] = []
    for trail in trails:
        trail_name = trail.get("Name", "")
        trail_arn = trail.get("TrailARN", "")

        status_ok, status_data = _run_aws_cmd([
            "cloudtrail", "get-trail-status",
            "--name", trail_arn or trail_name,
        ])
        if status_ok:
            is_logging = status_data.get("IsLogging", False)
            if not is_logging:
                inactive_trails.append(trail_name)
        else:
            inactive_trails.append(f"{trail_name} (status unavailable)")

    if inactive_trails:
        findings.append(Finding(
            title=f"{len(inactive_trails)} CloudTrail trail(s) not actively logging",
            description=(
                "The following trails are not recording API activity: "
                + ", ".join(inactive_trails)
            ),
            severity=Severity.HIGH,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"inactive_trails": inactive_trails},
            remediation="Enable logging on all CloudTrail trails.",
        ))
    else:
        findings.append(Finding(
            title="CloudTrail is active and logging",
            description=f"All {len(trails)} trail(s) are actively logging API activity.",
            severity=Severity.INFO,
            category=CATEGORY,
            scanner=SCANNER_NAME,
            evidence={"trail_count": len(trails)},
        ))

    return findings

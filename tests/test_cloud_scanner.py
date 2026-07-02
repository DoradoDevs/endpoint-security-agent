"""Tests for Cloud Security Scanner.

All subprocess calls are mocked — no real cloud CLIs are invoked.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch, call

import pytest

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.cloud_scanner import CloudScanner
from scanners.cloud_checks import aws as aws_checks
from scanners.cloud_checks import azure as azure_checks
from scanners.cloud_checks import gcp as gcp_checks


def _make_config() -> AgentConfig:
    return AgentConfig()


def _mock_subprocess_result(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Create a mock subprocess.CompletedProcess."""
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# ---------------------------------------------------------------------------
# CloudScanner properties
# ---------------------------------------------------------------------------


class TestCloudScannerProperties:
    def test_name(self):
        scanner = CloudScanner(_make_config())
        assert scanner.name == "CloudScanner"

    def test_description(self):
        scanner = CloudScanner(_make_config())
        assert "Cloud" in scanner.description
        assert "AWS" in scanner.description

    def test_supported_platforms(self):
        scanner = CloudScanner(_make_config())
        assert "all" in scanner.supported_platforms


# ---------------------------------------------------------------------------
# No CLIs detected
# ---------------------------------------------------------------------------


class TestNoCLIDetection:
    @patch("scanners.cloud_scanner.shutil.which", return_value=None)
    def test_no_clis_returns_info_finding(self, mock_which):
        scanner = CloudScanner(_make_config())
        findings = scanner.scan()

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "No cloud CLIs detected" in findings[0].title

    @patch("scanners.cloud_scanner.shutil.which", return_value=None)
    def test_no_clis_evidence_lists_checked(self, mock_which):
        scanner = CloudScanner(_make_config())
        findings = scanner.scan()

        assert "aws" in findings[0].evidence.get("checked_clis", [])
        assert "az" in findings[0].evidence.get("checked_clis", [])
        assert "gcloud" in findings[0].evidence.get("checked_clis", [])


# ---------------------------------------------------------------------------
# AWS Checks
# ---------------------------------------------------------------------------


class TestAWSChecks:
    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_s3_public_buckets_detected(self, mock_run):
        """Buckets without full public access block produce HIGH finding."""
        buckets_response = json.dumps({
            "Buckets": [
                {"Name": "my-public-bucket"},
                {"Name": "my-private-bucket"},
            ]
        })
        # get-public-access-block for first bucket fails (no block)
        public_block_fail = _mock_subprocess_result(
            stderr="NoSuchPublicAccessBlockConfiguration", returncode=1
        )
        # get-public-access-block for second bucket succeeds
        private_block_ok = _mock_subprocess_result(
            stdout=json.dumps({
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            })
        )
        mock_run.side_effect = [
            _mock_subprocess_result(stdout=buckets_response),  # list-buckets
            public_block_fail,   # first bucket
            private_block_ok,    # second bucket
        ]

        findings = aws_checks.check_s3_public_buckets()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "my-public-bucket" in high[0].description

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_s3_all_buckets_protected(self, mock_run):
        """All buckets with full block produce INFO finding."""
        buckets_response = json.dumps({
            "Buckets": [{"Name": "secure-bucket"}]
        })
        block_ok = _mock_subprocess_result(
            stdout=json.dumps({
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            })
        )
        mock_run.side_effect = [
            _mock_subprocess_result(stdout=buckets_response),
            block_ok,
        ]

        findings = aws_checks.check_s3_public_buckets()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_s3_cli_error_handled(self, mock_run):
        """CLI error during list-buckets is handled gracefully."""
        mock_run.return_value = _mock_subprocess_result(
            stderr="Unable to locate credentials", returncode=1
        )

        findings = aws_checks.check_s3_public_buckets()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "could not complete" in findings[0].title.lower()

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_iam_no_password_policy(self, mock_run):
        """No IAM password policy produces HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stderr="NoSuchEntity", returncode=1
        )

        findings = aws_checks.check_iam_password_policy()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "password policy" in high[0].title.lower()

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_iam_weak_password_policy(self, mock_run):
        """Weak password policy produces MEDIUM finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "PasswordPolicy": {
                    "MinimumPasswordLength": 6,
                    "RequireSymbols": False,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": False,
                    "RequireLowercaseCharacters": True,
                    "MaxPasswordAge": 0,
                }
            })
        )

        findings = aws_checks.check_iam_password_policy()
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1
        assert "weakness" in medium[0].title.lower()

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_iam_strong_password_policy(self, mock_run):
        """Strong password policy produces INFO finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "PasswordPolicy": {
                    "MinimumPasswordLength": 16,
                    "RequireSymbols": True,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                    "MaxPasswordAge": 90,
                }
            })
        )

        findings = aws_checks.check_iam_password_policy()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_security_groups_open_ingress(self, mock_run):
        """Security groups with 0.0.0.0/0 ingress produce HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "SecurityGroups": [{
                    "GroupId": "sg-123",
                    "GroupName": "wide-open",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                    }],
                }]
            })
        )

        findings = aws_checks.check_security_groups()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "unrestricted" in high[0].title.lower()

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_security_groups_ipv6_open_ingress(self, mock_run):
        """Security groups with ::/0 IPv6 ingress produce HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "SecurityGroups": [{
                    "GroupId": "sg-456",
                    "GroupName": "ipv6-open",
                    "IpPermissions": [{
                        "IpProtocol": "-1",
                        "IpRanges": [],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }],
                }]
            })
        )

        findings = aws_checks.check_security_groups()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_security_groups_restricted(self, mock_run):
        """Restricted security groups produce INFO finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "SecurityGroups": [{
                    "GroupId": "sg-789",
                    "GroupName": "locked-down",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        "Ipv6Ranges": [],
                    }],
                }]
            })
        )

        findings = aws_checks.check_security_groups()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_cloudtrail_no_trails(self, mock_run):
        """No CloudTrail trails produces CRITICAL finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({"trailList": []})
        )

        findings = aws_checks.check_cloudtrail_status()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert "No CloudTrail" in critical[0].title

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_cloudtrail_active(self, mock_run):
        """Active CloudTrail produces INFO finding."""
        mock_run.side_effect = [
            _mock_subprocess_result(
                stdout=json.dumps({
                    "trailList": [{
                        "Name": "main-trail",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main-trail",
                    }]
                })
            ),
            _mock_subprocess_result(
                stdout=json.dumps({"IsLogging": True})
            ),
        ]

        findings = aws_checks.check_cloudtrail_status()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_cloudtrail_inactive(self, mock_run):
        """Inactive CloudTrail produces HIGH finding."""
        mock_run.side_effect = [
            _mock_subprocess_result(
                stdout=json.dumps({
                    "trailList": [{
                        "Name": "dead-trail",
                        "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/dead-trail",
                    }]
                })
            ),
            _mock_subprocess_result(
                stdout=json.dumps({"IsLogging": False})
            ),
        ]

        findings = aws_checks.check_cloudtrail_status()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_timeout_handled(self, mock_run):
        """Subprocess timeout is handled gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="aws", timeout=30)

        findings = aws_checks.check_s3_public_buckets()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "could not complete" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# Azure Checks
# ---------------------------------------------------------------------------


class TestAzureChecks:
    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_nsg_permissive_rules_detected(self, mock_run):
        """NSG with * source produces HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "test-nsg",
                "resourceGroup": "rg-test",
                "securityRules": [{
                    "name": "allow-all",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "22",
                    "protocol": "Tcp",
                }],
            }])
        )

        findings = azure_checks.check_nsg_rules()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "permissive" in high[0].title.lower()

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_nsg_no_permissive_rules(self, mock_run):
        """NSG with restricted rules produces INFO."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "secure-nsg",
                "resourceGroup": "rg-prod",
                "securityRules": [{
                    "name": "allow-internal",
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/8",
                    "destinationPortRange": "443",
                    "protocol": "Tcp",
                }],
            }])
        )

        findings = azure_checks.check_nsg_rules()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_nsg_outbound_rules_ignored(self, mock_run):
        """Outbound rules are not flagged even with * source."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "test-nsg",
                "resourceGroup": "rg-test",
                "securityRules": [{
                    "name": "allow-outbound",
                    "direction": "Outbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "*",
                    "protocol": "*",
                }],
            }])
        )

        findings = azure_checks.check_nsg_rules()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_storage_public_access_detected(self, mock_run):
        """Storage accounts with public blob access produce HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "publicstore",
                "allowBlobPublicAccess": True,
                "networkRuleSet": {"defaultAction": "Allow"},
            }])
        )

        findings = azure_checks.check_storage_access()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "publicstore" in high[0].description

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_storage_all_restricted(self, mock_run):
        """Storage accounts with restricted access produce INFO."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "securestore",
                "allowBlobPublicAccess": False,
                "networkRuleSet": {"defaultAction": "Deny"},
            }])
        )

        findings = azure_checks.check_storage_access()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_storage_no_accounts(self, mock_run):
        """No storage accounts produces INFO."""
        mock_run.return_value = _mock_subprocess_result(stdout=json.dumps([]))

        findings = azure_checks.check_storage_access()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "No Azure storage accounts" in findings[0].title

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_activity_log_present(self, mock_run):
        """Activity log with entries produces INFO."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([
                {"eventTimestamp": "2025-01-01T00:00:00Z", "operationName": {"value": "test"}},
            ])
        )

        findings = azure_checks.check_activity_log()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_activity_log_empty(self, mock_run):
        """Empty activity log produces MEDIUM finding."""
        mock_run.return_value = _mock_subprocess_result(stdout=json.dumps([]))

        findings = azure_checks.check_activity_log()
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_cli_error_handled(self, mock_run):
        """Azure CLI errors are handled gracefully."""
        mock_run.return_value = _mock_subprocess_result(
            stderr="Please run 'az login'", returncode=1
        )

        findings = azure_checks.check_nsg_rules()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# GCP Checks
# ---------------------------------------------------------------------------


class TestGCPChecks:
    @patch("scanners.cloud_checks.gcp._get_current_project", return_value="test-project")
    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_iam_broad_bindings_detected(self, mock_run, mock_project):
        """IAM bindings with allUsers on broad role produce HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "bindings": [{
                    "role": "roles/editor",
                    "members": ["allUsers"],
                }]
            })
        )

        findings = gcp_checks.check_iam_bindings()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "broad" in high[0].title.lower()

    @patch("scanners.cloud_checks.gcp._get_current_project", return_value="test-project")
    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_iam_least_privilege(self, mock_run, mock_project):
        """IAM bindings with fine-grained roles produce INFO."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "bindings": [{
                    "role": "roles/storage.objectViewer",
                    "members": ["serviceAccount:app@test.iam.gserviceaccount.com"],
                }]
            })
        )

        findings = gcp_checks.check_iam_bindings()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.gcp._get_current_project", return_value=None)
    def test_iam_no_project_skipped(self, mock_project):
        """IAM check skipped when no project is configured."""
        findings = gcp_checks.check_iam_bindings()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "no project" in findings[0].title.lower()

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_firewall_open_ingress_detected(self, mock_run):
        """Firewall rules with 0.0.0.0/0 produce HIGH finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "allow-all-ssh",
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "network": "default",
                "priority": 1000,
            }])
        )

        findings = gcp_checks.check_firewall_rules()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert "unrestricted" in high[0].title.lower()

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_firewall_restricted_rules(self, mock_run):
        """Restricted firewall rules produce INFO."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "allow-internal",
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["10.0.0.0/8"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                "network": "default",
                "priority": 1000,
            }])
        )

        findings = gcp_checks.check_firewall_rules()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_firewall_disabled_rules_ignored(self, mock_run):
        """Disabled firewall rules are not flagged."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([{
                "name": "disabled-open-rule",
                "direction": "INGRESS",
                "disabled": True,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "network": "default",
                "priority": 1000,
            }])
        )

        findings = gcp_checks.check_firewall_rules()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_audit_logging_no_sinks(self, mock_run):
        """No logging sinks produce MEDIUM finding."""
        mock_run.return_value = _mock_subprocess_result(stdout=json.dumps([]))

        findings = gcp_checks.check_audit_logging()
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_audit_logging_sinks_present(self, mock_run):
        """Configured sinks produce INFO finding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps([
                {"name": "audit-sink", "destination": "storage.googleapis.com/audit-bucket"},
            ])
        )

        findings = gcp_checks.check_audit_logging()
        assert all(f.severity == Severity.INFO for f in findings)

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_cli_timeout_handled(self, mock_run):
        """Subprocess timeout is handled gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="gcloud", timeout=30)

        findings = gcp_checks.check_firewall_rules()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Integration: CloudScanner with mixed environments
# ---------------------------------------------------------------------------


class TestCloudScannerIntegration:
    @patch("scanners.cloud_scanner.CloudScanner._verify_cli")
    @patch("scanners.cloud_scanner.shutil.which")
    def test_aws_only_environment(self, mock_which, mock_verify):
        """Only AWS CLI available runs AWS checks only."""
        def which_side_effect(cmd):
            if cmd == "aws":
                return "/usr/bin/aws"
            return None

        mock_which.side_effect = which_side_effect
        mock_verify.return_value = True

        scanner = CloudScanner(_make_config())

        with patch.object(aws_checks, "check_s3_public_buckets", return_value=[]) as mock_s3, \
             patch.object(aws_checks, "check_iam_password_policy", return_value=[]) as mock_iam, \
             patch.object(aws_checks, "check_security_groups", return_value=[]) as mock_sg, \
             patch.object(aws_checks, "check_cloudtrail_status", return_value=[]) as mock_ct:

            findings = scanner.scan()

            mock_s3.assert_called_once()
            mock_iam.assert_called_once()
            mock_sg.assert_called_once()
            mock_ct.assert_called_once()

        # Should have the "CLIs detected" INFO finding
        detected = [f for f in findings if "detected" in f.title.lower()]
        assert len(detected) == 1
        assert "Amazon Web Services" in detected[0].title

    @patch("scanners.cloud_scanner.CloudScanner._verify_cli")
    @patch("scanners.cloud_scanner.shutil.which")
    def test_multi_cloud_environment(self, mock_which, mock_verify):
        """Multiple CLIs available runs checks for all providers."""
        def which_side_effect(cmd):
            mapping = {
                "aws": "/usr/bin/aws",
                "az": "/usr/bin/az",
                "gcloud": "/usr/bin/gcloud",
            }
            return mapping.get(cmd)

        mock_which.side_effect = which_side_effect
        mock_verify.return_value = True

        scanner = CloudScanner(_make_config())

        with patch.object(aws_checks, "check_s3_public_buckets", return_value=[]), \
             patch.object(aws_checks, "check_iam_password_policy", return_value=[]), \
             patch.object(aws_checks, "check_security_groups", return_value=[]), \
             patch.object(aws_checks, "check_cloudtrail_status", return_value=[]), \
             patch.object(azure_checks, "check_nsg_rules", return_value=[]), \
             patch.object(azure_checks, "check_storage_access", return_value=[]), \
             patch.object(azure_checks, "check_activity_log", return_value=[]), \
             patch.object(gcp_checks, "check_iam_bindings", return_value=[]), \
             patch.object(gcp_checks, "check_firewall_rules", return_value=[]), \
             patch.object(gcp_checks, "check_audit_logging", return_value=[]):

            findings = scanner.scan()

        detected = [f for f in findings if "detected" in f.title.lower()]
        assert len(detected) == 1
        providers = detected[0].evidence.get("providers", [])
        assert "aws" in providers
        assert "azure" in providers
        assert "gcp" in providers

    @patch("scanners.cloud_scanner.CloudScanner._verify_cli")
    @patch("scanners.cloud_scanner.shutil.which")
    def test_check_exception_handled(self, mock_which, mock_verify):
        """Exception in a check function produces error finding, other checks continue."""
        mock_which.side_effect = lambda cmd: "/usr/bin/aws" if cmd == "aws" else None
        mock_verify.return_value = True

        scanner = CloudScanner(_make_config())

        with patch.object(aws_checks, "check_s3_public_buckets", side_effect=RuntimeError("boom")), \
             patch.object(aws_checks, "check_iam_password_policy", return_value=[
                 Finding(
                     title="IAM OK",
                     description="Password policy is fine",
                     severity=Severity.INFO,
                     category="Cloud Security",
                     scanner="CloudScanner",
                 )
             ]), \
             patch.object(aws_checks, "check_security_groups", return_value=[]), \
             patch.object(aws_checks, "check_cloudtrail_status", return_value=[]):

            findings = scanner.scan()

        # Should have error finding for the failed check
        error_findings = [f for f in findings if "error" in f.title.lower() and "check_s3" in f.title]
        assert len(error_findings) == 1
        assert error_findings[0].severity == Severity.INFO
        assert "boom" in error_findings[0].description

        # Should still have the IAM OK finding
        iam_findings = [f for f in findings if "IAM OK" in f.title]
        assert len(iam_findings) == 1

    @patch("scanners.cloud_scanner.CloudScanner._verify_cli", return_value=False)
    @patch("scanners.cloud_scanner.shutil.which", return_value="/usr/bin/aws")
    def test_cli_verification_failure(self, mock_which, mock_verify):
        """CLI that exists but fails verification is not used."""
        scanner = CloudScanner(_make_config())
        findings = scanner.scan()

        assert len(findings) == 1
        assert "No cloud CLIs detected" in findings[0].title

    def test_run_method_catches_exceptions(self):
        """The BaseScanner.run() method handles scan-level exceptions."""
        scanner = CloudScanner(_make_config())

        with patch.object(scanner, "scan", side_effect=RuntimeError("total failure")):
            findings = scanner.run()

        # BaseScanner.run() catches exceptions and returns empty list (per base.py)
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# All findings use correct category and scanner name
# ---------------------------------------------------------------------------


class TestFindingConsistency:
    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_aws_findings_use_correct_category(self, mock_run):
        """All AWS findings use 'Cloud Security' category."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({"Buckets": []})
        )

        findings = aws_checks.check_s3_public_buckets()
        for f in findings:
            assert f.category == "Cloud Security"
            assert f.scanner == "CloudScanner"

    @patch("scanners.cloud_checks.azure.subprocess.run")
    def test_azure_findings_use_correct_category(self, mock_run):
        """All Azure findings use 'Cloud Security' category."""
        mock_run.return_value = _mock_subprocess_result(
            stderr="error", returncode=1
        )

        findings = azure_checks.check_nsg_rules()
        for f in findings:
            assert f.category == "Cloud Security"
            assert f.scanner == "CloudScanner"

    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_gcp_findings_use_correct_category(self, mock_run):
        """All GCP findings use 'Cloud Security' category."""
        mock_run.return_value = _mock_subprocess_result(stdout=json.dumps([]))

        findings = gcp_checks.check_firewall_rules()
        for f in findings:
            assert f.category == "Cloud Security"
            assert f.scanner == "CloudScanner"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_empty_json_response(self, mock_run):
        """Empty JSON response is handled gracefully."""
        mock_run.return_value = _mock_subprocess_result(stdout="")

        findings = aws_checks.check_s3_public_buckets()
        assert len(findings) >= 1

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_no_buckets_key(self, mock_run):
        """JSON response missing expected keys is handled."""
        mock_run.return_value = _mock_subprocess_result(stdout=json.dumps({}))

        findings = aws_checks.check_s3_public_buckets()
        # Should handle gracefully (empty Buckets list)
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) >= 1

    @patch("scanners.cloud_checks.aws.subprocess.run")
    def test_malformed_json(self, mock_run):
        """Malformed JSON output is handled gracefully."""
        mock_run.return_value = _mock_subprocess_result(stdout="not valid json{{{")

        findings = aws_checks.check_s3_public_buckets()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @patch("scanners.cloud_checks.gcp._get_current_project", return_value="test-project")
    @patch("scanners.cloud_checks.gcp.subprocess.run")
    def test_iam_many_members_on_broad_role(self, mock_run, mock_project):
        """Many members on a broad role flag the binding."""
        mock_run.return_value = _mock_subprocess_result(
            stdout=json.dumps({
                "bindings": [{
                    "role": "roles/owner",
                    "members": [
                        f"user:user{i}@example.com" for i in range(10)
                    ],
                }]
            })
        )

        findings = gcp_checks.check_iam_bindings()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

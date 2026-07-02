"""
CIS Critical Security Controls v8 — mapped to Sentinel scanner categories.

Each control maps to one or more scanner finding categories so the compliance
engine can determine pass/fail based on actual scan results.
"""

from __future__ import annotations

from compliance.models import ComplianceControl, ComplianceFramework


CIS_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        id="CIS-1",
        title="Inventory and Control of Enterprise Assets",
        description=(
            "Actively manage all enterprise assets connected to the network "
            "so that only authorized assets are given access."
        ),
        category="Asset Management",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Process Anomaly", "Network Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-2",
        title="Inventory and Control of Software Assets",
        description=(
            "Actively manage all software on the network so that only "
            "authorized software is installed and can execute."
        ),
        category="Software Management",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Patch Management", "Service Audit"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-3",
        title="Data Protection",
        description=(
            "Develop processes and technical controls to identify, classify, "
            "securely handle, retain, and dispose of data."
        ),
        category="Data Protection",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Credential Exposure", "File Integrity"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-4",
        title="Secure Configuration of Enterprise Assets and Software",
        description=(
            "Establish and maintain the secure configuration of enterprise "
            "assets and software."
        ),
        category="Configuration",
        framework=ComplianceFramework.CIS,
        mapped_categories=["System Configuration", "SSH Security", "Server Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-5",
        title="Account Management",
        description=(
            "Use processes and tools to assign and manage authorization to "
            "credentials for user accounts."
        ),
        category="Account Management",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Access Control", "Privilege Escalation"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-6",
        title="Access Control Management",
        description=(
            "Use processes and tools to create, assign, manage, and revoke "
            "access credentials and privileges for user, administrator, and "
            "service accounts."
        ),
        category="Access Control",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Access Control"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-7",
        title="Continuous Vulnerability Management",
        description=(
            "Develop a plan to continuously assess and track vulnerabilities "
            "on all enterprise assets."
        ),
        category="Vulnerability Management",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Known Vulnerabilities", "Network Vulnerability"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-8",
        title="Audit Log Management",
        description=(
            "Collect, alert, review, and retain audit logs of events that "
            "could help detect, understand, or recover from an attack."
        ),
        category="Logging",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Log Analysis"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-9",
        title="Email and Web Browser Protections",
        description=(
            "Improve protections and detections of threats from email and "
            "web vectors."
        ),
        category="Browser Security",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Browser Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-10",
        title="Malware Defenses",
        description=(
            "Prevent or control the installation, spread, and execution of "
            "malicious applications, code, or scripts."
        ),
        category="Malware Defense",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Malware Indicators", "Threat Intelligence"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-11",
        title="Data Recovery",
        description=(
            "Establish and maintain data recovery practices sufficient to "
            "restore in-scope enterprise assets to a pre-incident state."
        ),
        category="Data Recovery",
        framework=ComplianceFramework.CIS,
        mapped_categories=[],  # No scanner mapping — NOT_ASSESSED
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-13",
        title="Network Monitoring and Defense",
        description=(
            "Operate processes and tooling to establish and maintain "
            "comprehensive network monitoring and defense."
        ),
        category="Network Defense",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Network Security", "Network Vulnerability"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-14",
        title="Security Awareness and Skills Training",
        description=(
            "Establish and maintain a security awareness program to influence "
            "behavior among the workforce."
        ),
        category="Security Training",
        framework=ComplianceFramework.CIS,
        mapped_categories=[],  # No scanner mapping — NOT_ASSESSED
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CIS-16",
        title="Application Software Security",
        description=(
            "Manage the security life cycle of in-house developed, hosted, "
            "or acquired software to prevent, detect, and remediate "
            "security weaknesses."
        ),
        category="Application Security",
        framework=ComplianceFramework.CIS,
        mapped_categories=["Persistence", "Service Audit"],
        fail_severities=["critical", "high"],
    ),
]

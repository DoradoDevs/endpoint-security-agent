"""
NIST 800-53 Security and Privacy Controls — mapped to Sentinel scanner categories.

Selected controls from NIST SP 800-53 Rev 5 control families that align with
the findings produced by Sentinel security scanners.
"""

from __future__ import annotations

from compliance.models import ComplianceControl, ComplianceFramework


NIST_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        id="AC-2",
        title="Account Management",
        description=(
            "Manage system accounts including establishing, activating, "
            "modifying, reviewing, disabling, and removing accounts."
        ),
        category="Access Control",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Access Control", "Privilege Escalation"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="AC-6",
        title="Least Privilege",
        description=(
            "Employ the principle of least privilege, allowing only "
            "authorized accesses necessary to accomplish assigned tasks."
        ),
        category="Access Control",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Privilege Escalation", "Access Control"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="AU-2",
        title="Audit Events",
        description=(
            "Identify the types of events that the system is capable of "
            "logging in support of the audit function."
        ),
        category="Audit",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Log Analysis"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="AU-6",
        title="Audit Review, Analysis, and Reporting",
        description=(
            "Review and analyze system audit records for indications of "
            "inappropriate or unusual activity."
        ),
        category="Audit",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Log Analysis"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CM-6",
        title="Configuration Settings",
        description=(
            "Establish and document configuration settings for components "
            "employed within the system using the latest security configuration "
            "guidance."
        ),
        category="Configuration Management",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["System Configuration", "SSH Security", "Server Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CM-7",
        title="Least Functionality",
        description=(
            "Configure the system to provide only mission-essential "
            "capabilities and prohibit or restrict the use of non-essential "
            "functions, ports, protocols, and services."
        ),
        category="Configuration Management",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Service Audit", "Network Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="IA-5",
        title="Authenticator Management",
        description=(
            "Manage system authenticators by verifying the identity of "
            "individuals, groups, roles, services, or devices as a "
            "prerequisite to allowing access."
        ),
        category="Identification and Authentication",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Credential Exposure", "SSH Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="SC-7",
        title="Boundary Protection",
        description=(
            "Monitor and control communications at the external managed "
            "interfaces to the system and at key internal boundaries."
        ),
        category="System and Communications",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Network Security", "Network Vulnerability"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="SC-13",
        title="Cryptographic Protection",
        description=(
            "Determine the cryptographic uses and implement the types of "
            "cryptography required for each specified use."
        ),
        category="System and Communications",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["SSH Security", "Browser Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="SI-2",
        title="Flaw Remediation",
        description=(
            "Identify, report, and correct system flaws in a timely manner, "
            "including software and firmware updates."
        ),
        category="System and Information Integrity",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Known Vulnerabilities", "Patch Management"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="SI-3",
        title="Malicious Code Protection",
        description=(
            "Implement malicious code protection mechanisms at system entry "
            "and exit points to detect and eradicate malicious code."
        ),
        category="System and Information Integrity",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Malware Indicators", "Threat Intelligence"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="SI-4",
        title="System Monitoring",
        description=(
            "Monitor the system to detect attacks and indicators of potential "
            "attacks, unauthorized connections, and unauthorized use."
        ),
        category="System and Information Integrity",
        framework=ComplianceFramework.NIST_800_53,
        mapped_categories=["Process Anomaly", "Network Security", "Log Analysis"],
        fail_severities=["critical", "high"],
    ),
]

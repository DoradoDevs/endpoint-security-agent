"""
SOC 2 Trust Services Criteria — mapped to Sentinel scanner categories.

SOC 2 controls from the Common Criteria (CC) and Availability (A) categories
relevant to system-level security scanning.
"""

from __future__ import annotations

from compliance.models import ComplianceControl, ComplianceFramework


SOC2_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        id="CC6.1",
        title="Logical Access Security",
        description=(
            "The entity implements logical access security software, "
            "infrastructure, and architectures over protected information "
            "assets to protect them from security events."
        ),
        category="Logical and Physical Access",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Access Control", "SSH Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC6.3",
        title="Role-Based Access and Least Privilege",
        description=(
            "The entity authorizes, modifies, or removes access to data, "
            "software, functions, and other protected information assets "
            "based on roles and responsibilities."
        ),
        category="Logical and Physical Access",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Privilege Escalation", "Access Control"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC6.6",
        title="Security Against External Threats",
        description=(
            "The entity implements controls to prevent or detect and act "
            "upon the introduction of unauthorized or malicious software."
        ),
        category="Logical and Physical Access",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Malware Indicators", "Threat Intelligence", "Network Security"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC6.7",
        title="Data Integrity in Transmission and Movement",
        description=(
            "The entity restricts the transmission, movement, and removal "
            "of information to authorized internal and external users and "
            "processes."
        ),
        category="Logical and Physical Access",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["File Integrity", "Credential Exposure"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC7.1",
        title="Threat Detection and Monitoring",
        description=(
            "To meet its objectives, the entity uses detection and monitoring "
            "procedures to identify changes to configurations that result in "
            "the introduction of new vulnerabilities."
        ),
        category="System Operations",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Process Anomaly", "Log Analysis", "Network Vulnerability"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC7.2",
        title="Incident Monitoring and Response",
        description=(
            "The entity monitors system components and the operation of "
            "those components for anomalies that are indicative of malicious "
            "acts, natural disasters, and errors."
        ),
        category="System Operations",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Log Analysis", "Process Anomaly"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC8.1",
        title="Change Management",
        description=(
            "The entity authorizes, designs, develops, configures, documents, "
            "tests, approves, and implements changes to infrastructure and "
            "software."
        ),
        category="Change Management",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["System Configuration", "Patch Management", "Service Audit"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="A1.1",
        title="System Availability and Capacity",
        description=(
            "The entity maintains, monitors, and evaluates current processing "
            "capacity and use of system components to manage capacity demand "
            "and enable the implementation of additional capacity as needed."
        ),
        category="Availability",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Network Security", "Service Audit"],
        fail_severities=["critical", "high"],
    ),
    ComplianceControl(
        id="CC5.2",
        title="Risk Identification and Assessment",
        description=(
            "The entity identifies risks to the achievement of its objectives "
            "across the entity and analyzes risks as a basis for determining "
            "how the risks should be managed."
        ),
        category="Risk Assessment",
        framework=ComplianceFramework.SOC2,
        mapped_categories=["Known Vulnerabilities", "Network Vulnerability"],
        fail_severities=["critical", "high"],
    ),
]

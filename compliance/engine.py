"""
Sentinel Agent — Compliance Engine

Evaluates scan findings against compliance frameworks (CIS, NIST, SOC 2)
and produces per-control pass/fail results with compliance percentages.
"""

from __future__ import annotations

from core.telemetry import ScanResult
from compliance.models import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceResult,
    ControlResult,
    ControlStatus,
)


class ComplianceEngine:
    """Evaluates scan findings against compliance frameworks."""

    def evaluate(
        self,
        result: ScanResult,
        framework: ComplianceFramework,
    ) -> ComplianceResult:
        """Evaluate scan results against a single compliance framework.

        Args:
            result: Aggregated scan result containing findings.
            framework: The compliance framework to evaluate against.

        Returns:
            ComplianceResult with per-control pass/fail status.
        """
        controls = self._get_controls(framework)
        comp_result = ComplianceResult(framework=framework)

        for control in controls:
            control_result = self._evaluate_control(control, result)
            comp_result.controls.append(control_result)

        return comp_result

    def evaluate_all(self, result: ScanResult) -> list[ComplianceResult]:
        """Evaluate scan results against all supported frameworks.

        Args:
            result: Aggregated scan result containing findings.

        Returns:
            List of ComplianceResult, one per framework.
        """
        return [self.evaluate(result, fw) for fw in ComplianceFramework]

    def _get_controls(
        self,
        framework: ComplianceFramework,
    ) -> list[ComplianceControl]:
        """Import and return the controls list for a given framework."""
        if framework == ComplianceFramework.CIS:
            from compliance.frameworks.cis_benchmark import CIS_CONTROLS

            return CIS_CONTROLS
        elif framework == ComplianceFramework.NIST_800_53:
            from compliance.frameworks.nist_800_53 import NIST_CONTROLS

            return NIST_CONTROLS
        elif framework == ComplianceFramework.SOC2:
            from compliance.frameworks.soc2 import SOC2_CONTROLS

            return SOC2_CONTROLS
        else:
            return []

    def _evaluate_control(
        self,
        control: ComplianceControl,
        result: ScanResult,
    ) -> ControlResult:
        """Evaluate a single control against the scan findings.

        Logic:
            - If the control has no mapped_categories -> NOT_ASSESSED
            - If any finding in a mapped category has a severity in
              fail_severities -> FAIL
            - If any finding in a mapped category exists at a lower
              severity -> PARTIAL
            - No findings in mapped categories -> PASS
        """
        # Controls with no scanner mapping cannot be assessed
        if not control.mapped_categories:
            return ControlResult(
                control=control,
                status=ControlStatus.NOT_ASSESSED,
                notes="No scanner mapping for this control.",
            )

        # Collect findings that match any of the control's mapped categories
        matched_findings = [
            f for f in result.findings
            if f.category in control.mapped_categories
        ]

        if not matched_findings:
            return ControlResult(
                control=control,
                status=ControlStatus.PASS,
                notes="No findings in mapped categories.",
            )

        # Check if any findings have a fail-level severity
        fail_findings = [
            f for f in matched_findings
            if f.severity.value in control.fail_severities
        ]

        if fail_findings:
            return ControlResult(
                control=control,
                status=ControlStatus.FAIL,
                findings=matched_findings,
                notes=f"{len(fail_findings)} finding(s) at fail severity.",
            )

        # Findings exist but none at fail severity -> PARTIAL
        return ControlResult(
            control=control,
            status=ControlStatus.PARTIAL,
            findings=matched_findings,
            notes=f"{len(matched_findings)} finding(s) at lower severity.",
        )

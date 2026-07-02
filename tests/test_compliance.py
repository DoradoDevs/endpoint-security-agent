"""Tests for the Compliance Framework engine and models."""

from __future__ import annotations

from core.config import Severity
from core.telemetry import Finding, ScanResult
from compliance.models import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceResult,
    ControlResult,
    ControlStatus,
)
from compliance.engine import ComplianceEngine
from compliance.frameworks.cis_benchmark import CIS_CONTROLS
from compliance.frameworks.nist_800_53 import NIST_CONTROLS
from compliance.frameworks.soc2 import SOC2_CONTROLS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    title: str = "Test finding",
    severity: Severity = Severity.HIGH,
    category: str = "Network Security",
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        title=title,
        description="Test description",
        severity=severity,
        category=category,
        scanner="TestScanner",
        evidence=evidence or {},
    )


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        findings=findings or [],
        risk_score=0.0,
        risk_grade="A",
        scan_duration_seconds=1.0,
    )


# ---------------------------------------------------------------------------
# Framework definition tests
# ---------------------------------------------------------------------------

class TestCISControls:
    """CIS Benchmark control definitions."""

    def test_cis_controls_not_empty(self):
        assert len(CIS_CONTROLS) >= 12

    def test_cis_controls_are_compliance_controls(self):
        for ctrl in CIS_CONTROLS:
            assert isinstance(ctrl, ComplianceControl)

    def test_cis_controls_have_correct_framework(self):
        for ctrl in CIS_CONTROLS:
            assert ctrl.framework == ComplianceFramework.CIS

    def test_cis_control_ids_are_unique(self):
        ids = [c.id for c in CIS_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_cis_covers_expected_areas(self):
        ids = {c.id for c in CIS_CONTROLS}
        for expected_id in ["CIS-1", "CIS-4", "CIS-7", "CIS-10", "CIS-13"]:
            assert expected_id in ids, f"Missing CIS control {expected_id}"

    def test_cis_11_has_no_mapping(self):
        """CIS-11 Data Recovery should have no mapped categories."""
        cis11 = next(c for c in CIS_CONTROLS if c.id == "CIS-11")
        assert cis11.mapped_categories == []


class TestNISTControls:
    """NIST 800-53 control definitions."""

    def test_nist_controls_not_empty(self):
        assert len(NIST_CONTROLS) >= 10

    def test_nist_controls_have_correct_framework(self):
        for ctrl in NIST_CONTROLS:
            assert ctrl.framework == ComplianceFramework.NIST_800_53

    def test_nist_control_ids_are_valid(self):
        for ctrl in NIST_CONTROLS:
            # NIST IDs follow pattern: XX-N or XX-NN
            parts = ctrl.id.split("-")
            assert len(parts) == 2, f"Invalid NIST ID format: {ctrl.id}"
            assert parts[0].isalpha(), f"NIST family should be alpha: {ctrl.id}"
            assert parts[1].isdigit(), f"NIST number should be numeric: {ctrl.id}"

    def test_nist_control_ids_are_unique(self):
        ids = [c.id for c in NIST_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_nist_covers_key_families(self):
        families = {c.id.split("-")[0] for c in NIST_CONTROLS}
        for expected in ["AC", "AU", "CM", "SI", "SC", "IA"]:
            assert expected in families, f"Missing NIST family {expected}"


class TestSOC2Controls:
    """SOC 2 Trust Services Criteria definitions."""

    def test_soc2_controls_not_empty(self):
        assert len(SOC2_CONTROLS) >= 8

    def test_soc2_controls_have_correct_framework(self):
        for ctrl in SOC2_CONTROLS:
            assert ctrl.framework == ComplianceFramework.SOC2

    def test_soc2_control_ids_are_valid(self):
        for ctrl in SOC2_CONTROLS:
            # SOC 2 IDs follow pattern: CCN.N or AN.N
            assert "." in ctrl.id, f"SOC2 ID should contain a dot: {ctrl.id}"

    def test_soc2_control_ids_are_unique(self):
        ids = [c.id for c in SOC2_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_soc2_covers_key_criteria(self):
        ids = {c.id for c in SOC2_CONTROLS}
        for expected in ["CC6.1", "CC7.1", "CC8.1", "A1.1"]:
            assert expected in ids, f"Missing SOC 2 control {expected}"


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------

class TestComplianceEngine:
    """Tests for the ComplianceEngine evaluation logic."""

    def setup_method(self):
        self.engine = ComplianceEngine()

    def test_evaluate_empty_scan_result_cis(self):
        """Empty scan result should yield PASS or NOT_ASSESSED for all CIS controls."""
        result = _make_scan_result()
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        assert comp.framework == ComplianceFramework.CIS
        assert comp.total_controls == len(CIS_CONTROLS)
        for cr in comp.controls:
            assert cr.status in (ControlStatus.PASS, ControlStatus.NOT_ASSESSED)

    def test_evaluate_empty_scan_result_nist(self):
        """Empty scan result should yield PASS or NOT_ASSESSED for all NIST controls."""
        result = _make_scan_result()
        comp = self.engine.evaluate(result, ComplianceFramework.NIST_800_53)

        assert comp.framework == ComplianceFramework.NIST_800_53
        assert comp.total_controls == len(NIST_CONTROLS)
        for cr in comp.controls:
            assert cr.status in (ControlStatus.PASS, ControlStatus.NOT_ASSESSED)

    def test_evaluate_empty_scan_result_soc2(self):
        """Empty scan result should yield PASS or NOT_ASSESSED for all SOC2 controls."""
        result = _make_scan_result()
        comp = self.engine.evaluate(result, ComplianceFramework.SOC2)

        assert comp.framework == ComplianceFramework.SOC2
        assert comp.total_controls == len(SOC2_CONTROLS)
        for cr in comp.controls:
            assert cr.status in (ControlStatus.PASS, ControlStatus.NOT_ASSESSED)

    def test_engine_detects_fail_on_critical_finding(self):
        """A critical finding should cause mapped controls to FAIL."""
        finding = _make_finding(
            title="Open dangerous port",
            severity=Severity.CRITICAL,
            category="Network Security",
        )
        result = _make_scan_result([finding])
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        # CIS-1 maps to Network Security
        cis1 = next(cr for cr in comp.controls if cr.control.id == "CIS-1")
        assert cis1.status == ControlStatus.FAIL
        assert len(cis1.findings) == 1

    def test_engine_detects_fail_on_high_finding(self):
        """A high-severity finding should also cause FAIL (default fail_severities)."""
        finding = _make_finding(
            title="Weak SSH config",
            severity=Severity.HIGH,
            category="SSH Security",
        )
        result = _make_scan_result([finding])
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        # CIS-4 maps to SSH Security
        cis4 = next(cr for cr in comp.controls if cr.control.id == "CIS-4")
        assert cis4.status == ControlStatus.FAIL

    def test_engine_detects_partial_on_medium_finding(self):
        """A medium-severity finding should result in PARTIAL status."""
        finding = _make_finding(
            title="Minor config issue",
            severity=Severity.MEDIUM,
            category="System Configuration",
        )
        result = _make_scan_result([finding])
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        # CIS-4 maps to System Configuration
        cis4 = next(cr for cr in comp.controls if cr.control.id == "CIS-4")
        assert cis4.status == ControlStatus.PARTIAL
        assert len(cis4.findings) == 1

    def test_engine_detects_partial_on_low_finding(self):
        """A low-severity finding should result in PARTIAL status."""
        finding = _make_finding(
            title="Minor info",
            severity=Severity.LOW,
            category="Access Control",
        )
        result = _make_scan_result([finding])
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        # CIS-5 maps to Access Control
        cis5 = next(cr for cr in comp.controls if cr.control.id == "CIS-5")
        assert cis5.status == ControlStatus.PARTIAL

    def test_not_assessed_controls_dont_affect_percentage(self):
        """NOT_ASSESSED controls should be excluded from compliance percentage."""
        result = _make_scan_result()
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        # All assessed controls should PASS, NOT_ASSESSED should be excluded
        assert comp.compliance_percentage == 100.0

        # Verify at least one control is NOT_ASSESSED (CIS-11)
        not_assessed = [cr for cr in comp.controls if cr.status == ControlStatus.NOT_ASSESSED]
        assert len(not_assessed) >= 1

    def test_compliance_percentage_with_failures(self):
        """Compliance percentage should decrease with failures."""
        finding = _make_finding(
            severity=Severity.CRITICAL,
            category="Network Security",
        )
        result = _make_scan_result([finding])
        comp = self.engine.evaluate(result, ComplianceFramework.CIS)

        assert comp.failed > 0
        assert comp.compliance_percentage < 100.0

    def test_evaluate_all_returns_all_frameworks(self):
        """evaluate_all should return one result per framework."""
        result = _make_scan_result()
        all_results = self.engine.evaluate_all(result)

        assert len(all_results) == len(ComplianceFramework)
        frameworks_returned = {r.framework for r in all_results}
        assert frameworks_returned == set(ComplianceFramework)

    def test_evaluate_all_with_findings(self):
        """evaluate_all with findings should propagate failures across frameworks."""
        finding = _make_finding(
            severity=Severity.CRITICAL,
            category="Malware Indicators",
        )
        result = _make_scan_result([finding])
        all_results = self.engine.evaluate_all(result)

        # CIS-10, NIST SI-3, SOC2 CC6.6 all map to Malware Indicators
        for comp in all_results:
            failed_controls = [cr for cr in comp.controls if cr.status == ControlStatus.FAIL]
            assert len(failed_controls) >= 1, (
                f"{comp.framework.value} should have at least one failed control"
            )


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------

class TestComplianceSerialization:
    """Tests for to_dict serialization of compliance results."""

    def test_control_result_to_dict(self):
        control = ComplianceControl(
            id="TEST-1",
            title="Test Control",
            description="A test control",
            category="Testing",
            framework=ComplianceFramework.CIS,
            mapped_categories=["Network Security"],
        )
        cr = ControlResult(
            control=control,
            status=ControlStatus.PASS,
            notes="All clear.",
        )
        d = cr.to_dict()

        assert d["control_id"] == "TEST-1"
        assert d["title"] == "Test Control"
        assert d["category"] == "Testing"
        assert d["framework"] == "cis"
        assert d["status"] == "pass"
        assert d["finding_count"] == 0
        assert d["notes"] == "All clear."

    def test_compliance_result_to_dict(self):
        engine = ComplianceEngine()
        result = _make_scan_result()
        comp = engine.evaluate(result, ComplianceFramework.CIS)
        d = comp.to_dict()

        assert d["framework"] == "cis"
        assert d["total_controls"] == len(CIS_CONTROLS)
        assert d["passed"] >= 0
        assert d["failed"] == 0
        assert "compliance_percentage" in d
        assert isinstance(d["controls"], list)
        assert len(d["controls"]) == len(CIS_CONTROLS)

    def test_compliance_result_to_dict_with_failures(self):
        engine = ComplianceEngine()
        finding = _make_finding(severity=Severity.CRITICAL, category="Log Analysis")
        result = _make_scan_result([finding])
        comp = engine.evaluate(result, ComplianceFramework.CIS)
        d = comp.to_dict()

        assert d["failed"] > 0
        assert d["compliance_percentage"] < 100.0

        # Verify individual control dicts
        failed_controls = [c for c in d["controls"] if c["status"] == "fail"]
        assert len(failed_controls) > 0
        for fc in failed_controls:
            assert fc["finding_count"] > 0


# ---------------------------------------------------------------------------
# Model property tests
# ---------------------------------------------------------------------------

class TestComplianceResultProperties:
    """Tests for ComplianceResult computed properties."""

    def test_empty_result_properties(self):
        comp = ComplianceResult(framework=ComplianceFramework.CIS)
        assert comp.total_controls == 0
        assert comp.passed == 0
        assert comp.failed == 0
        assert comp.partial == 0
        assert comp.compliance_percentage == 100.0

    def test_all_pass_percentage(self):
        control = ComplianceControl(
            id="X-1", title="X", description="X",
            category="X", framework=ComplianceFramework.CIS,
            mapped_categories=["Test"],
        )
        comp = ComplianceResult(
            framework=ComplianceFramework.CIS,
            controls=[
                ControlResult(control=control, status=ControlStatus.PASS),
                ControlResult(control=control, status=ControlStatus.PASS),
            ],
        )
        assert comp.compliance_percentage == 100.0
        assert comp.passed == 2
        assert comp.failed == 0

    def test_mixed_status_percentage(self):
        control = ComplianceControl(
            id="X-1", title="X", description="X",
            category="X", framework=ComplianceFramework.CIS,
            mapped_categories=["Test"],
        )
        comp = ComplianceResult(
            framework=ComplianceFramework.CIS,
            controls=[
                ControlResult(control=control, status=ControlStatus.PASS),
                ControlResult(control=control, status=ControlStatus.FAIL),
                ControlResult(control=control, status=ControlStatus.NOT_ASSESSED),
            ],
        )
        # 1 pass out of 2 assessed = 50%
        assert comp.compliance_percentage == 50.0
        assert comp.passed == 1
        assert comp.failed == 1
        assert comp.partial == 0

    def test_partial_counts(self):
        control = ComplianceControl(
            id="X-1", title="X", description="X",
            category="X", framework=ComplianceFramework.CIS,
            mapped_categories=["Test"],
        )
        comp = ComplianceResult(
            framework=ComplianceFramework.CIS,
            controls=[
                ControlResult(control=control, status=ControlStatus.PARTIAL),
                ControlResult(control=control, status=ControlStatus.PARTIAL),
                ControlResult(control=control, status=ControlStatus.PASS),
            ],
        )
        assert comp.partial == 2
        assert comp.passed == 1
        # Only PASS counts for percentage: 1/3 = 33.3%
        assert comp.compliance_percentage == 33.3

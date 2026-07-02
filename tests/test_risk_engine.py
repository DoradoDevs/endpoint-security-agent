"""Tests for the risk scoring engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Severity
from core.telemetry import ScanResult, Finding
from reporting.risk_engine import RiskEngine


def _make_finding(severity: Severity, category: str = "Test") -> Finding:
    return Finding(
        title=f"Test {severity.value}",
        description="Test finding",
        severity=severity,
        category=category,
        scanner="test",
    )


def test_empty_scan_score_zero():
    engine = RiskEngine()
    result = ScanResult()
    score, grade = engine.calculate(result)
    assert score == 0.0
    assert grade == "A+"


def test_info_only_score_zero():
    engine = RiskEngine()
    result = ScanResult()
    result.add_finding(_make_finding(Severity.INFO))
    result.add_finding(_make_finding(Severity.INFO))
    score, grade = engine.calculate(result)
    assert score == 0.0
    assert grade == "A+"


def test_single_critical_high_score():
    engine = RiskEngine()
    result = ScanResult()
    result.add_finding(_make_finding(Severity.CRITICAL))
    score, grade = engine.calculate(result)
    assert score > 20
    assert grade in ("A", "B", "C")


def test_multiple_criticals_very_high():
    engine = RiskEngine()
    result = ScanResult()
    for _ in range(5):
        result.add_finding(_make_finding(Severity.CRITICAL, "Malware Indicators"))
    score, grade = engine.calculate(result)
    assert score > 50


def test_score_never_exceeds_100():
    engine = RiskEngine()
    result = ScanResult()
    for i in range(50):
        result.add_finding(_make_finding(Severity.CRITICAL, f"Cat{i}"))
    score, grade = engine.calculate(result)
    assert score <= 100.0


def test_grade_f_for_max_risk():
    engine = RiskEngine()
    result = ScanResult()
    for i in range(20):
        result.add_finding(_make_finding(Severity.CRITICAL, f"Cat{i}"))
    for i in range(20):
        result.add_finding(_make_finding(Severity.HIGH, f"HCat{i}"))
    score, grade = engine.calculate(result)
    assert grade == "F"


def test_low_findings_low_score():
    engine = RiskEngine()
    result = ScanResult()
    result.add_finding(_make_finding(Severity.LOW))
    score, grade = engine.calculate(result)
    assert score < 15
    assert grade == "A+"


def test_score_breakdown():
    engine = RiskEngine()
    result = ScanResult()
    result.add_finding(_make_finding(Severity.CRITICAL, "Network Security"))
    result.add_finding(_make_finding(Severity.HIGH, "SSH Security"))
    breakdown = engine.get_score_breakdown(result)
    assert len(breakdown) == 2
    categories = [b["category"] for b in breakdown]
    assert "Network Security" in categories
    assert "SSH Security" in categories


if __name__ == "__main__":
    test_empty_scan_score_zero()
    test_info_only_score_zero()
    test_single_critical_high_score()
    test_multiple_criticals_very_high()
    test_score_never_exceeds_100()
    test_grade_f_for_max_risk()
    test_low_findings_low_score()
    test_score_breakdown()
    print("All risk engine tests passed!")

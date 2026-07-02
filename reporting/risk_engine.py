"""
Sentinel Agent — Risk Scoring Engine

Calculates a composite risk score (0-100) based on scan findings.

Scoring methodology:
- Each finding contributes based on its severity weight
- Weighted by category (some categories are more impactful)
- Diminishing returns per category (many LOW findings don't equal one CRITICAL)
- Score is capped at 100

Grade scale:
  0-15:  A+ (Excellent)
  16-30: A  (Good)
  31-45: B  (Fair)
  46-60: C  (Needs Attention)
  61-75: D  (Poor)
  76-100: F (Critical)
"""

from __future__ import annotations

import math
from typing import Any

from core.config import Severity
from core.telemetry import ScanResult, Finding


# Category weights — some categories matter more than others
CATEGORY_WEIGHTS = {
    "Threat Intelligence": 2.2,
    "Malware Indicators": 2.0,
    "Network Vulnerability": 1.6,
    "Known Vulnerabilities": 1.8,
    "Credential Exposure": 1.7,
    "SSH Security": 1.5,
    "File Integrity": 1.5,
    "Privilege Escalation": 1.4,
    "Network Security": 1.3,
    "Persistence": 1.3,
    "Access Control": 1.2,
    "Log Analysis": 1.1,
    "Patch Management": 1.1,
    "System Configuration": 1.0,
    "Server Security": 1.0,
    "Service Audit": 1.0,
    "Device Security": 1.3,
    "USB Security": 1.2,
    "Bluetooth Security": 0.9,
    "Cloud Security": 1.5,
    "Behavioral Analysis": 2.0,
    "Browser Security": 0.9,
    "Process Anomaly": 0.8,
}

GRADE_THRESHOLDS = [
    (15, "A+", "Excellent"),
    (30, "A", "Good"),
    (45, "B", "Fair"),
    (60, "C", "Needs Attention"),
    (75, "D", "Poor"),
    (100, "F", "Critical"),
]


class RiskEngine:
    """Calculates weighted risk scores from scan findings."""

    def calculate(self, result: ScanResult) -> tuple[float, str]:
        """Calculate risk score and grade from scan results.

        Returns:
            Tuple of (score: 0-100, grade: str)
        """
        if not result.findings:
            return 0.0, "A+"

        # Group findings by category
        by_category: dict[str, list[Finding]] = {}
        for f in result.findings:
            if f.severity == Severity.INFO:
                continue  # INFO findings don't contribute to risk
            by_category.setdefault(f.category, []).append(f)

        total_score = 0.0

        for category, findings in by_category.items():
            cat_weight = CATEGORY_WEIGHTS.get(category, 1.0)
            cat_score = 0.0

            # Sort by severity (highest first)
            findings.sort(key=lambda f: f.severity.weight, reverse=True)

            for i, finding in enumerate(findings):
                # Diminishing returns: each additional finding in same category
                # contributes less (logarithmic decay)
                position_factor = 1.0 / (1.0 + math.log1p(i))
                finding_score = finding.severity.weight * position_factor
                cat_score += finding_score

            total_score += cat_score * cat_weight

        # Normalize to 0-100 scale
        # Calibration: A single CRITICAL finding should score ~25
        # Two CRITICAL + three HIGH should score ~65
        normalized = min(100.0, total_score * 2.5)
        score = round(normalized, 1)

        # Determine grade
        grade = "F"
        for threshold, g, _ in GRADE_THRESHOLDS:
            if score <= threshold:
                grade = g
                break

        return score, grade

    def get_grade_info(self, score: float) -> dict[str, str]:
        """Get grade details for a given score."""
        for threshold, grade, description in GRADE_THRESHOLDS:
            if score <= threshold:
                return {"grade": grade, "description": description, "threshold": str(threshold)}
        return {"grade": "F", "description": "Critical", "threshold": "100"}

    def get_score_breakdown(self, result: ScanResult) -> list[dict[str, Any]]:
        """Get detailed score breakdown by category."""
        breakdown: list[dict[str, Any]] = []

        by_category: dict[str, list[Finding]] = {}
        for f in result.findings:
            if f.severity == Severity.INFO:
                continue
            by_category.setdefault(f.category, []).append(f)

        for category, findings in sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True):
            cat_weight = CATEGORY_WEIGHTS.get(category, 1.0)
            sev_counts = {}
            for f in findings:
                sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

            breakdown.append({
                "category": category,
                "finding_count": len(findings),
                "weight": cat_weight,
                "severities": sev_counts,
                "top_finding": findings[0].title if findings else "",
            })

        return breakdown

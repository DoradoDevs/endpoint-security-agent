"""
Sentinel Agent — HTML Report Generator

Generates professional security assessment reports using Jinja2 templates.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from core.telemetry import ScanResult
from reporting.risk_engine import RiskEngine, GRADE_THRESHOLDS


class HTMLReportGenerator:
    """Generates rich HTML security reports."""

    def __init__(self):
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

    def generate(self, result: ScanResult, output_dir: Path) -> Path:
        template = self.env.get_template("report.html.j2")

        # Build template context
        findings_by_severity = {}
        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            matches = [f.to_dict() for f in result.findings if f.severity.value == sev]
            if matches:
                findings_by_severity[sev] = matches

        # Remediation checklist (only actionable findings)
        remediations = []
        for f in result.findings:
            if f.remediation and f.severity.value in ("critical", "high", "medium"):
                remediations.append({
                    "title": f.title,
                    "severity": f.severity.value,
                    "remediation": f.remediation,
                })

        # Categories
        categories = set(f.category for f in result.findings)

        # Grade class for CSS
        grade_class = "grade-excellent"
        grade_description = "Excellent security posture"
        for threshold, grade, desc in GRADE_THRESHOLDS:
            if result.risk_score <= threshold:
                grade_description = desc
                if grade in ("A+", "A"):
                    grade_class = "grade-good"
                elif grade == "B":
                    grade_class = "grade-fair"
                elif grade == "C":
                    grade_class = "grade-attention"
                elif grade == "D":
                    grade_class = "grade-poor"
                else:
                    grade_class = "grade-critical"
                break

        context = {
            "system_info": result.system_info.to_dict(),
            "risk_score": result.risk_score,
            "risk_grade": result.risk_grade,
            "grade_class": grade_class,
            "grade_description": grade_description,
            "total_findings": len(result.findings),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "info_count": result.info_count,
            "findings_by_severity": findings_by_severity,
            "remediations": remediations,
            "categories": categories,
            "scanners_run": result.scanners_run,
            "scan_duration": result.scan_duration_seconds,
            "errors": result.errors,
        }

        html = template.render(**context)

        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = output_dir / f"sentinel_report_{timestamp}.html"
        filepath.write_text(html, encoding="utf-8")

        return filepath

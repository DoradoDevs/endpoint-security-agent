"""
Sentinel Agent — TUI Dashboard State

Shared mutable state for the interactive terminal dashboard.
All panels read from and write to this central state object.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TUIState:
    """Shared mutable state for the TUI."""

    risk_score: float = 0.0
    risk_grade: str = "A+"
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: list = field(default_factory=list)
    scan_in_progress: bool = False
    scan_progress: str = ""
    scanners_run: list[str] = field(default_factory=list)
    active_panel: int = 0  # 0=overview, 1=findings, 2=scanners, 3=hardening
    panel_names: list[str] = field(
        default_factory=lambda: ["Overview", "Findings", "Scanners", "Actions"],
    )
    severity_filter: str = "all"  # all, critical, high, medium, low
    last_scan_time: str = ""
    status_message: str = "Ready"

    def update_from_result(self, result) -> None:
        """Update state from a ScanResult."""
        self.risk_score = result.risk_score
        self.risk_grade = result.risk_grade
        self.total_findings = len(result.findings)
        self.findings = list(result.findings)
        self.scanners_run = list(result.scanners_run)
        # Count by severity
        self.critical_count = result.critical_count
        self.high_count = result.high_count
        self.medium_count = result.medium_count
        self.low_count = result.low_count
        self.info_count = result.info_count

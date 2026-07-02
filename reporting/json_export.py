"""
Sentinel Agent — JSON Report Exporter

Generates machine-readable JSON reports for integration with
SIEM systems, dashboards, and automation pipelines.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from core.telemetry import ScanResult


class JSONExporter:
    """Exports scan results to structured JSON."""

    def export(self, result: ScanResult, output_dir: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sentinel_report_{timestamp}.json"
        filepath = output_dir / filename

        output_dir.mkdir(parents=True, exist_ok=True)

        report_data = {
            "report_metadata": {
                "product": "Sentinel Security Agent",
                "report_version": "1.0",
                "generated_at": datetime.now().isoformat(),
                "format": "json",
            },
            **result.to_dict(),
        }

        filepath.write_text(json.dumps(report_data, indent=2, default=str))
        return filepath

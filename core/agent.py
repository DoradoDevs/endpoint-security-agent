"""
Sentinel Agent — Main Agent Controller

Top-level orchestrator that ties together configuration, scheduling,
scanning, reporting, and remediation into a coherent execution pipeline.

SECURITY MODEL:
- All operations are transparent and logged
- No hidden persistence or stealth behavior
- Read-only scanning by default
- Remediation requires explicit opt-in
- Dry-run mode available for all operations
"""

from __future__ import annotations

from pathlib import Path

from core import __version__, __product__
from core.config import AgentConfig, AgentEdition
from core.logging import init_logging, get_logger
from core.scheduler import ScanScheduler
from core.telemetry import ScanResult


class SentinelAgent:
    """Primary agent controller — the entry point for all operations."""

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.logger = init_logging(self.config.log_dir)
        self.scheduler = ScanScheduler(self.config)
        self._scan_result: ScanResult | None = None

    @property
    def product_info(self) -> str:
        edition = "Server" if self.config.edition == AgentEdition.SERVER else "Desktop"
        return f"{__product__} v{__version__} ({edition} Edition)"

    def scan(self) -> ScanResult:
        """Execute a security scan and return results."""
        self.logger.info(f"Starting {self.product_info}")
        result = self.scheduler.run_scan()
        self._scan_result = result
        return result

    def generate_reports(self, result: ScanResult | None = None) -> list[Path]:
        """Generate HTML and JSON reports from scan results."""
        result = result or self._scan_result
        if result is None:
            raise RuntimeError("No scan results available. Run scan() first.")

        from reporting.html_report import HTMLReportGenerator
        from reporting.json_export import JSONExporter

        output_dir = self.config.report.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        generated: list[Path] = []

        if self.config.report.generate_json:
            exporter = JSONExporter()
            path = exporter.export(result, output_dir)
            generated.append(path)
            self.logger.info(f"JSON report: {path}")

        if self.config.report.generate_html:
            generator = HTMLReportGenerator()
            path = generator.generate(result, output_dir)
            generated.append(path)
            self.logger.info(f"HTML report: {path}")

        return generated

    def harden(self, result: ScanResult | None = None) -> dict:
        """Run safe hardening based on scan findings."""
        result = result or self._scan_result
        if result is None:
            raise RuntimeError("No scan results available. Run scan() first.")

        from remediation.hardening import HardeningEngine

        engine = HardeningEngine(self.config)
        return engine.apply(result)

    def respond(self, result: ScanResult | None = None) -> dict:
        """Execute automated threat responses based on scan findings and policy."""
        result = result or self._scan_result
        if result is None:
            raise RuntimeError("No scan results available. Run scan() first.")

        from response.engine import ThreatResponseEngine

        engine = ThreatResponseEngine(self.config)
        return engine.respond(result)

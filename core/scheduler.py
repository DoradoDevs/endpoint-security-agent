"""
Sentinel Agent — Scan Scheduler & Orchestrator

Coordinates scanner execution, collects results, and manages scan lifecycle.
All scanners are run transparently with full logging.
"""

from __future__ import annotations

import platform
import sys
import time
from typing import TYPE_CHECKING

import psutil

from core import __version__
from core.config import AgentConfig, ScanDepth, Severity, is_windows, is_macos, is_linux
from core.logging import get_logger
from core.telemetry import ScanResult, SystemInfo, Finding

if TYPE_CHECKING:
    from scanners.base import BaseScanner


class ScanScheduler:
    """Orchestrates scanner discovery, execution, and result aggregation."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()
        self.scanners: list[BaseScanner] = []

    def discover_scanners(self) -> list[BaseScanner]:
        """Load all applicable scanners for the current platform and config."""
        from scanners.process_scanner import ProcessScanner
        from scanners.startup_scanner import StartupScanner
        from scanners.network_scanner import NetworkScanner
        from scanners.package_scanner import PackageScanner
        from scanners.config_scanner import ConfigScanner

        scanners: list[BaseScanner] = []

        if self.config.scan.enable_process_scan:
            scanners.append(ProcessScanner(self.config))
        if self.config.scan.enable_startup_scan:
            scanners.append(StartupScanner(self.config))
        if self.config.scan.enable_network_scan:
            scanners.append(NetworkScanner(self.config))
        if self.config.scan.enable_package_scan:
            scanners.append(PackageScanner(self.config))
        if self.config.scan.enable_config_scan:
            scanners.append(ConfigScanner(self.config))

        # v2.0 scanners
        if self.config.scan.enable_file_integrity_scan:
            try:
                from scanners.file_integrity_scanner import FileIntegrityScanner
                scanners.append(FileIntegrityScanner(self.config))
            except ImportError:
                self.log.debug("FileIntegrityScanner not available")
        if self.config.scan.enable_browser_scan:
            try:
                from scanners.browser_scanner import BrowserScanner
                scanners.append(BrowserScanner(self.config))
            except ImportError:
                self.log.debug("BrowserScanner not available")
        if self.config.scan.enable_credential_scan:
            try:
                from scanners.credential_scanner import CredentialScanner
                scanners.append(CredentialScanner(self.config))
            except ImportError:
                self.log.debug("CredentialScanner not available")
        if self.config.scan.enable_log_analysis_scan:
            try:
                from scanners.log_analysis_scanner import LogAnalysisScanner
                scanners.append(LogAnalysisScanner(self.config))
            except ImportError:
                self.log.debug("LogAnalysisScanner not available")
        if self.config.scan.enable_privilege_scan:
            try:
                from scanners.privilege_scanner import PrivilegeScanner
                scanners.append(PrivilegeScanner(self.config))
            except ImportError:
                self.log.debug("PrivilegeScanner not available")
        if self.config.scan.enable_service_audit_scan:
            try:
                from scanners.service_audit_scanner import ServiceAuditScanner
                scanners.append(ServiceAuditScanner(self.config))
            except ImportError:
                self.log.debug("ServiceAuditScanner not available")

        # v3.0 scanners
        if getattr(self.config.scan, "enable_network_vuln_scan", False):
            try:
                from scanners.network_vuln_scanner import NetworkVulnScanner
                scanners.append(NetworkVulnScanner(self.config))
            except ImportError:
                self.log.debug("NetworkVulnScanner not available")

        if getattr(self.config.scan, "enable_device_scan", False):
            try:
                from scanners.device_scanner import DeviceScanner
                scanners.append(DeviceScanner(self.config))
            except ImportError:
                self.log.debug("DeviceScanner not available")

        if getattr(self.config.scan, "enable_cloud_scan", False):
            try:
                from scanners.cloud_scanner import CloudScanner
                scanners.append(CloudScanner(self.config))
            except ImportError:
                self.log.debug("CloudScanner not available")

        # v3.5 threat hunting scanners
        if getattr(self.config.scan, "enable_malware_scan", False):
            try:
                from scanners.malware_scanner import MalwareScanner
                scanners.append(MalwareScanner(self.config))
            except ImportError:
                self.log.debug("MalwareScanner not available")

        if getattr(self.config.scan, "enable_memory_scan", False):
            try:
                from scanners.memory_scanner import MemoryScanner
                scanners.append(MemoryScanner(self.config))
            except ImportError:
                self.log.debug("MemoryScanner not available")

        if getattr(self.config.scan, "enable_persistence_scan", False):
            try:
                from scanners.persistence_scanner import PersistenceScanner
                scanners.append(PersistenceScanner(self.config))
            except ImportError:
                self.log.debug("PersistenceScanner not available")

        if getattr(self.config.scan, "enable_heuristic_scan", False):
            try:
                from scanners.heuristic_scanner import HeuristicScanner
                scanners.append(HeuristicScanner(self.config))
            except ImportError:
                self.log.debug("HeuristicScanner not available")

        if getattr(self.config.scan, "enable_ioc_scan", False):
            try:
                from scanners.ioc_scanner import IOCScanner
                scanners.append(IOCScanner(self.config))
            except ImportError:
                self.log.debug("IOCScanner not available")

        if getattr(self.config.scan, "enable_yara_scan", False):
            try:
                from scanners.yara_scanner import YaraScanner
                scanners.append(YaraScanner(self.config))
            except ImportError:
                self.log.debug("YaraScanner not available")

        if getattr(self.config.scan, "enable_amsi_scan", False):
            try:
                from scanners.amsi_scanner import AMSIScanner
                scanners.append(AMSIScanner(self.config))
            except ImportError:
                self.log.debug("AMSIScanner not available")

        # Filter to platform-compatible scanners
        current_platform = platform.system().lower()
        compatible = []
        for s in scanners:
            if current_platform in s.supported_platforms or "all" in s.supported_platforms:
                compatible.append(s)
            else:
                self.log.debug(f"Skipping scanner {s.name} — not supported on {current_platform}")

        self.scanners = compatible
        self.log.info(f"Discovered {len(compatible)} scanners for {current_platform}")
        return compatible

    def collect_system_info(self) -> SystemInfo:
        """Gather baseline system information."""
        mem = psutil.virtual_memory()
        uname = platform.uname()

        info = SystemInfo(
            hostname=uname.node,
            os_name=uname.system,
            os_version=uname.release,
            os_build=uname.version,
            architecture=uname.machine,
            cpu_count=psutil.cpu_count(logical=True) or 0,
            total_memory_gb=round(mem.total / (1024**3), 2),
            python_version=sys.version.split()[0],
            agent_version=__version__,
            platform_details={
                "processor": uname.processor or platform.processor(),
                "platform_string": platform.platform(),
            },
        )

        self.log.info(f"System: {info.os_name} {info.os_version} ({info.architecture})")
        self.log.info(f"Host: {info.hostname} | CPUs: {info.cpu_count} | RAM: {info.total_memory_gb} GB")
        return info

    def run_scan(self) -> ScanResult:
        """Execute full scan pipeline and return aggregated results."""
        start_time = time.time()
        result = ScanResult()

        self.log.info("=" * 60)
        self.log.info("SENTINEL SECURITY SCAN — STARTING")
        self.log.info("=" * 60)

        # Phase 1: System info
        result.system_info = self.collect_system_info()

        # Phase 1.5: Refresh threat intelligence feeds (if enabled)
        if self.config.scan.enable_threat_intel:
            try:
                from threat_intel.ioc_database import IOCDatabase
                from threat_intel.feed_manager import FeedManager
                db = IOCDatabase()
                fm = FeedManager(db, self.config)
                refresh_results = fm.refresh_all()
                total_iocs = sum(refresh_results.values())
                if total_iocs > 0:
                    self.log.info(f"Threat intel refreshed: {total_iocs} new IOCs loaded")
                stats = db.get_stats()
                self.log.info(f"Threat intel DB: {stats['total']} total IOCs")
            except ImportError:
                self.log.debug("Threat intelligence module not available")
            except Exception as e:
                self.log.warning(f"Threat intel refresh failed: {e}")

        # Phase 2: Discover scanners
        self.discover_scanners()

        # Phase 3: Execute each scanner
        min_sev = self.config.scan.min_severity
        min_weight = Severity(min_sev).weight if min_sev != "info" else 0.0

        for scanner in self.scanners:
            self.log.info(f"Running scanner: {scanner.name}")
            try:
                findings = scanner.run()
                # Apply severity filter from profile
                if min_weight > 0:
                    findings = [f for f in findings if f.severity.weight >= min_weight]
                for finding in findings:
                    result.add_finding(finding)
                result.scanners_run.append(scanner.name)
                self.log.info(f"  {scanner.name}: {len(findings)} findings")
            except Exception as e:
                error_msg = f"Scanner {scanner.name} failed: {e}"
                self.log.error(error_msg)
                result.add_error(error_msg)

        # Phase 4: Risk scoring
        from reporting.risk_engine import RiskEngine
        risk_engine = RiskEngine()
        result.risk_score, result.risk_grade = risk_engine.calculate(result)

        result.scan_duration_seconds = round(time.time() - start_time, 2)

        self.log.info("=" * 60)
        self.log.info(f"SCAN COMPLETE — {len(result.findings)} findings | "
                      f"Risk: {result.risk_score}/100 ({result.risk_grade}) | "
                      f"Duration: {result.scan_duration_seconds}s")
        self.log.info("=" * 60)

        return result

"""
Sentinel Agent — Base Scanner Interface

All scanners inherit from this base class. Ensures consistent interface,
logging, and error handling across all scan modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.config import AgentConfig
from core.logging import get_logger
from core.telemetry import Finding


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """What this scanner checks."""
        ...

    @property
    def supported_platforms(self) -> list[str]:
        """Platforms this scanner supports. Override to restrict."""
        return ["all"]

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Execute the scan and return findings."""
        ...

    def run(self) -> list[Finding]:
        """Execute scan with error handling, logging, and allowlist filtering."""
        self.log.info(f"  [{self.name}] {self.description}")
        try:
            findings = self.scan()
            findings = self._filter_allowlisted(findings)
            for f in findings:
                from core.logging import log_finding
                log_finding(f.severity.value, f.category, f.title, f.description)
            return findings
        except Exception as e:
            self.log.error(f"  [{self.name}] Scanner error: {e}")
            return []

    def _filter_allowlisted(self, findings: list[Finding]) -> list[Finding]:
        """Remove findings that match allowlist entries."""
        if not getattr(self.config, "allowlist", None):
            return findings
        if not self.config.allowlist.enabled:
            return findings
        try:
            from core.allowlist import AllowlistManager
            mgr = AllowlistManager()
            filtered = []
            for f in findings:
                # Check hash exclusion
                sha256 = f.evidence.get("sha256", "")
                if sha256 and mgr.is_hash_allowed(sha256, self.name):
                    self.log.debug(f"  [{self.name}] Allowlisted (hash): {f.title}")
                    continue
                # Check path exclusion
                path = f.evidence.get("path") or f.evidence.get("filepath") or f.evidence.get("file", "")
                if path and mgr.is_path_excluded(str(path), self.name):
                    self.log.debug(f"  [{self.name}] Allowlisted (path): {f.title}")
                    continue
                # Check process exclusion
                proc = f.evidence.get("process_name") or f.evidence.get("name", "")
                if proc and mgr.is_process_excluded(proc, self.name):
                    self.log.debug(f"  [{self.name}] Allowlisted (process): {f.title}")
                    continue
                filtered.append(f)
            return filtered
        except ImportError:
            return findings

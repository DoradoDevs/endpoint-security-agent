"""
Sentinel Agent — YARA Rule Scanner

Scans files using YARA rules for malware detection. Supports:
- Loading .yar/.yara rule files from a configurable directory
- Compiling rules once and caching for performance
- Scanning files with compiled rules
- Converting YARA matches to Sentinel Finding objects
- Hash-based IOC matching against the threat intel database

SECURITY: This scanner is read-only. It never modifies, quarantines,
or deletes files. All findings are advisory.

DEPENDENCY: Requires the `yara-python` package (pip install yara-python).
Falls back gracefully if not installed — the scanner simply produces no
YARA-based findings and logs a debug message.
"""

from __future__ import annotations

import hashlib
import platform
from pathlib import Path
from typing import Any

from core.config import AgentConfig, Severity
from core.logging import get_logger
from core.telemetry import Finding
from scanners.base import BaseScanner

# Maximum bytes to read from a single file for YARA scanning
_MAX_READ_BYTES = 50 * 1024 * 1024  # 50 MB

# Maximum files to scan per directory
_MAX_FILES_PER_DIR = 500


def _default_rules_dir() -> Path:
    """Return the platform-specific directory for YARA rule files."""
    system = platform.system().lower()
    if system == "windows":
        return Path.home() / "AppData" / "Local" / "Sentinel" / "yara_rules"
    elif system == "darwin":
        return Path.home() / "Library" / "Application Support" / "Sentinel" / "yara_rules"
    return Path.home() / ".sentinel" / "yara_rules"


class YaraScanner(BaseScanner):
    """Scans files using YARA rules and IOC hash matching."""

    @property
    def name(self) -> str:
        return "YaraScanner"

    @property
    def description(self) -> str:
        return "Scans files using YARA rules and IOC hash matching"

    @property
    def supported_platforms(self) -> list[str]:
        return ["all"]

    def __init__(self, config: AgentConfig, ioc_db: Any = None):
        super().__init__(config)
        self.log = get_logger()
        self._ioc_db = ioc_db
        self._yara = self._load_yara()
        self._compiled_rules = None
        self._rules_dir = _default_rules_dir()
        self._rule_count = 0

    # ------------------------------------------------------------------
    # YARA library loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_yara():
        """Try to import the yara module. Returns None if not installed."""
        try:
            import yara
            return yara
        except ImportError:
            return None

    def _compile_rules(self) -> Any:
        """Compile all .yar/.yara files in the rules directory."""
        if self._compiled_rules is not None:
            return self._compiled_rules

        if self._yara is None:
            return None

        if not self._rules_dir.is_dir():
            self._rules_dir.mkdir(parents=True, exist_ok=True)
            self.log.info(
                f"[YaraScanner] Created rules directory: {self._rules_dir}. "
                f"Place .yar files here for YARA scanning."
            )
            return None

        # Collect rule files
        rule_files: dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for rule_path in self._rules_dir.glob(ext):
                try:
                    namespace = rule_path.stem
                    rule_files[namespace] = str(rule_path)
                except Exception:
                    continue

        if not rule_files:
            self.log.debug("[YaraScanner] No YARA rule files found")
            return None

        try:
            self._compiled_rules = self._yara.compile(filepaths=rule_files)
            self._rule_count = len(rule_files)
            self.log.info(f"[YaraScanner] Compiled {self._rule_count} YARA rule file(s)")
            return self._compiled_rules
        except self._yara.SyntaxError as exc:
            self.log.warning(f"[YaraScanner] YARA compilation error: {exc}")
            return None
        except Exception as exc:
            self.log.warning(f"[YaraScanner] YARA compilation failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Scan entry point
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        """Execute YARA and IOC hash scan on target directories."""
        findings: list[Finding] = []

        has_yara = self._compile_rules() is not None
        has_ioc = self._ioc_db is not None

        if not has_yara and not has_ioc:
            self.log.debug("[YaraScanner] No YARA rules or IOC DB available, skipping")
            return findings

        targets = self._get_scan_targets()

        for directory in targets:
            try:
                file_count = 0
                for entry in directory.iterdir():
                    if file_count >= _MAX_FILES_PER_DIR:
                        break
                    if not entry.is_file():
                        continue
                    file_count += 1
                    try:
                        findings.extend(self._scan_file(entry))
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            except (PermissionError, FileNotFoundError, OSError):
                continue

        return findings

    # ------------------------------------------------------------------
    # Per-file scanning
    # ------------------------------------------------------------------

    def _scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file with YARA rules and IOC hash check."""
        findings: list[Finding] = []

        try:
            file_size = filepath.stat().st_size
        except (OSError, PermissionError):
            return findings

        if file_size == 0 or file_size > _MAX_READ_BYTES:
            return findings

        # Read file content
        try:
            content = filepath.read_bytes()
        except (PermissionError, FileNotFoundError, OSError):
            return findings

        # YARA matching
        if self._compiled_rules is not None:
            findings.extend(self._match_yara(filepath, content))

        # IOC hash matching
        if self._ioc_db is not None:
            ioc_finding = self._match_ioc_hash(filepath, content)
            if ioc_finding:
                findings.append(ioc_finding)

        return findings

    def _match_yara(self, filepath: Path, content: bytes) -> list[Finding]:
        """Match file content against compiled YARA rules."""
        findings: list[Finding] = []

        try:
            matches = self._compiled_rules.match(data=content, timeout=30)
        except Exception as exc:
            self.log.debug(f"[YaraScanner] YARA match error for {filepath}: {exc}")
            return findings

        for match in matches:
            # Map YARA rule metadata to severity
            severity = self._yara_severity(match)
            tags = list(match.tags) if match.tags else []

            sha256 = hashlib.sha256(content).hexdigest()

            matched_strings: list[str] = []
            for offset, identifier, data in match.strings:
                matched_strings.append(f"{identifier}@0x{offset:x}")
                if len(matched_strings) >= 10:
                    break

            findings.append(Finding(
                title=f"YARA match: {match.rule}",
                description=(
                    f"File matched YARA rule '{match.rule}' "
                    f"(namespace: {match.namespace}). "
                    f"Tags: {', '.join(tags) if tags else 'none'}."
                ),
                severity=severity,
                category="Malware Indicators",
                scanner=self.name,
                evidence={
                    "path": str(filepath),
                    "sha256": sha256,
                    "yara_rule": match.rule,
                    "yara_namespace": match.namespace,
                    "yara_tags": tags,
                    "matched_strings": matched_strings,
                    "match_count": len(match.strings),
                },
                remediation=(
                    f"Investigate the file at {filepath}. YARA rule "
                    f"'{match.rule}' flagged this file as potentially malicious."
                ),
            ))

        return findings

    def _match_ioc_hash(self, filepath: Path, content: bytes) -> Finding | None:
        """Check file SHA-256 against IOC database."""
        sha256 = hashlib.sha256(content).hexdigest()
        match = self._ioc_db.lookup_hash(sha256)

        if match is None:
            return None

        return Finding(
            title=f"Known malware hash: {filepath.name}",
            description=(
                f"File SHA-256 ({sha256[:16]}...) matches a known-malicious "
                f"hash in the threat intelligence database."
            ),
            severity=Severity.CRITICAL,
            category="Malware Indicators",
            scanner=self.name,
            evidence={
                "path": str(filepath),
                "sha256": sha256,
                "ioc_match": True,
                "ioc_category": match.threat_category.value if hasattr(match, 'threat_category') else "unknown",
                "ioc_source": match.source if hasattr(match, 'source') else "",
            },
            remediation=(
                f"This file matches a known malware hash. Quarantine or "
                f"delete {filepath} immediately and check for lateral movement."
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_scan_targets(self) -> list[Path]:
        """Return list of directories to scan (reuses MalwareScanner targets)."""
        try:
            from scanners.malware_scanner import MalwareScanner
            ms = MalwareScanner(self.config)
            return ms._get_scan_targets()
        except ImportError:
            # Fallback: basic targets
            import tempfile
            targets: list[Path] = []
            try:
                tmp = Path(tempfile.gettempdir())
                if tmp.is_dir():
                    targets.append(tmp)
            except OSError:
                pass
            home = Path.home()
            for subdir in ("Downloads", "Desktop"):
                candidate = home / subdir
                if candidate.is_dir():
                    targets.append(candidate)
            return targets

    @staticmethod
    def _yara_severity(match) -> Severity:
        """Derive severity from YARA rule tags or metadata."""
        tags = {t.lower() for t in (match.tags or [])}

        if "critical" in tags or "apt" in tags or "ransomware" in tags:
            return Severity.CRITICAL
        if "high" in tags or "malware" in tags or "trojan" in tags:
            return Severity.HIGH
        if "medium" in tags or "suspicious" in tags:
            return Severity.MEDIUM
        if "low" in tags or "informational" in tags:
            return Severity.LOW

        # Check meta fields if available
        meta = getattr(match, 'meta', {}) or {}
        sev = meta.get("severity", "").lower()
        if sev in ("critical", "high", "medium", "low"):
            return Severity(sev)

        # Default: HIGH for any YARA match
        return Severity.HIGH

    def get_info(self) -> dict[str, Any]:
        """Return scanner info including YARA availability."""
        return {
            "yara_available": self._yara is not None,
            "rules_directory": str(self._rules_dir),
            "compiled_rules": self._rule_count,
            "ioc_db_available": self._ioc_db is not None,
        }

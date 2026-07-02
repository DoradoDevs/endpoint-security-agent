"""Tests for the IOC matcher."""

import tempfile
from pathlib import Path

from core.config import Severity
from core.telemetry import Finding
from threat_intel.ioc_database import IOCDatabase
from threat_intel.matcher import IOCMatcher
from threat_intel.models import IOCEntry, IOCType, ThreatCategory


class TestIOCMatcher:
    """Tests for IOCMatcher matching logic."""

    def _make_db_with_iocs(self, tmp_dir: str) -> IOCDatabase:
        db = IOCDatabase(cache_dir=Path(tmp_dir))
        db.add_entries([
            IOCEntry(
                value="1.2.3.4",
                ioc_type=IOCType.IP_ADDRESS,
                threat_category=ThreatCategory.C2_SERVER,
                source="test_feed",
                confidence=90,
                description="Known C2 server",
            ),
            IOCEntry(
                value="a" * 64,
                ioc_type=IOCType.FILE_HASH_SHA256,
                threat_category=ThreatCategory.MALWARE,
                source="test_feed",
                confidence=95,
                description="Known malware",
            ),
            IOCEntry(
                value="evil.com",
                ioc_type=IOCType.DOMAIN,
                threat_category=ThreatCategory.PHISHING,
                source="test_feed",
                confidence=80,
                description="Phishing domain",
            ),
        ])
        return db

    def test_match_ip_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            match = matcher.match_ip("1.2.3.4", "test connection", "NetworkScanner")
            assert match is not None
            assert match.ioc.value == "1.2.3.4"
            assert match.ioc.threat_category == ThreatCategory.C2_SERVER

    def test_match_ip_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            match = matcher.match_ip("9.9.9.9", "safe connection", "NetworkScanner")
            assert match is None

    def test_match_hash_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            match = matcher.match_hash("a" * 64, "file check", "FileIntegrityScanner")
            assert match is not None
            assert match.ioc.threat_category == ThreatCategory.MALWARE

    def test_match_domain_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            match = matcher.match_domain("evil.com", "DNS lookup", "NetworkScanner")
            assert match is not None
            assert match.ioc.threat_category == ThreatCategory.PHISHING

    def test_match_findings_extracts_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            findings = [
                Finding(
                    title="Suspicious connection",
                    description="Connection to known bad IP",
                    severity=Severity.HIGH,
                    category="Network Security",
                    scanner="NetworkScanner",
                    evidence={"remote_ip": "1.2.3.4", "port": 443},
                ),
                Finding(
                    title="Normal connection",
                    description="Safe",
                    severity=Severity.INFO,
                    category="Network Security",
                    scanner="NetworkScanner",
                    evidence={"remote_ip": "8.8.8.8"},
                ),
            ]
            matches = matcher.match_findings(findings)
            assert len(matches) == 1
            assert matches[0].ioc.value == "1.2.3.4"

    def test_match_findings_extracts_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            findings = [
                Finding(
                    title="File changed",
                    description="System file modified",
                    severity=Severity.HIGH,
                    category="File Integrity",
                    scanner="FileIntegrityScanner",
                    evidence={"sha256": "a" * 64, "path": "/etc/passwd"},
                ),
            ]
            matches = matcher.match_findings(findings)
            assert len(matches) == 1
            assert matches[0].ioc.threat_category == ThreatCategory.MALWARE

    def test_ioc_match_to_finding_high_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            match = matcher.match_ip("1.2.3.4", "connection", "NetworkScanner")
            finding = IOCMatcher.ioc_match_to_finding(match)
            assert finding.severity == Severity.CRITICAL  # confidence 90 >= 80
            assert finding.category == "Threat Intelligence"
            assert "c2_server" in finding.description

    def test_ioc_match_to_finding_low_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            db.add_entries([
                IOCEntry(
                    value="5.5.5.5",
                    ioc_type=IOCType.IP_ADDRESS,
                    threat_category=ThreatCategory.GENERIC,
                    source="test",
                    confidence=50,
                ),
            ])
            matcher = IOCMatcher(db)
            match = matcher.match_ip("5.5.5.5", "connection", "NetworkScanner")
            finding = IOCMatcher.ioc_match_to_finding(match)
            assert finding.severity == Severity.HIGH  # confidence 50 < 80

    def test_match_findings_extracts_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            findings = [
                Finding(
                    title="DNS query",
                    description="Suspicious domain resolution",
                    severity=Severity.MEDIUM,
                    category="Network Security",
                    scanner="NetworkScanner",
                    evidence={"domain": "evil.com"},
                ),
            ]
            matches = matcher.match_findings(findings)
            assert len(matches) == 1

    def test_finding_evidence_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db_with_iocs(tmp)
            matcher = IOCMatcher(db)
            match = matcher.match_ip("1.2.3.4", "context", "scanner")
            evidence = match.to_finding_evidence()
            assert evidence["ioc_value"] == "1.2.3.4"
            assert evidence["ioc_type"] == "ip_address"
            assert evidence["threat_category"] == "c2_server"
            assert evidence["source"] == "test_feed"
            assert evidence["confidence"] == 90

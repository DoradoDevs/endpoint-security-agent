"""
Tests for the EDR DNS Monitor.

Covers domain analysis, DGA detection, suspicious TLD detection,
query rate limiting, IOC matching, and safe domain filtering.
"""

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.dns_monitor import (
    DNSMonitor,
    DNSQuery,
    DGA_ENTROPY_THRESHOLD,
    SUSPICIOUS_TLDS,
    SAFE_DOMAINS,
)
from edr.event_types import EDREvent, EDREventType
from core.config import AgentConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_monitor(ioc_db=None) -> DNSMonitor:
    """Create a DNSMonitor with default config."""
    config = AgentConfig()
    return DNSMonitor(config, ioc_db=ioc_db)


def _collect_events(monitor: DNSMonitor, domain: str, **kwargs) -> list[EDREvent]:
    """Analyze a domain and collect generated events."""
    events: list[EDREvent] = []
    monitor._on_event = events.append
    query = DNSQuery(domain=domain, **kwargs)
    result = monitor._analyze_domain(domain, query, time.time())
    return result


# ---------------------------------------------------------------------------
# TestDGADetection
# ---------------------------------------------------------------------------

class TestDGADetection:
    """Tests for DGA and DNS tunneling detection."""

    def test_high_entropy_subdomain_flagged(self):
        """Long random subdomain should be flagged as DGA/tunneling."""
        monitor = _make_monitor()
        # Simulate a DGA domain with high-entropy subdomain
        events = _collect_events(monitor, "xk7q9mz3v8w2p4j6.evil.com")
        dga = [e for e in events if e.details.get("detection") == "dga_tunneling"]
        assert len(dga) == 1
        assert dga[0].severity == "high"

    def test_normal_subdomain_not_flagged(self):
        """Normal readable subdomains should not trigger DGA detection."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "mail.example.com")
        dga = [e for e in events if e.details.get("detection") == "dga_tunneling"]
        assert len(dga) == 0

    def test_short_subdomain_not_flagged(self):
        """Short subdomains should not be analyzed for entropy."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "abc.evil.com")
        dga = [e for e in events if e.details.get("detection") == "dga_tunneling"]
        assert len(dga) == 0

    def test_no_subdomain_not_flagged(self):
        """Domain without subdomain should not trigger DGA."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "example.com")
        dga = [e for e in events if e.details.get("detection") == "dga_tunneling"]
        assert len(dga) == 0


# ---------------------------------------------------------------------------
# TestSuspiciousTLD
# ---------------------------------------------------------------------------

class TestSuspiciousTLD:
    """Tests for suspicious TLD detection."""

    def test_suspicious_tld_flagged(self):
        """Domains with known-abused TLDs should be flagged."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "malware.tk")
        tld = [e for e in events if e.details.get("detection") == "suspicious_tld"]
        assert len(tld) == 1
        assert tld[0].severity == "medium"
        assert tld[0].details["suspicious_tld"] == ".tk"

    def test_normal_tld_not_flagged(self):
        """Normal TLDs (.com, .org, etc.) should not be flagged."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "example.org")
        tld = [e for e in events if e.details.get("detection") == "suspicious_tld"]
        assert len(tld) == 0

    def test_onion_domain_flagged(self):
        """.onion domains should be flagged."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "hidden.onion")
        tld = [e for e in events if e.details.get("detection") == "suspicious_tld"]
        assert len(tld) == 1


# ---------------------------------------------------------------------------
# TestIOCMatching
# ---------------------------------------------------------------------------

class TestIOCMatching:
    """Tests for IOC database domain matching."""

    def test_ioc_domain_match(self):
        """Known-bad domain should produce critical alert."""
        mock_db = MagicMock()
        mock_match = MagicMock()
        mock_match.threat_category.value = "c2"
        mock_match.source = "abuse_ch"
        mock_db.lookup_domain.return_value = mock_match
        mock_db.lookup_ip.return_value = None

        monitor = _make_monitor(ioc_db=mock_db)
        events = _collect_events(monitor, "evil-c2-server.com")

        ioc = [e for e in events if e.details.get("detection") == "ioc_domain_match"]
        assert len(ioc) == 1
        assert ioc[0].severity == "critical"
        assert ioc[0].details["ioc_category"] == "c2"

    def test_ioc_resolved_ip_match(self):
        """Domain resolving to a known-bad IP should produce critical alert."""
        mock_db = MagicMock()
        mock_db.lookup_domain.return_value = None
        mock_ip_match = MagicMock()
        mock_ip_match.threat_category.value = "malware"
        mock_db.lookup_ip.return_value = mock_ip_match

        monitor = _make_monitor(ioc_db=mock_db)
        events = _collect_events(
            monitor, "benign-looking.com",
            response_ips=["185.220.101.1"],
        )
        ioc = [e for e in events if e.details.get("detection") == "ioc_resolved_ip_match"]
        assert len(ioc) == 1

    def test_no_ioc_match(self):
        """Clean domain should not produce IOC alerts."""
        mock_db = MagicMock()
        mock_db.lookup_domain.return_value = None
        mock_db.lookup_ip.return_value = None

        monitor = _make_monitor(ioc_db=mock_db)
        events = _collect_events(monitor, "clean-domain.org")
        ioc = [e for e in events if e.details.get("ioc_match")]
        assert len(ioc) == 0


# ---------------------------------------------------------------------------
# TestSafeDomains
# ---------------------------------------------------------------------------

class TestSafeDomains:
    """Tests for safe domain filtering."""

    def test_safe_domain_skipped(self):
        """Known-safe domains should not produce any alerts."""
        monitor = _make_monitor()
        for domain in ["api.google.com", "update.microsoft.com", "cdn.github.com"]:
            events = _collect_events(monitor, domain)
            assert len(events) == 0, f"Expected no alerts for {domain}"

    def test_unsafe_domain_analyzed(self):
        """Non-safe domains should be analyzed normally."""
        monitor = _make_monitor()
        events = _collect_events(monitor, "totally-legit.tk")
        assert len(events) > 0  # Should flag suspicious TLD


# ---------------------------------------------------------------------------
# TestQueryRate
# ---------------------------------------------------------------------------

class TestQueryRate:
    """Tests for query rate anomaly detection."""

    def test_high_rate_flagged(self):
        """Exceeding query rate threshold should produce alert."""
        monitor = _make_monitor()
        now = time.time()

        # Simulate 60 queries to same domain in rapid succession
        for _ in range(60):
            monitor._check_query_rate("rapid.example.com", now)

        event = monitor._check_query_rate("rapid.example.com", now)
        assert event is not None
        assert event.details["detection"] == "high_query_rate"

    def test_normal_rate_not_flagged(self):
        """Normal query rate should not trigger."""
        monitor = _make_monitor()
        event = monitor._check_query_rate("normal.example.com", time.time())
        assert event is None


# ---------------------------------------------------------------------------
# TestLabelEntropy
# ---------------------------------------------------------------------------

class TestLabelEntropy:
    """Tests for the entropy calculation utility."""

    def test_high_entropy_random_string(self):
        """Random-looking strings should have high entropy."""
        entropy = DNSMonitor._label_entropy("xk7q9mz3v8w2p4j6n1")
        assert entropy > 3.5

    def test_low_entropy_repeated(self):
        """Repeated characters should have low entropy."""
        entropy = DNSMonitor._label_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_empty_string(self):
        """Empty string should return 0 entropy."""
        assert DNSMonitor._label_entropy("") == 0.0

    def test_moderate_entropy_word(self):
        """Normal English word should have moderate entropy."""
        entropy = DNSMonitor._label_entropy("newsletter")
        assert 2.0 < entropy < 4.0


# ---------------------------------------------------------------------------
# TestCSVParsing
# ---------------------------------------------------------------------------

class TestCSVParsing:
    """Tests for the CSV line parser."""

    def test_simple_csv(self):
        result = DNSMonitor._parse_csv_line("a,b,c")
        assert result == ["a", "b", "c"]

    def test_quoted_csv(self):
        result = DNSMonitor._parse_csv_line('"hello","world, here","test"')
        assert result == ["hello", "world, here", "test"]

    def test_empty_fields(self):
        result = DNSMonitor._parse_csv_line("a,,c")
        assert result == ["a", "", "c"]

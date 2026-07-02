"""Tests for threat intelligence feed adapters."""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from threat_intel.feeds.abuse_ch import FeodoTrackerFeed, URLhausFeed, MalwareBazaarHashFeed
from threat_intel.feeds.emergingthreats import EmergingThreatsFeed
from threat_intel.feeds.alienvault_otx import AlienVaultOTXFeed
from threat_intel.feed_manager import FeedManager
from threat_intel.ioc_database import IOCDatabase
from threat_intel.models import IOCType, ThreatCategory


class TestFeodoTrackerFeed:
    def test_parse_blocklist(self):
        feed = FeodoTrackerFeed()
        content = "# comment line\n# another comment\n1.2.3.4\n5.6.7.8\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 2
        assert entries[0].value == "1.2.3.4"
        assert entries[0].ioc_type == IOCType.IP_ADDRESS
        assert entries[0].threat_category == ThreatCategory.C2_SERVER
        assert entries[0].confidence == 90

    def test_skip_comments_and_blanks(self):
        feed = FeodoTrackerFeed()
        content = "# comment\n\n  \n# another\n10.0.0.1\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 1

    def test_empty_response(self):
        feed = FeodoTrackerFeed()
        with patch.object(feed, "_http_get", return_value=None):
            entries = feed.fetch()
        assert entries == []

    def test_invalid_ip_skipped(self):
        feed = FeodoTrackerFeed()
        content = "not-an-ip\n1.2.3.4\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 1


class TestURLhausFeed:
    def test_parse_urls(self):
        feed = URLhausFeed()
        content = "# URLhaus\nhttp://evil.com/payload.exe\nhttps://bad.net/malware\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 2
        assert entries[0].ioc_type == IOCType.URL
        assert entries[0].threat_category == ThreatCategory.MALWARE

    def test_skip_non_urls(self):
        feed = URLhausFeed()
        content = "# comment\nnot-a-url\nhttp://valid.com/path\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 1


class TestMalwareBazaarFeed:
    def test_parse_hashes(self):
        feed = MalwareBazaarHashFeed()
        h1 = "a" * 64
        h2 = "b" * 64
        content = f"# MalwareBazaar\n{h1}\n{h2}\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 2
        assert entries[0].ioc_type == IOCType.FILE_HASH_SHA256
        assert entries[0].confidence == 95

    def test_skip_invalid_hashes(self):
        feed = MalwareBazaarHashFeed()
        content = "# header\ntooshort\n" + "g" * 64 + "\n" + "a" * 64 + "\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 1


class TestEmergingThreatsFeed:
    def test_parse_ips(self):
        feed = EmergingThreatsFeed()
        content = "# ET\n192.168.1.100\n10.0.0.1\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 2
        assert entries[0].threat_category == ThreatCategory.GENERIC

    def test_skip_invalid_ips(self):
        feed = EmergingThreatsFeed()
        content = "999.999.999.999\n10.0.0.1\nnot-ip\n"
        with patch.object(feed, "_http_get", return_value=content):
            entries = feed.fetch()
        assert len(entries) == 1  # Only 10.0.0.1 is valid


class TestAlienVaultOTXFeed:
    def test_no_api_key_returns_empty(self):
        feed = AlienVaultOTXFeed(api_key="")
        entries = feed.fetch()
        assert entries == []

    def test_parse_pulse_indicators(self):
        feed = AlienVaultOTXFeed(api_key="test_key")
        response = {
            "results": [
                {
                    "name": "Test Pulse",
                    "tags": ["malware", "apt"],
                    "indicators": [
                        {"type": "IPv4", "indicator": "1.2.3.4"},
                        {"type": "domain", "indicator": "evil.com"},
                        {"type": "FileHash-SHA256", "indicator": "a" * 64},
                        {"type": "unknown_type", "indicator": "skip-me"},
                    ],
                }
            ]
        }
        import json
        with patch.object(feed, "_http_get_authenticated", return_value=json.dumps(response)):
            entries = feed.fetch()
        assert len(entries) == 3  # unknown_type skipped


class TestFeedManager:
    def test_discover_feeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            fm = FeedManager(db)
            assert len(fm.feeds) >= 4  # At least 4 built-in feeds

    def test_refresh_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            fm = FeedManager(db)
            # Mock all feeds to return test data
            for feed in fm.feeds:
                feed.fetch = MagicMock(return_value=[])
            results = fm.refresh_all(force=True)
            assert isinstance(results, dict)
            # All feeds should have been called
            for feed in fm.feeds:
                feed.fetch.assert_called_once()

    def test_list_feeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            fm = FeedManager(db)
            feeds = fm.list_feeds()
            assert len(feeds) >= 4
            assert all("name" in f for f in feeds)
            assert all("description" in f for f in feeds)

    def test_refresh_specific_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            fm = FeedManager(db)
            # Mock the specific feed
            for feed in fm.feeds:
                if feed.name == "abuse_ch_feodo":
                    feed.fetch = MagicMock(return_value=[])
            count = fm.refresh_feed("abuse_ch_feodo", force=True)
            assert count == 0  # No entries returned

    def test_refresh_nonexistent_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            fm = FeedManager(db)
            count = fm.refresh_feed("nonexistent_feed")
            assert count == 0

    def test_rate_limiting(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp))
            fm = FeedManager(db)
            fm._max_requests = 2
            fm._rate_window = 60
            # Simulate exceeding rate limit
            fm._request_times = [__import__("time").time()] * 2
            assert fm._check_rate_limit() is False

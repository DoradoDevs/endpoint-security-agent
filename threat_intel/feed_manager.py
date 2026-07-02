"""
Sentinel Agent — Feed Manager

Orchestrates threat intelligence feed registration, fetching, and updates.
Follows the NVDCache rate limiting pattern.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from core.logging import get_logger
from threat_intel.ioc_database import IOCDatabase

if TYPE_CHECKING:
    from core.config import AgentConfig
    from threat_intel.feeds.base_feed import BaseFeed


class FeedManager:
    """Manages threat intelligence feed lifecycle."""

    def __init__(self, db: IOCDatabase, config: AgentConfig | None = None):
        self.db = db
        self.config = config
        self.log = get_logger()
        self.feeds = self._discover_feeds()

        # Rate limiting (matching NVDCache pattern)
        self._request_times: list[float] = []
        self._max_requests = 10
        self._rate_window = 60  # seconds

    def _discover_feeds(self) -> list[BaseFeed]:
        """Load all available feed adapters."""
        feeds: list[BaseFeed] = []

        from threat_intel.feeds.abuse_ch import (
            FeodoTrackerFeed,
            URLhausFeed,
            MalwareBazaarHashFeed,
        )
        from threat_intel.feeds.emergingthreats import EmergingThreatsFeed

        feeds.extend([
            FeodoTrackerFeed(),
            URLhausFeed(),
            MalwareBazaarHashFeed(),
            EmergingThreatsFeed(),
        ])

        # Optional: AlienVault OTX (requires API key)
        otx_key = ""
        if self.config:
            otx_key = getattr(
                getattr(self.config, "threat_intel", None),
                "otx_api_key",
                "",
            )
        if otx_key:
            from threat_intel.feeds.alienvault_otx import AlienVaultOTXFeed
            feeds.append(AlienVaultOTXFeed(api_key=otx_key))

        return feeds

    def refresh_all(self, force: bool = False) -> dict[str, int]:
        """Refresh all feeds that need updating. Returns IOC counts per feed."""
        results: dict[str, int] = {}

        for feed in self.feeds:
            if not force and not self.db.needs_refresh(feed.name):
                self.log.debug(f"Feed '{feed.name}' is still fresh, skipping")
                continue

            if not self._check_rate_limit():
                self.log.debug("Feed refresh rate limited, stopping")
                break

            try:
                self._record_request()
                entries = feed.fetch()
                count = self.db.add_entries(entries)
                self.db.mark_refreshed(feed.name)
                results[feed.name] = count
                self.log.info(f"Feed '{feed.name}': {count} new IOCs (total fetched: {len(entries)})")
            except Exception as e:
                self.log.error(f"Feed '{feed.name}' failed: {e}")
                results[feed.name] = 0

        return results

    def refresh_feed(self, feed_name: str, force: bool = False) -> int:
        """Refresh a specific feed by name. Returns count of new IOCs."""
        for feed in self.feeds:
            if feed.name == feed_name:
                if not force and not self.db.needs_refresh(feed.name):
                    return 0
                try:
                    entries = feed.fetch()
                    count = self.db.add_entries(entries)
                    self.db.mark_refreshed(feed.name)
                    return count
                except Exception as e:
                    self.log.error(f"Feed '{feed_name}' failed: {e}")
                    return 0
        self.log.warning(f"Feed '{feed_name}' not found")
        return 0

    def list_feeds(self) -> list[dict[str, str]]:
        """Return summary info for all registered feeds."""
        return [
            {
                "name": feed.name,
                "description": feed.description,
                "update_interval_hours": str(feed.update_interval_hours),
                "needs_refresh": str(self.db.needs_refresh(feed.name)),
            }
            for feed in self.feeds
        ]

    def _check_rate_limit(self) -> bool:
        """Check if we can make another feed request."""
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < self._rate_window]
        return len(self._request_times) < self._max_requests

    def _record_request(self) -> None:
        """Record that a feed request was made."""
        self._request_times.append(time.time())

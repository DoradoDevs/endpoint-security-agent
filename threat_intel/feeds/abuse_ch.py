"""
Sentinel Agent — abuse.ch Feed Adapters

Integrates with abuse.ch threat intelligence services:
- Feodo Tracker: Botnet C2 IP blocklist
- URLhaus: Malware distribution URLs
- MalwareBazaar: Known malware file hashes
"""

from __future__ import annotations

from threat_intel.feeds.base_feed import BaseFeed
from threat_intel.models import IOCEntry, IOCType, ThreatCategory


class FeodoTrackerFeed(BaseFeed):
    """abuse.ch Feodo Tracker — botnet C2 IP addresses."""

    URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

    @property
    def name(self) -> str:
        return "abuse_ch_feodo"

    @property
    def description(self) -> str:
        return "Feodo Tracker recommended C2 IP blocklist"

    def fetch(self) -> list[IOCEntry]:
        content = self._http_get(self.URL)
        if not content:
            return []

        entries: list[IOCEntry] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Basic IP validation
            parts = line.split(".")
            if len(parts) != 4:
                continue
            entries.append(IOCEntry(
                value=line,
                ioc_type=IOCType.IP_ADDRESS,
                threat_category=ThreatCategory.C2_SERVER,
                source=self.name,
                confidence=90,
                description="Feodo Tracker recommended blocklist — botnet C2 server",
            ))

        self.log.info(f"Feodo Tracker: fetched {len(entries)} C2 IPs")
        return entries


class URLhausFeed(BaseFeed):
    """abuse.ch URLhaus — malware distribution URLs."""

    URL = "https://urlhaus.abuse.ch/downloads/text_recent/"

    @property
    def name(self) -> str:
        return "abuse_ch_urlhaus"

    @property
    def description(self) -> str:
        return "URLhaus recent malware distribution URLs"

    def fetch(self) -> list[IOCEntry]:
        content = self._http_get(self.URL)
        if not content:
            return []

        entries: list[IOCEntry] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("http"):
                continue
            entries.append(IOCEntry(
                value=line,
                ioc_type=IOCType.URL,
                threat_category=ThreatCategory.MALWARE,
                source=self.name,
                confidence=85,
                description="URLhaus — active malware distribution URL",
            ))

        self.log.info(f"URLhaus: fetched {len(entries)} malware URLs")
        return entries


class MalwareBazaarHashFeed(BaseFeed):
    """abuse.ch MalwareBazaar — recent malware SHA-256 hashes."""

    URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

    @property
    def name(self) -> str:
        return "abuse_ch_malwarebazaar"

    @property
    def description(self) -> str:
        return "MalwareBazaar recent malware SHA-256 hashes"

    def fetch(self) -> list[IOCEntry]:
        content = self._http_get(self.URL)
        if not content:
            return []

        entries: list[IOCEntry] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # SHA-256 hashes are 64 hex characters
            if len(line) == 64 and all(c in "0123456789abcdef" for c in line.lower()):
                entries.append(IOCEntry(
                    value=line.lower(),
                    ioc_type=IOCType.FILE_HASH_SHA256,
                    threat_category=ThreatCategory.MALWARE,
                    source=self.name,
                    confidence=95,
                    description="MalwareBazaar — confirmed malware sample hash",
                ))

        self.log.info(f"MalwareBazaar: fetched {len(entries)} malware hashes")
        return entries

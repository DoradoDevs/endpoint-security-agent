"""
Sentinel Agent — AlienVault OTX Feed

AlienVault Open Threat Exchange pulse feed.
Requires an API key (free registration at https://otx.alienvault.com/).
"""

from __future__ import annotations

import json

from threat_intel.feeds.base_feed import BaseFeed
from threat_intel.models import IOCEntry, IOCType, ThreatCategory


# Map OTX indicator types to our IOC types
_OTX_TYPE_MAP: dict[str, IOCType] = {
    "IPv4": IOCType.IP_ADDRESS,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "FileHash-SHA256": IOCType.FILE_HASH_SHA256,
    "FileHash-SHA1": IOCType.FILE_HASH_SHA1,
    "FileHash-MD5": IOCType.FILE_HASH_MD5,
    "email": IOCType.EMAIL,
}


class AlienVaultOTXFeed(BaseFeed):
    """AlienVault OTX pulse feed (requires API key)."""

    BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def __init__(self, api_key: str = "") -> None:
        super().__init__()
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "alienvault_otx"

    @property
    def description(self) -> str:
        return "AlienVault OTX subscribed pulse indicators"

    def fetch(self) -> list[IOCEntry]:
        if not self.api_key:
            self.log.debug("AlienVault OTX: no API key configured, skipping")
            return []

        url = f"{self.BASE_URL}?limit=50&modified_since=7d"
        content = self._http_get_authenticated(url)
        if not content:
            return []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            self.log.debug("AlienVault OTX: invalid JSON response")
            return []

        entries: list[IOCEntry] = []
        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "")
            for indicator in pulse.get("indicators", []):
                ioc_type = _OTX_TYPE_MAP.get(indicator.get("type", ""))
                if ioc_type is None:
                    continue

                entries.append(IOCEntry(
                    value=indicator.get("indicator", ""),
                    ioc_type=ioc_type,
                    threat_category=ThreatCategory.GENERIC,
                    source=self.name,
                    confidence=75,
                    description=f"OTX Pulse: {pulse_name}",
                    tags=pulse.get("tags", [])[:5],
                ))

        self.log.info(f"AlienVault OTX: fetched {len(entries)} indicators")
        return entries

    def _http_get_authenticated(self, url: str, timeout: int = 30) -> str | None:
        """HTTP GET with OTX API key header."""
        import urllib.request
        import urllib.error

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Sentinel-Agent/2.0")
            req.add_header("X-OTX-API-KEY", self.api_key)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as e:
            self.log.debug(f"AlienVault OTX request failed: {e}")
            return None

"""
Sentinel Agent — Emerging Threats Feed

Proofpoint/ET compromised IP list — known compromised hosts.
"""

from __future__ import annotations

from threat_intel.feeds.base_feed import BaseFeed
from threat_intel.models import IOCEntry, IOCType, ThreatCategory


class EmergingThreatsFeed(BaseFeed):
    """Proofpoint/Emerging Threats compromised IP list."""

    URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

    @property
    def name(self) -> str:
        return "emergingthreats_compromised"

    @property
    def description(self) -> str:
        return "Emerging Threats compromised IP blocklist"

    def fetch(self) -> list[IOCEntry]:
        content = self._http_get(self.URL)
        if not content:
            return []

        entries: list[IOCEntry] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(".")
            if len(parts) != 4:
                continue
            try:
                # Validate all parts are integers 0-255
                if not all(0 <= int(p) <= 255 for p in parts):
                    continue
            except ValueError:
                continue

            entries.append(IOCEntry(
                value=line,
                ioc_type=IOCType.IP_ADDRESS,
                threat_category=ThreatCategory.GENERIC,
                source=self.name,
                confidence=70,
                description="Emerging Threats — known compromised host",
            ))

        self.log.info(f"Emerging Threats: fetched {len(entries)} compromised IPs")
        return entries

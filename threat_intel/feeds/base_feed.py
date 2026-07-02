"""
Sentinel Agent — Base Threat Intelligence Feed

Abstract base class for all feed adapters.
"""

from __future__ import annotations

import urllib.request
import urllib.error
from abc import ABC, abstractmethod

from core.logging import get_logger
from threat_intel.models import IOCEntry


class BaseFeed(ABC):
    """Abstract base for threat intelligence feed adapters."""

    def __init__(self) -> None:
        self.log = get_logger()

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique feed identifier."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @property
    def update_interval_hours(self) -> int:
        """How often this feed should be refreshed."""
        return 6

    @abstractmethod
    def fetch(self) -> list[IOCEntry]:
        """Fetch IOCs from the feed source."""
        ...

    def _http_get(self, url: str, timeout: int = 30) -> str | None:
        """Helper for HTTP GET requests using stdlib."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Sentinel-Agent/2.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as e:
            self.log.debug(f"Feed HTTP request failed for {self.name}: {e}")
            return None

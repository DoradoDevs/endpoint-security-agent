"""
Sentinel Agent — Threat Intelligence Data Models

IOC types, threat categories, and match results for threat intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    FILE_NAME = "file_name"


class ThreatCategory(str, Enum):
    """Classification of the threat."""

    MALWARE = "malware"
    C2_SERVER = "c2_server"
    BOTNET = "botnet"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    EXPLOIT_KIT = "exploit_kit"
    CRYPTOMINER = "cryptominer"
    APT = "apt"
    GENERIC = "generic"


@dataclass
class IOCEntry:
    """A single Indicator of Compromise."""

    value: str
    ioc_type: IOCType
    threat_category: ThreatCategory
    source: str
    confidence: int = 75
    description: str = ""
    first_seen: str = ""
    last_seen: str = ""
    tags: list[str] = field(default_factory=list)
    reference_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "threat_category": self.threat_category.value,
            "source": self.source,
            "confidence": self.confidence,
            "description": self.description,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
            "reference_url": self.reference_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IOCEntry:
        return cls(
            value=data["value"],
            ioc_type=IOCType(data["ioc_type"]),
            threat_category=ThreatCategory(data["threat_category"]),
            source=data["source"],
            confidence=data.get("confidence", 75),
            description=data.get("description", ""),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            tags=data.get("tags", []),
            reference_url=data.get("reference_url", ""),
        )


@dataclass
class IOCMatch:
    """Result of matching a scan artifact against the IOC database."""

    ioc: IOCEntry
    matched_value: str
    matched_context: str
    scanner: str

    def to_finding_evidence(self) -> dict[str, Any]:
        return {
            "ioc_value": self.ioc.value,
            "ioc_type": self.ioc.ioc_type.value,
            "threat_category": self.ioc.threat_category.value,
            "source": self.ioc.source,
            "confidence": self.ioc.confidence,
            "matched_context": self.matched_context,
        }

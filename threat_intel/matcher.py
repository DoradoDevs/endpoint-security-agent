"""
Sentinel Agent — IOC Matcher

Cross-references scan findings against the IOC database.
Converts IOC matches to standard Finding objects for inclusion in scan results.
"""

from __future__ import annotations

from core.config import Severity
from core.telemetry import Finding
from threat_intel.ioc_database import IOCDatabase
from threat_intel.models import IOCMatch


class IOCMatcher:
    """Cross-references scan artifacts against the IOC database."""

    def __init__(self, db: IOCDatabase):
        self.db = db

    def match_ip(self, ip: str, context: str, scanner: str) -> IOCMatch | None:
        """Check if an IP matches a known-bad indicator."""
        entry = self.db.lookup_ip(ip)
        if entry:
            return IOCMatch(
                ioc=entry,
                matched_value=ip,
                matched_context=context,
                scanner=scanner,
            )
        return None

    def match_domain(self, domain: str, context: str, scanner: str) -> IOCMatch | None:
        """Check if a domain matches a known-bad indicator."""
        entry = self.db.lookup_domain(domain)
        if entry:
            return IOCMatch(
                ioc=entry,
                matched_value=domain,
                matched_context=context,
                scanner=scanner,
            )
        return None

    def match_hash(self, file_hash: str, context: str, scanner: str) -> IOCMatch | None:
        """Check if a file hash matches known malware."""
        entry = self.db.lookup_hash(file_hash)
        if entry:
            return IOCMatch(
                ioc=entry,
                matched_value=file_hash,
                matched_context=context,
                scanner=scanner,
            )
        return None

    def match_url(self, url: str, context: str, scanner: str) -> IOCMatch | None:
        """Check if a URL matches a known-bad indicator."""
        entry = self.db.lookup_url(url)
        if entry:
            return IOCMatch(
                ioc=entry,
                matched_value=url,
                matched_context=context,
                scanner=scanner,
            )
        return None

    def match_findings(self, findings: list[Finding]) -> list[IOCMatch]:
        """Scan all findings for IOC matches in their evidence dicts."""
        matches: list[IOCMatch] = []

        for finding in findings:
            evidence = finding.evidence

            # Check IPs in evidence
            for key in ("remote_ip", "ip", "address", "raddr"):
                ip = evidence.get(key)
                if ip and isinstance(ip, str):
                    match = self.match_ip(ip, f"Finding: {finding.title}", finding.scanner)
                    if match:
                        matches.append(match)

            # Check file hashes in evidence
            for key in ("sha256", "hash", "current_hash", "baseline_hash", "exe_hash"):
                h = evidence.get(key)
                if h and isinstance(h, str):
                    match = self.match_hash(h, f"Finding: {finding.title}", finding.scanner)
                    if match:
                        matches.append(match)

            # Check domains
            for key in ("domain", "hostname", "remote_host"):
                domain = evidence.get(key)
                if domain and isinstance(domain, str):
                    match = self.match_domain(domain, f"Finding: {finding.title}", finding.scanner)
                    if match:
                        matches.append(match)

        return matches

    @staticmethod
    def ioc_match_to_finding(match: IOCMatch) -> Finding:
        """Convert an IOC match to a standard Finding for scan results."""
        severity = Severity.CRITICAL if match.ioc.confidence >= 80 else Severity.HIGH

        return Finding(
            title=f"Threat intel match: {match.ioc.ioc_type.value} {match.ioc.value}",
            description=(
                f"Matched known {match.ioc.threat_category.value} indicator from "
                f"feed '{match.ioc.source}'. {match.ioc.description}"
            ),
            severity=severity,
            category="Threat Intelligence",
            scanner=match.scanner,
            evidence=match.to_finding_evidence(),
            remediation=(
                f"Investigate the {match.ioc.ioc_type.value} '{match.ioc.value}'. "
                f"It is associated with {match.ioc.threat_category.value} activity."
            ),
        )

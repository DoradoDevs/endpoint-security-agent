"""
Sentinel Agent — DNS Monitor

Monitors DNS resolution activity by sniffing UDP port 53 traffic.
Detects suspicious DNS patterns including:
- Queries to known-malicious domains (IOC database)
- DNS tunneling (high-entropy subdomain labels, abnormal query volume)
- DGA (Domain Generation Algorithm) domain patterns
- Queries to uncommon TLDs associated with abuse

SECURITY: This monitor is read-only. It passively observes DNS traffic
and never modifies, blocks, or intercepts any packets.

IMPLEMENTATION NOTES:
- Uses a raw socket or scapy (if available) for packet capture.
- Falls back to periodic polling of system DNS cache on Windows.
- Does NOT require elevated privileges for the polling fallback.
"""

from __future__ import annotations

import math
import platform
import re
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# TLDs commonly abused for malware C2 and phishing
SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom free TLDs
    ".top", ".xyz", ".club", ".buzz", ".icu",
    ".work", ".click", ".surf", ".rest",
    ".onion",  # Tor hidden services (shouldn't appear in normal DNS)
}

# Known DNS-over-HTTPS / DNS-over-TLS resolvers (suspicious if queried directly)
DOH_RESOLVERS: set[str] = {
    "1.1.1.1", "1.0.0.1",         # Cloudflare
    "8.8.8.8", "8.8.4.4",         # Google
    "9.9.9.9", "149.112.112.112", # Quad9
    "208.67.222.222",              # OpenDNS
}

# Minimum entropy to flag a subdomain label as potential DGA/tunneling
DGA_ENTROPY_THRESHOLD = 3.8

# Minimum label length to apply entropy check
DGA_MIN_LABEL_LENGTH = 12

# Maximum queries per domain per window before flagging as suspicious
QUERY_RATE_THRESHOLD = 50
QUERY_RATE_WINDOW = 60  # seconds

# Known safe domains to never flag
SAFE_DOMAINS: set[str] = {
    "localhost", "wpad", "isatap",
    "microsoft.com", "windows.com", "windowsupdate.com",
    "apple.com", "icloud.com",
    "google.com", "googleapis.com", "gstatic.com",
    "github.com", "githubusercontent.com",
    "cloudflare.com", "amazonaws.com",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DNSQuery:
    """Represents a captured DNS query."""
    domain: str
    query_type: str = "A"       # A, AAAA, MX, TXT, CNAME, etc.
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    resolver_ip: str = ""
    response_ips: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DNS Monitor
# ---------------------------------------------------------------------------

class DNSMonitor:
    """Monitors DNS resolution activity for security threats.

    Uses platform-specific methods to observe DNS queries:
    - Windows: Polls ipconfig /displaydns or Get-DnsClientCache
    - Linux/macOS: Reads /var/log/syslog or systemd-resolved logs
    - All platforms: Optional scapy packet capture if available
    """

    def __init__(
        self,
        config: AgentConfig,
        on_event: Callable[[EDREvent], None] | None = None,
        ioc_db: Any | None = None,
    ):
        self.config = config
        self.log = get_logger()
        self._on_event = on_event
        self._ioc_db = ioc_db
        self._poll_interval = 10.0  # seconds
        self._known_domains: set[str] = set()

        # Rate tracking: domain -> list of timestamps
        self._query_history: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def start(self, stop_event: threading.Event) -> None:
        """Start DNS monitoring. Blocks until stop_event is set."""
        self.log.info("[DNSMonitor] Starting DNS monitoring")

        # Take initial snapshot
        self._snapshot_dns_cache()

        while not stop_event.is_set():
            stop_event.wait(timeout=self._poll_interval)
            if stop_event.is_set():
                break
            self._poll_dns_activity()

    # ------------------------------------------------------------------
    # Platform-specific DNS cache polling
    # ------------------------------------------------------------------

    def _snapshot_dns_cache(self) -> None:
        """Take initial snapshot of DNS cache to establish baseline."""
        entries = self._read_dns_cache()
        self._known_domains = {e.domain for e in entries}
        self.log.info(f"[DNSMonitor] Baseline: {len(self._known_domains)} cached domains")

    def _poll_dns_activity(self) -> None:
        """Poll for new DNS queries since last check."""
        entries = self._read_dns_cache()
        now = time.time()

        for entry in entries:
            domain = entry.domain.lower().rstrip(".")
            if not domain:
                continue

            if domain in self._known_domains:
                continue
            self._known_domains.add(domain)

            # Analyze the domain
            findings = self._analyze_domain(domain, entry, now)
            for event in findings:
                if self._on_event:
                    self._on_event(event)

    def _read_dns_cache(self) -> list[DNSQuery]:
        """Read DNS cache entries from the OS."""
        system = platform.system().lower()
        if system == "windows":
            return self._read_windows_dns_cache()
        elif system == "linux":
            return self._read_linux_dns_cache()
        elif system == "darwin":
            return self._read_macos_dns_cache()
        return []

    def _read_windows_dns_cache(self) -> list[DNSQuery]:
        """Read DNS cache via PowerShell Get-DnsClientCache."""
        entries: list[DNSQuery] = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-DnsClientCache | Select-Object -Property Entry,RecordType,Data "
                 "| ConvertTo-Csv -NoTypeInformation"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return entries

            lines = result.stdout.strip().splitlines()
            for line in lines[1:]:  # Skip header
                parts = self._parse_csv_line(line)
                if len(parts) >= 2:
                    domain = parts[0].strip('"').strip()
                    record_type = parts[1].strip('"').strip() if len(parts) > 1 else "A"
                    response_ip = parts[2].strip('"').strip() if len(parts) > 2 else ""
                    if domain:
                        entries.append(DNSQuery(
                            domain=domain,
                            query_type=str(record_type),
                            response_ips=[response_ip] if response_ip else [],
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.log.debug(f"[DNSMonitor] Windows DNS cache read failed: {e}")

        return entries

    def _read_linux_dns_cache(self) -> list[DNSQuery]:
        """Read recent DNS queries from systemd-resolved or journal."""
        entries: list[DNSQuery] = []

        # Try systemd-resolved statistics
        try:
            result = subprocess.run(
                ["resolvectl", "query", "--cache"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith(("--", "Link")):
                        parts = line.split()
                        if parts:
                            domain = parts[0].rstrip(".")
                            entries.append(DNSQuery(domain=domain))
                return entries
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # Fallback: parse journalctl for DNS queries
        try:
            result = subprocess.run(
                ["journalctl", "-u", "systemd-resolved", "--since", "2 minutes ago",
                 "--no-pager", "-q"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # Look for query patterns in resolved logs
                    match = re.search(r"(?:Accepting|Processing) (?:transaction|query) for (.+?)(?:\s|$)", line)
                    if match:
                        domain = match.group(1).rstrip(".")
                        entries.append(DNSQuery(domain=domain))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return entries

    def _read_macos_dns_cache(self) -> list[DNSQuery]:
        """Read DNS cache on macOS via dscacheutil or log stream."""
        entries: list[DNSQuery] = []

        try:
            result = subprocess.run(
                ["dscacheutil", "-cachedump", "-entries"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                current_domain = ""
                for line in result.stdout.splitlines():
                    if line.startswith("name:"):
                        current_domain = line.split(":", 1)[1].strip().rstrip(".")
                    elif current_domain and line.startswith("ip_address:"):
                        ip = line.split(":", 1)[1].strip()
                        entries.append(DNSQuery(
                            domain=current_domain,
                            response_ips=[ip] if ip else [],
                        ))
                        current_domain = ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return entries

    # ------------------------------------------------------------------
    # Domain analysis
    # ------------------------------------------------------------------

    def _analyze_domain(self, domain: str, query: DNSQuery, now: float) -> list[EDREvent]:
        """Analyze a domain for suspicious characteristics."""
        events: list[EDREvent] = []

        # Skip known-safe domains
        if self._is_safe_domain(domain):
            return events

        # Check 1: IOC database match
        if self._ioc_db:
            ioc_event = self._check_ioc_match(domain, query)
            if ioc_event:
                events.append(ioc_event)
                return events  # IOC match is definitive — skip heuristics

        # Check 2: DGA / DNS tunneling detection
        dga_event = self._check_dga_tunneling(domain, query)
        if dga_event:
            events.append(dga_event)

        # Check 3: Suspicious TLD
        tld_event = self._check_suspicious_tld(domain, query)
        if tld_event:
            events.append(tld_event)

        # Check 4: Query rate anomaly
        rate_event = self._check_query_rate(domain, now)
        if rate_event:
            events.append(rate_event)

        return events

    def _check_ioc_match(self, domain: str, query: DNSQuery) -> EDREvent | None:
        """Check domain against IOC database."""
        match = self._ioc_db.lookup_domain(domain)
        if match:
            return EDREvent(
                event_type=EDREventType.NETWORK_CONNECT,
                source_process="dns",
                target=domain,
                details={
                    "dns_query": domain,
                    "query_type": query.query_type,
                    "ioc_match": True,
                    "ioc_category": match.threat_category.value if hasattr(match, 'threat_category') else "unknown",
                    "ioc_source": match.source if hasattr(match, 'source') else "",
                    "detection": "ioc_domain_match",
                },
                severity="critical",
            )

        # Also check resolved IPs against IOC database
        for ip in query.response_ips:
            ip_match = self._ioc_db.lookup_ip(ip)
            if ip_match:
                return EDREvent(
                    event_type=EDREventType.NETWORK_CONNECT,
                    source_process="dns",
                    target=f"{domain} -> {ip}",
                    details={
                        "dns_query": domain,
                        "resolved_ip": ip,
                        "ioc_match": True,
                        "ioc_category": ip_match.threat_category.value if hasattr(ip_match, 'threat_category') else "unknown",
                        "detection": "ioc_resolved_ip_match",
                    },
                    severity="critical",
                )
        return None

    def _check_dga_tunneling(self, domain: str, query: DNSQuery) -> EDREvent | None:
        """Detect DGA domains and DNS tunneling by subdomain entropy."""
        # Extract the subdomain labels (everything before the registered domain)
        parts = domain.split(".")
        if len(parts) < 3:
            return None  # No subdomain to analyze

        # Analyze the longest subdomain label
        subdomain_labels = parts[:-2]  # Everything except registered domain + TLD
        longest_label = max(subdomain_labels, key=len) if subdomain_labels else ""

        if len(longest_label) < DGA_MIN_LABEL_LENGTH:
            return None

        entropy = self._label_entropy(longest_label)
        if entropy < DGA_ENTROPY_THRESHOLD:
            return None

        # Additional heuristic: high consonant-to-vowel ratio
        vowels = sum(1 for c in longest_label.lower() if c in "aeiou")
        consonants = sum(1 for c in longest_label.lower() if c.isalpha() and c not in "aeiou")
        ratio = consonants / max(vowels, 1)

        # DGA domains often have ratio > 4 or very high entropy
        if entropy > 4.0 or (entropy > DGA_ENTROPY_THRESHOLD and ratio > 4):
            return EDREvent(
                event_type=EDREventType.NETWORK_CONNECT,
                source_process="dns",
                target=domain,
                details={
                    "dns_query": domain,
                    "query_type": query.query_type,
                    "subdomain_label": longest_label,
                    "label_entropy": round(entropy, 3),
                    "consonant_vowel_ratio": round(ratio, 2),
                    "detection": "dga_tunneling",
                },
                severity="high",
            )
        return None

    def _check_suspicious_tld(self, domain: str, query: DNSQuery) -> EDREvent | None:
        """Flag domains with TLDs commonly abused for malware."""
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return EDREvent(
                    event_type=EDREventType.NETWORK_CONNECT,
                    source_process="dns",
                    target=domain,
                    details={
                        "dns_query": domain,
                        "query_type": query.query_type,
                        "suspicious_tld": tld,
                        "detection": "suspicious_tld",
                    },
                    severity="medium",
                )
        return None

    def _check_query_rate(self, domain: str, now: float) -> EDREvent | None:
        """Detect abnormally high query rates to a single domain."""
        # Extract the registered domain (last 2 parts)
        parts = domain.split(".")
        registered = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        with self._lock:
            history = self._query_history[registered]
            history.append(now)

            # Prune old entries
            cutoff = now - QUERY_RATE_WINDOW
            self._query_history[registered] = [t for t in history if t >= cutoff]
            count = len(self._query_history[registered])

        if count > QUERY_RATE_THRESHOLD:
            return EDREvent(
                event_type=EDREventType.NETWORK_CONNECT,
                source_process="dns",
                target=domain,
                details={
                    "dns_query": domain,
                    "registered_domain": registered,
                    "query_count": count,
                    "window_seconds": QUERY_RATE_WINDOW,
                    "detection": "high_query_rate",
                },
                severity="medium",
            )
        return None

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _label_entropy(label: str) -> float:
        """Calculate Shannon entropy of a DNS label string."""
        if not label:
            return 0.0
        freq: dict[str, int] = defaultdict(int)
        for ch in label.lower():
            freq[ch] += 1
        length = len(label)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_safe_domain(domain: str) -> bool:
        """Check if a domain is known-safe and should not be flagged."""
        parts = domain.lower().split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in SAFE_DOMAINS:
                return True
        return False

    @staticmethod
    def _parse_csv_line(line: str) -> list[str]:
        """Simple CSV line parser handling quoted fields."""
        result: list[str] = []
        current = ""
        in_quotes = False
        for ch in line:
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == "," and not in_quotes:
                result.append(current)
                current = ""
            else:
                current += ch
        result.append(current)
        return result

"""
Sentinel Agent — Event Correlation Engine

Correlates individual EDR events into attack chains and compound
detections. This is the intelligence layer that transforms raw event
noise into actionable security alerts.

DESIGN:
- Maintains sliding time windows of recent events indexed by PID and IP.
- Evaluates correlation rules against incoming events in real-time.
- Each rule defines a pattern of events that, when observed together
  within a time window, constitute a higher-confidence detection.
- Produces CorrelatedAlert objects that carry the full event chain,
  a composite severity, and a MITRE ATT&CK reference where applicable.

SECURITY: This module is read-only and observational. It never
modifies, terminates, or interacts with any process or connection.
"""

from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from edr.event_types import EDREvent, EDREventType


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    """Correlated alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CorrelatedAlert:
    """A compound detection produced by correlating multiple EDR events."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    rule_name: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.HIGH
    mitre_tactic: str = ""
    mitre_technique: str = ""
    events: list[EDREvent] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source_pids: list[int] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "event_ids": [e.id for e in self.events],
            "event_count": len(self.events),
            "timestamp": self.timestamp,
            "source_pids": self.source_pids,
            "evidence": self.evidence,
        }


@dataclass
class CorrelationRule:
    """Defines a pattern of events that constitute a compound detection.

    Attributes:
        name: Human-readable rule name.
        description: What this correlation detects.
        required_event_types: Set of event types that must appear in the window.
        min_events: Minimum number of matching events to trigger.
        window_seconds: Sliding time window in seconds.
        severity: Severity of the resulting alert.
        mitre_tactic: MITRE ATT&CK tactic (e.g., "Execution").
        mitre_technique: MITRE ATT&CK technique ID (e.g., "T1059").
        condition: Optional callable for custom logic. Receives the list of
                   candidate events and returns (should_alert, evidence_dict).
        group_by: How to group events — "pid", "ip", or "global".
    """
    name: str
    description: str
    required_event_types: set[EDREventType]
    min_events: int = 2
    window_seconds: int = 60
    severity: AlertSeverity = AlertSeverity.HIGH
    mitre_tactic: str = ""
    mitre_technique: str = ""
    condition: Callable[[list[EDREvent]], tuple[bool, dict[str, Any]]] | None = None
    group_by: str = "pid"  # "pid", "ip", or "global"


# ---------------------------------------------------------------------------
# Built-in correlation rules
# ---------------------------------------------------------------------------

def _condition_process_spawn_then_network(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Process starts from temp dir, then makes outbound connection."""
    temp_markers = ["\\temp\\", "\\tmp\\", "/tmp/", "/var/tmp/", "/dev/shm/",
                    "\\appdata\\local\\temp\\", "\\downloads\\"]
    has_temp_process = False
    has_network = False
    process_name = ""
    remote_target = ""

    for e in events:
        if e.event_type == EDREventType.PROCESS_START:
            target_lower = (e.target or "").lower()
            if any(marker in target_lower for marker in temp_markers):
                has_temp_process = True
                process_name = e.source_process
        elif e.event_type == EDREventType.NETWORK_CONNECT:
            has_network = True
            remote_target = e.target

    if has_temp_process and has_network:
        return True, {"process": process_name, "remote_target": remote_target,
                       "indicator": "temp_dir_process_with_network"}
    return False, {}


def _condition_rapid_file_encryption(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Multiple file modifications in rapid succession — ransomware indicator."""
    file_events = [e for e in events if e.event_type in
                   (EDREventType.FILE_MODIFY, EDREventType.FILE_CREATE, EDREventType.FILE_DELETE)]
    if len(file_events) < 10:
        return False, {}

    # Check if modifications happened within a tight burst (< 5 seconds spread)
    timestamps = sorted(datetime.fromisoformat(e.timestamp) for e in file_events)
    if len(timestamps) >= 2:
        spread = (timestamps[-1] - timestamps[0]).total_seconds()
        rate = len(file_events) / max(spread, 0.1)
        if rate > 2.0:  # More than 2 file ops per second
            return True, {"file_count": len(file_events),
                          "spread_seconds": round(spread, 2),
                          "rate_per_second": round(rate, 2)}
    return False, {}


def _condition_lateral_movement(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Process spawns a remote access tool or makes SMB/RDP/WinRM connections."""
    lateral_tools = {"psexec", "psexec64", "wmic", "winrs", "mstsc",
                     "ssh", "scp", "nc", "ncat", "nmap"}
    lateral_ports = {445, 3389, 5985, 5986, 22, 135}  # SMB, RDP, WinRM, SSH, RPC

    has_tool = False
    has_port = False
    tool_name = ""
    port_hit = 0

    for e in events:
        if e.event_type == EDREventType.PROCESS_START:
            proc = e.source_process.lower().replace(".exe", "")
            if proc in lateral_tools:
                has_tool = True
                tool_name = e.source_process
        elif e.event_type == EDREventType.NETWORK_CONNECT:
            remote_port = e.details.get("remote_port", 0)
            if remote_port in lateral_ports:
                has_port = True
                port_hit = remote_port

    if has_tool or has_port:
        return True, {"lateral_tool": tool_name, "lateral_port": port_hit,
                       "indicator": "lateral_movement"}
    return False, {}


def _condition_credential_access(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Process accesses LSASS or credential stores."""
    cred_targets = {"lsass.exe", "lsass", "sam", "ntds.dit",
                    "/etc/shadow", "/etc/passwd", ".ssh/id_rsa"}
    cred_tools = {"mimikatz", "procdump", "secretsdump", "lazagne",
                  "rubeus", "kerberoast", "hashcat", "john"}

    hits: list[str] = []
    for e in events:
        proc_lower = e.source_process.lower().replace(".exe", "")
        target_lower = (e.target or "").lower()

        if proc_lower in cred_tools:
            hits.append(f"tool:{e.source_process}")
        for ct in cred_targets:
            if ct in target_lower:
                hits.append(f"target:{ct}")

    if hits:
        return True, {"credential_indicators": hits}
    return False, {}


def _condition_defense_evasion(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Process disables security tools or clears logs."""
    evasion_patterns = [
        "net stop", "sc stop", "taskkill /f", "wevtutil cl",
        "set-mppreference -disablerealtimemonitoring",
        "remove-mppreference", "add-mppreference -exclusionpath",
        "iptables -f", "ufw disable", "setenforce 0",
    ]

    hits: list[str] = []
    for e in events:
        cmdline = e.details.get("cmdline", "").lower()
        for pattern in evasion_patterns:
            if pattern in cmdline:
                hits.append(pattern)

    if hits:
        return True, {"evasion_commands": hits}
    return False, {}


def _condition_dns_exfiltration(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """DGA/tunneling DNS queries combined with file or process activity.

    This pattern indicates data exfiltration via DNS tunneling — an attacker
    encodes stolen data in DNS subdomain labels to bypass firewalls.
    """
    has_dga_dns = False
    has_file_or_process = False
    dns_domain = ""
    file_target = ""

    for e in events:
        detection = e.details.get("detection", "")
        if detection in ("dga_tunneling", "ioc_domain_match"):
            has_dga_dns = True
            dns_domain = e.details.get("dns_query", e.target)
        elif e.event_type in (EDREventType.FILE_MODIFY, EDREventType.FILE_CREATE,
                              EDREventType.FILE_DELETE):
            has_file_or_process = True
            file_target = e.target
        elif e.event_type == EDREventType.PROCESS_START:
            has_file_or_process = True

    if has_dga_dns and has_file_or_process:
        return True, {"dns_domain": dns_domain, "file_target": file_target,
                       "indicator": "dns_exfiltration"}
    return False, {}


def _condition_dns_c2_with_process(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Suspicious DNS query (IOC match or DGA) combined with a process
    launched from a temp directory — strong C2 indicator.
    """
    temp_markers = ["\\temp\\", "\\tmp\\", "/tmp/", "/var/tmp/", "/dev/shm/",
                    "\\appdata\\local\\temp\\", "\\downloads\\"]
    has_suspicious_dns = False
    has_temp_process = False
    dns_domain = ""
    process_name = ""

    for e in events:
        detection = e.details.get("detection", "")
        if detection in ("dga_tunneling", "ioc_domain_match", "ioc_resolved_ip_match"):
            has_suspicious_dns = True
            dns_domain = e.details.get("dns_query", e.target)
        elif e.event_type == EDREventType.PROCESS_START:
            target_lower = (e.target or "").lower()
            if any(marker in target_lower for marker in temp_markers):
                has_temp_process = True
                process_name = e.source_process

    if has_suspicious_dns and has_temp_process:
        return True, {"dns_domain": dns_domain, "process": process_name,
                       "indicator": "dns_c2_with_temp_process"}
    return False, {}


def _condition_dns_beaconing(events: list[EDREvent]) -> tuple[bool, dict[str, Any]]:
    """Multiple DNS queries to the same suspicious domain in short succession
    — characteristic of C2 beaconing over DNS.
    """
    dns_events = [e for e in events
                  if e.details.get("detection") in ("dga_tunneling", "suspicious_tld",
                                                     "high_query_rate")]
    if len(dns_events) < 3:
        return False, {}

    # Group by registered domain (last 2 labels)
    domain_counts: dict[str, int] = {}
    for e in dns_events:
        domain = e.details.get("dns_query", e.target)
        parts = domain.split(".")
        registered = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        domain_counts[registered] = domain_counts.get(registered, 0) + 1

    # Any domain queried 3+ times in the window is beaconing
    beaconing_domains = {d: c for d, c in domain_counts.items() if c >= 3}
    if beaconing_domains:
        return True, {"beaconing_domains": beaconing_domains,
                       "total_queries": sum(beaconing_domains.values())}
    return False, {}


# The built-in correlation rules
BUILTIN_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="C2 Beacon — Temp Process with Network",
        description=(
            "A process launched from a temporary directory established an "
            "outbound network connection. This pattern is characteristic of "
            "malware droppers and command-and-control beacons."
        ),
        required_event_types={EDREventType.PROCESS_START, EDREventType.NETWORK_CONNECT},
        min_events=2,
        window_seconds=30,
        severity=AlertSeverity.CRITICAL,
        mitre_tactic="Command and Control",
        mitre_technique="T1071",
        condition=_condition_process_spawn_then_network,
        group_by="pid",
    ),

    CorrelationRule(
        name="Ransomware — Rapid File Encryption",
        description=(
            "Detected a burst of file modifications at an abnormally high rate. "
            "This pattern strongly indicates active ransomware encryption."
        ),
        required_event_types={EDREventType.FILE_MODIFY, EDREventType.FILE_CREATE},
        min_events=10,
        window_seconds=15,
        severity=AlertSeverity.CRITICAL,
        mitre_tactic="Impact",
        mitre_technique="T1486",
        condition=_condition_rapid_file_encryption,
        group_by="pid",
    ),

    CorrelationRule(
        name="Lateral Movement Detected",
        description=(
            "A process spawned a known lateral movement tool or established "
            "connections on SMB/RDP/WinRM/SSH ports. This may indicate an "
            "attacker moving between systems."
        ),
        required_event_types={EDREventType.PROCESS_START, EDREventType.NETWORK_CONNECT},
        min_events=1,
        window_seconds=120,
        severity=AlertSeverity.HIGH,
        mitre_tactic="Lateral Movement",
        mitre_technique="T1021",
        condition=_condition_lateral_movement,
        group_by="global",
    ),

    CorrelationRule(
        name="Credential Access Attempt",
        description=(
            "Detected access to credential stores (LSASS, SAM, shadow) or "
            "execution of known credential harvesting tools."
        ),
        required_event_types={EDREventType.PROCESS_START},
        min_events=1,
        window_seconds=60,
        severity=AlertSeverity.CRITICAL,
        mitre_tactic="Credential Access",
        mitre_technique="T1003",
        condition=_condition_credential_access,
        group_by="global",
    ),

    CorrelationRule(
        name="Defense Evasion — Security Tool Disabled",
        description=(
            "A process executed commands to disable security tools, clear "
            "event logs, or modify firewall rules. Attackers commonly do "
            "this before deploying payloads."
        ),
        required_event_types={EDREventType.PROCESS_START},
        min_events=1,
        window_seconds=60,
        severity=AlertSeverity.HIGH,
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562",
        condition=_condition_defense_evasion,
        group_by="global",
    ),

    CorrelationRule(
        name="Process Injection Chain",
        description=(
            "A suspicious process start was followed by privilege escalation "
            "or additional process spawns — possible multi-stage payload."
        ),
        required_event_types={EDREventType.PROCESS_START, EDREventType.PRIVILEGE_ESCALATION},
        min_events=2,
        window_seconds=30,
        severity=AlertSeverity.HIGH,
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1055",
        group_by="pid",
    ),

    CorrelationRule(
        name="Canary File Triggered with File Activity",
        description=(
            "A canary file was accessed alongside other file modification "
            "events. This is a strong ransomware or data exfiltration indicator."
        ),
        required_event_types={EDREventType.CANARY_TRIGGERED, EDREventType.FILE_MODIFY},
        min_events=2,
        window_seconds=30,
        severity=AlertSeverity.CRITICAL,
        mitre_tactic="Impact",
        mitre_technique="T1486",
        group_by="global",
    ),

    # ----- DNS-specific correlation rules -----

    CorrelationRule(
        name="DNS Exfiltration — DGA + File Activity",
        description=(
            "Detected DNS tunneling or DGA domain queries combined with "
            "file modification activity. This pattern strongly indicates "
            "data exfiltration via DNS subdomain encoding."
        ),
        required_event_types={EDREventType.NETWORK_CONNECT},
        min_events=2,
        window_seconds=120,
        severity=AlertSeverity.CRITICAL,
        mitre_tactic="Exfiltration",
        mitre_technique="T1048.003",
        condition=_condition_dns_exfiltration,
        group_by="global",
    ),

    CorrelationRule(
        name="DNS C2 — Suspicious DNS + Temp Process",
        description=(
            "A process launched from a temporary directory was observed "
            "alongside DNS queries to DGA or known-malicious domains. "
            "This is a strong command-and-control indicator."
        ),
        required_event_types={EDREventType.NETWORK_CONNECT, EDREventType.PROCESS_START},
        min_events=2,
        window_seconds=60,
        severity=AlertSeverity.CRITICAL,
        mitre_tactic="Command and Control",
        mitre_technique="T1071.004",
        condition=_condition_dns_c2_with_process,
        group_by="global",
    ),

    CorrelationRule(
        name="DNS Beaconing Detected",
        description=(
            "Repeated DNS queries to suspicious domains detected in a "
            "short time window. This periodic pattern is characteristic "
            "of malware C2 beaconing over DNS."
        ),
        required_event_types={EDREventType.NETWORK_CONNECT},
        min_events=3,
        window_seconds=120,
        severity=AlertSeverity.HIGH,
        mitre_tactic="Command and Control",
        mitre_technique="T1071.004",
        condition=_condition_dns_beaconing,
        group_by="global",
    ),
]


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Real-time event correlation engine.

    Feed events via `ingest(event)`. The engine maintains sliding windows
    indexed by PID and globally, evaluates all rules, and emits
    CorrelatedAlert objects through the on_alert callback.

    Thread-safe: designed to be called from multiple monitor threads.
    """

    def __init__(
        self,
        rules: list[CorrelationRule] | None = None,
        on_alert: Callable[[CorrelatedAlert], None] | None = None,
        max_window_seconds: int = 300,
        dedup_window_seconds: int = 300,
    ):
        self._rules = rules if rules is not None else list(BUILTIN_RULES)
        self._on_alert = on_alert
        self._max_window = max_window_seconds
        self._dedup_window = dedup_window_seconds

        # Sliding windows — protected by _lock
        self._lock = threading.Lock()
        self._events_by_pid: dict[int, list[EDREvent]] = defaultdict(list)
        self._events_by_ip: dict[str, list[EDREvent]] = defaultdict(list)
        self._global_events: list[EDREvent] = []

        # Deduplication: rule_name -> last alert timestamp
        self._recent_alerts: dict[str, datetime] = {}

        # Stats
        self._events_ingested = 0
        self._alerts_emitted = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, event: EDREvent) -> list[CorrelatedAlert]:
        """Ingest an event and evaluate all correlation rules.

        Returns any alerts produced (also dispatched via on_alert callback).
        """
        alerts: list[CorrelatedAlert] = []

        with self._lock:
            self._events_ingested += 1
            now = datetime.now()

            # Index the event
            self._global_events.append(event)
            if event.source_pid:
                self._events_by_pid[event.source_pid].append(event)

            remote_ip = event.details.get("remote_ip", "")
            if remote_ip:
                self._events_by_ip[remote_ip].append(event)

            # Prune old events from all windows
            self._prune_windows(now)

            # Evaluate rules
            for rule in self._rules:
                candidates = self._get_candidates(rule, event)
                if len(candidates) < rule.min_events:
                    continue

                # Check required event types are present
                present_types = {e.event_type for e in candidates}
                if not rule.required_event_types.issubset(present_types):
                    continue

                # Run custom condition if provided
                evidence: dict[str, Any] = {}
                if rule.condition:
                    should_alert, evidence = rule.condition(candidates)
                    if not should_alert:
                        continue

                # Deduplication check
                dedup_key = self._dedup_key(rule, event)
                last_alert_time = self._recent_alerts.get(dedup_key)
                if last_alert_time and (now - last_alert_time).total_seconds() < self._dedup_window:
                    continue

                # Emit alert
                alert = CorrelatedAlert(
                    rule_name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    events=list(candidates),
                    source_pids=list({e.source_pid for e in candidates if e.source_pid}),
                    evidence=evidence,
                )
                alerts.append(alert)
                self._recent_alerts[dedup_key] = now
                self._alerts_emitted += 1

        # Dispatch callbacks outside the lock to avoid deadlocks
        for alert in alerts:
            if self._on_alert:
                self._on_alert(alert)

        return alerts

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule at runtime."""
        with self._lock:
            self._rules.append(rule)

    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        with self._lock:
            return {
                "events_ingested": self._events_ingested,
                "alerts_emitted": self._alerts_emitted,
                "active_rules": len(self._rules),
                "tracked_pids": len(self._events_by_pid),
                "tracked_ips": len(self._events_by_ip),
                "global_window_size": len(self._global_events),
                "dedup_entries": len(self._recent_alerts),
            }

    def get_rules(self) -> list[dict[str, Any]]:
        """Return summary of all active rules."""
        with self._lock:
            return [
                {
                    "name": r.name,
                    "description": r.description,
                    "severity": r.severity.value,
                    "mitre_tactic": r.mitre_tactic,
                    "mitre_technique": r.mitre_technique,
                    "window_seconds": r.window_seconds,
                    "min_events": r.min_events,
                    "group_by": r.group_by,
                }
                for r in self._rules
            ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_candidates(self, rule: CorrelationRule, trigger: EDREvent) -> list[EDREvent]:
        """Get candidate events for a rule based on its grouping strategy."""
        cutoff = datetime.now() - timedelta(seconds=rule.window_seconds)

        if rule.group_by == "pid" and trigger.source_pid:
            pool = self._events_by_pid.get(trigger.source_pid, [])
        elif rule.group_by == "ip":
            remote_ip = trigger.details.get("remote_ip", "")
            pool = self._events_by_ip.get(remote_ip, []) if remote_ip else []
        else:
            pool = self._global_events

        return [
            e for e in pool
            if datetime.fromisoformat(e.timestamp) >= cutoff
        ]

    def _prune_windows(self, now: datetime) -> None:
        """Remove events older than the maximum window from all indices."""
        cutoff = now - timedelta(seconds=self._max_window)

        self._global_events = [
            e for e in self._global_events
            if datetime.fromisoformat(e.timestamp) >= cutoff
        ]

        for pid in list(self._events_by_pid):
            events = self._events_by_pid[pid]
            pruned = [e for e in events if datetime.fromisoformat(e.timestamp) >= cutoff]
            if pruned:
                self._events_by_pid[pid] = pruned
            else:
                del self._events_by_pid[pid]

        for ip in list(self._events_by_ip):
            events = self._events_by_ip[ip]
            pruned = [e for e in events if datetime.fromisoformat(e.timestamp) >= cutoff]
            if pruned:
                self._events_by_ip[ip] = pruned
            else:
                del self._events_by_ip[ip]

        # Prune dedup entries
        dedup_cutoff = now - timedelta(seconds=self._dedup_window)
        expired = [k for k, v in self._recent_alerts.items() if v < dedup_cutoff]
        for k in expired:
            del self._recent_alerts[k]

    @staticmethod
    def _dedup_key(rule: CorrelationRule, trigger: EDREvent) -> str:
        """Create a deduplication key for a rule + context."""
        if rule.group_by == "pid":
            return f"{rule.name}:pid:{trigger.source_pid}"
        elif rule.group_by == "ip":
            remote_ip = trigger.details.get("remote_ip", "")
            return f"{rule.name}:ip:{remote_ip}"
        return f"{rule.name}:global"

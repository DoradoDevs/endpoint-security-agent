"""
Sentinel Agent — Real-Time Protection Engine

Orchestrates process, connection, DNS, and file monitors for continuous
endpoint protection. Feeds all events through the correlation engine
to detect multi-stage attack patterns. Dispatches alerts to the
notification system and SIEM integration.
"""

from __future__ import annotations

import threading
from typing import Any

from core.config import AgentConfig, Severity
from core.logging import get_logger
from core.telemetry import Finding
from edr.event_types import EDREvent, EDREventType
from edr.event_store import EventStore
from edr.correlation_engine import CorrelationEngine, CorrelatedAlert
from edr.process_tree import ProcessTree


class RealTimeProtectionEngine:
    """Orchestrates all real-time monitors with event correlation."""

    def __init__(self, config: AgentConfig, event_store: EventStore | None = None):
        self.config = config
        self.log = get_logger()
        self._store = event_store or EventStore()
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._event_count = 0
        self._threat_count = 0
        self._alert_count = 0

        # Shared IOC database — loaded once, passed to all monitors
        self._ioc_db = self._load_ioc_database()

        # Correlation engine — receives all events, emits compound alerts
        self._correlator = CorrelationEngine(on_alert=self._on_correlated_alert)

        # Process tree — tracks parent-child relationships for chain analysis
        self._process_tree = ProcessTree()

        # Notification manager — lazy-loaded on first alert
        self._notifier = None

        # SIEM integration — lazy-loaded on first alert
        self._siem = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, stop_event: threading.Event | None = None) -> None:
        """Start all monitors. Blocks until stop_event is set."""
        if stop_event:
            self._stop_event = stop_event

        self.log.info("[RealTimeEngine] Starting real-time protection")

        # Start process monitor (with shared IOC DB)
        try:
            from edr.process_monitor import ProcessMonitor
            pm = ProcessMonitor(self.config, on_event=self._on_process_event,
                                ioc_db=self._ioc_db)
            t = threading.Thread(target=pm.start, args=(self._stop_event,),
                                 name="sentinel-process-monitor", daemon=True)
            t.start()
            self._threads.append(t)
            self.log.info("[RealTimeEngine] Process monitor started")
        except (ImportError, TypeError):
            # TypeError fallback: old ProcessMonitor without ioc_db param
            try:
                from edr.process_monitor import ProcessMonitor
                pm = ProcessMonitor(self.config, on_event=self._on_process_event)
                t = threading.Thread(target=pm.start, args=(self._stop_event,),
                                     name="sentinel-process-monitor", daemon=True)
                t.start()
                self._threads.append(t)
                self.log.info("[RealTimeEngine] Process monitor started (no shared IOC)")
            except ImportError:
                self.log.debug("[RealTimeEngine] Process monitor not available")

        # Start connection monitor (with shared IOC DB)
        try:
            from edr.connection_monitor import ConnectionMonitor
            cm = ConnectionMonitor(self.config, on_event=self._on_connection_event,
                                   ioc_db=self._ioc_db)
            t = threading.Thread(target=cm.start, args=(self._stop_event,),
                                 name="sentinel-connection-monitor", daemon=True)
            t.start()
            self._threads.append(t)
            self.log.info("[RealTimeEngine] Connection monitor started")
        except (ImportError, TypeError):
            try:
                from edr.connection_monitor import ConnectionMonitor
                cm = ConnectionMonitor(self.config, on_event=self._on_connection_event)
                t = threading.Thread(target=cm.start, args=(self._stop_event,),
                                     name="sentinel-connection-monitor", daemon=True)
                t.start()
                self._threads.append(t)
                self.log.info("[RealTimeEngine] Connection monitor started (no shared IOC)")
            except ImportError:
                self.log.debug("[RealTimeEngine] Connection monitor not available")

        # Start DNS monitor (with shared IOC DB)
        try:
            from edr.dns_monitor import DNSMonitor
            dm = DNSMonitor(self.config, on_event=self._on_dns_event,
                            ioc_db=self._ioc_db)
            t = threading.Thread(target=dm.start, args=(self._stop_event,),
                                 name="sentinel-dns-monitor", daemon=True)
            t.start()
            self._threads.append(t)
            self.log.info("[RealTimeEngine] DNS monitor started")
        except ImportError:
            self.log.debug("[RealTimeEngine] DNS monitor not available")

        # Start ETW monitor (Windows kernel events — replaces polling)
        try:
            from edr.etw_monitor import ETWMonitor
            etw = ETWMonitor(self.config, on_event=self._on_etw_event,
                             ioc_db=self._ioc_db)
            t = threading.Thread(target=etw.start, args=(self._stop_event,),
                                 name="sentinel-etw-monitor", daemon=True)
            t.start()
            self._threads.append(t)
            self.log.info("[RealTimeEngine] ETW monitor started")
        except ImportError:
            self.log.debug("[RealTimeEngine] ETW monitor not available")

        # Start Sysmon parser (if Sysmon is installed)
        try:
            from edr.sysmon_parser import SysmonParser
            sp = SysmonParser(self.config, on_event=self._on_sysmon_event,
                              ioc_db=self._ioc_db)
            t = threading.Thread(target=sp.start, args=(self._stop_event,),
                                 name="sentinel-sysmon-parser", daemon=True)
            t.start()
            self._threads.append(t)
            self.log.info("[RealTimeEngine] Sysmon parser started")
        except ImportError:
            self.log.debug("[RealTimeEngine] Sysmon parser not available")

        # Start file monitor (extended file guard)
        try:
            from core.file_guard import FileGuard
            fg = FileGuard(self.config)
            t = threading.Thread(target=fg.start, args=(self._stop_event,),
                                 name="sentinel-file-monitor", daemon=True)
            t.start()
            self._threads.append(t)
            self.log.info("[RealTimeEngine] File monitor started")
        except ImportError:
            self.log.debug("[RealTimeEngine] File monitor not available")

        self.log.info(
            f"[RealTimeEngine] Active monitors: {len(self._threads)}, "
            f"Correlation rules: {len(self._correlator.get_rules())}"
        )

        # Block until stopped
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=1.0)

    def stop(self) -> None:
        """Stop all monitors."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=10)
        with self._lock:
            self.log.info(
                f"[RealTimeEngine] Stopped. Events: {self._event_count}, "
                f"Threats: {self._threat_count}, Correlated alerts: {self._alert_count}"
            )

    # ------------------------------------------------------------------
    # Event handlers (called from monitor threads)
    # ------------------------------------------------------------------

    def _on_process_event(self, event: EDREvent) -> None:
        """Handle process events."""
        self._ingest_event(event)

    def _on_connection_event(self, event: EDREvent) -> None:
        """Handle connection events."""
        self._ingest_event(event)

    def _on_dns_event(self, event: EDREvent) -> None:
        """Handle DNS events."""
        self._ingest_event(event)

    def _on_etw_event(self, event: EDREvent) -> None:
        """Handle ETW kernel events."""
        self._ingest_event(event)

    def _on_sysmon_event(self, event: EDREvent) -> None:
        """Handle Sysmon events."""
        self._ingest_event(event)

    def _ingest_event(self, event: EDREvent) -> None:
        """Common event ingestion: store, correlate, tree-track, and respond."""
        with self._lock:
            self._event_count += 1
        self._store.record_event(event)

        # Update process tree for ancestry tracking
        self._process_tree.on_event(event)

        # Feed to correlation engine (thread-safe internally)
        self._correlator.ingest(event)

        if event.severity in ("high", "critical"):
            with self._lock:
                self._threat_count += 1
            self.log.warning(
                f"[RealTimeEngine] Threat: {event.event_type.value} — "
                f"{event.source_process} (PID {event.source_pid}) "
                f"target={event.target} [{event.severity}]"
            )
            self._trigger_response(event)

            # Enrich with process chain analysis
            if event.source_pid:
                chain_score = self._process_tree.get_chain_score(event.source_pid)
                if chain_score > 10.0:
                    chain = self._process_tree.analyze_chain(event.source_pid)
                    self.log.warning(
                        f"[RealTimeEngine] Suspicious process chain (score={chain_score:.1f}): "
                        f"patterns={chain.get('attack_patterns', [])}"
                    )

            # Send desktop notification for individual high-severity events
            self._send_notification(
                title=f"Sentinel: {event.severity.upper()} threat detected",
                message=f"{event.source_process}: {event.event_type.value}",
                severity=event.severity,
            )

            # Forward to SIEM
            self._forward_event_to_siem(event)

    def _on_correlated_alert(self, alert: CorrelatedAlert) -> None:
        """Handle correlated alerts from the correlation engine."""
        with self._lock:
            self._alert_count += 1

        self.log.warning(
            f"[RealTimeEngine] CORRELATED ALERT: {alert.rule_name} "
            f"({alert.severity.value}) — {len(alert.events)} events, "
            f"PIDs: {alert.source_pids}"
        )
        if alert.mitre_technique:
            self.log.warning(
                f"[RealTimeEngine] MITRE ATT&CK: {alert.mitre_tactic} / {alert.mitre_technique}"
            )

        # Record the alert as a THREAT_DETECTED event in the store
        alert_event = EDREvent(
            event_type=EDREventType.THREAT_DETECTED,
            source_process=alert.rule_name,
            target=", ".join(str(p) for p in alert.source_pids),
            details={
                "alert_id": alert.id,
                "rule_name": alert.rule_name,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique,
                "event_count": len(alert.events),
                "evidence": alert.evidence,
            },
            severity=alert.severity.value,
        )
        self._store.record_event(alert_event)

        # Desktop notification for correlated alerts
        mitre_info = f" [{alert.mitre_technique}]" if alert.mitre_technique else ""
        self._send_notification(
            title=f"Sentinel: {alert.severity.value.upper()} — {alert.rule_name}",
            message=f"{alert.description[:120]}{mitre_info}",
            severity=alert.severity.value,
        )

        # Forward correlated alert to SIEM
        self._forward_alert_to_siem(alert)

        # Convert to a Finding and trigger the response engine
        finding = self._alert_to_finding(alert)
        self._trigger_response_for_finding(finding)

    # ------------------------------------------------------------------
    # Notification dispatch
    # ------------------------------------------------------------------

    def _send_notification(self, title: str, message: str, severity: str = "info") -> None:
        """Send a desktop notification for security events."""
        try:
            if self._notifier is None:
                from core.notifications import NotificationManager
                self._notifier = NotificationManager()
            self._notifier.notify(title, message, severity)
        except ImportError:
            pass
        except Exception as exc:
            self.log.debug(f"[RealTimeEngine] Notification failed: {exc}")

    # ------------------------------------------------------------------
    # SIEM forwarding
    # ------------------------------------------------------------------

    def _get_siem(self):
        """Lazy-load SIEM integration if configured."""
        if self._siem is not None:
            return self._siem

        try:
            siem_config = getattr(self.config, "siem", None)
            if siem_config is None:
                return None

            from reporting.siem_integration import SIEMIntegration, SIEMConfig

            cfg = SIEMConfig(
                webhook_url=getattr(siem_config, "webhook_url", ""),
                syslog_host=getattr(siem_config, "syslog_host", ""),
                syslog_port=getattr(siem_config, "syslog_port", 514),
                syslog_protocol=getattr(siem_config, "syslog_protocol", "udp"),
                syslog_format=getattr(siem_config, "syslog_format", "cef"),
                forward_min_severity=getattr(siem_config, "forward_min_severity", "low"),
            )
            if not cfg.webhook_url and not cfg.syslog_host:
                return None

            self._siem = SIEMIntegration(cfg)
            self.log.info("[RealTimeEngine] SIEM integration initialized")
            return self._siem
        except (ImportError, AttributeError):
            return None

    def _forward_event_to_siem(self, event: EDREvent) -> None:
        """Forward an EDR event to SIEM if configured."""
        siem = self._get_siem()
        if siem:
            try:
                siem.forward_event(event)
            except Exception as exc:
                self.log.debug(f"[RealTimeEngine] SIEM event forward failed: {exc}")

    def _forward_alert_to_siem(self, alert: CorrelatedAlert) -> None:
        """Forward a correlated alert to SIEM as a high-priority finding."""
        siem = self._get_siem()
        if siem:
            try:
                finding = self._alert_to_finding(alert)
                siem.forward_finding(finding)
            except Exception as exc:
                self.log.debug(f"[RealTimeEngine] SIEM alert forward failed: {exc}")

    # ------------------------------------------------------------------
    # Response integration
    # ------------------------------------------------------------------

    def _trigger_response(self, event: EDREvent) -> None:
        """Trigger automated response for a single high-severity event."""
        finding = self._event_to_finding(event)
        self._trigger_response_for_finding(finding)

    def _trigger_response_for_finding(self, finding: Finding) -> None:
        """Route a finding through the response engine."""
        if not getattr(self.config, "response", None):
            return
        if not self.config.response.auto_respond:
            return

        try:
            from response.engine import ThreatResponseEngine
            from core.telemetry import ScanResult, SystemInfo

            result = ScanResult(
                system_info=SystemInfo(),
                findings=[finding],
                risk_score=finding.severity.weight * 10,
                risk_grade="F" if finding.severity == Severity.CRITICAL else "D",
            )
            engine = ThreatResponseEngine(self.config)
            response = engine.respond(result)

            executed = response.get("total_actions", 0)
            errors = response.get("total_errors", 0)
            if executed:
                self.log.info(f"[RealTimeEngine] Auto-response: {executed} action(s) executed")
            if errors:
                self.log.warning(f"[RealTimeEngine] Auto-response: {errors} action(s) failed")
        except ImportError:
            self.log.debug("[RealTimeEngine] Response engine not available")
        except Exception as exc:
            self.log.error(f"[RealTimeEngine] Response error: {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _event_to_finding(event: EDREvent) -> Finding:
        """Convert an EDR event to a Finding for the response engine."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return Finding(
            title=f"Real-time detection: {event.event_type.value}",
            description=(
                f"Process '{event.source_process}' (PID {event.source_pid}) "
                f"triggered a {event.severity} severity {event.event_type.value} event."
            ),
            severity=severity_map.get(event.severity, Severity.MEDIUM),
            category="Real-Time Detection",
            scanner="RealTimeEngine",
            evidence={
                "pid": event.source_pid,
                "process_name": event.source_process,
                "target": event.target,
                "event_type": event.event_type.value,
                **event.details,
            },
            remediation="Investigate the flagged process and its network activity.",
        )

    @staticmethod
    def _alert_to_finding(alert: CorrelatedAlert) -> Finding:
        """Convert a CorrelatedAlert to a Finding for the response engine."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        pids_str = ", ".join(str(p) for p in alert.source_pids)
        return Finding(
            title=f"Correlated: {alert.rule_name}",
            description=f"{alert.description} (PIDs: {pids_str})",
            severity=severity_map.get(alert.severity.value, Severity.HIGH),
            category="Correlated Detection",
            scanner="CorrelationEngine",
            evidence={
                "alert_id": alert.id,
                "rule_name": alert.rule_name,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique,
                "event_count": len(alert.events),
                "source_pids": alert.source_pids,
                **alert.evidence,
            },
            remediation=(
                f"Multi-event detection ({alert.rule_name}). Investigate all "
                f"involved processes (PIDs: {pids_str}) and their activity."
            ),
        )

    def _load_ioc_database(self):
        """Load the IOC database once for shared use."""
        try:
            from threat_intel.ioc_database import IOCDatabase
            db = IOCDatabase()
            self.log.info("[RealTimeEngine] IOC database loaded")
            return db
        except ImportError:
            self.log.debug("[RealTimeEngine] IOC database not available")
            return None

    def get_stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        with self._lock:
            stats = {
                "total_events": self._event_count,
                "total_threats": self._threat_count,
                "total_correlated_alerts": self._alert_count,
                "active_threads": len([t for t in self._threads if t.is_alive()]),
            }
        stats["correlation"] = self._correlator.get_stats()
        stats["process_tree"] = self._process_tree.get_stats()
        return stats

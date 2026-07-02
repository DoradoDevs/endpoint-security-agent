"""
Sentinel Agent — Ransomware Shield

Combines canary files, backup snapshots, and real-time monitoring
for ransomware detection and response.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


class RansomwareShield:
    """Real-time ransomware detection and response."""

    def __init__(self, config: AgentConfig, event_callback=None):
        self.config = config
        self.log = get_logger()
        self._event_callback = event_callback
        self._canary_check_interval = 30  # seconds
        self._snapshot_interval = 3600  # 1 hour default
        self._alerts: list[dict] = []

    def start(self, stop_event: threading.Event) -> None:
        """Start ransomware monitoring. Blocks until stop_event is set."""
        self.log.info("[RansomwareShield] Starting ransomware protection")

        # Deploy canary files
        canary_mgr = None
        try:
            from edr.canary_files import CanaryFileManager

            canary_mgr = CanaryFileManager()
            count = canary_mgr.deploy_canaries()
            self.log.info(f"[RansomwareShield] {count} canary files deployed")
        except ImportError:
            self.log.debug("[RansomwareShield] Canary module not available")

        # Monitoring loop
        last_snapshot_time = time.time()

        while not stop_event.is_set():
            stop_event.wait(timeout=self._canary_check_interval)
            if stop_event.is_set():
                break

            # Check canaries
            if canary_mgr:
                triggered = canary_mgr.check_canaries()
                if triggered:
                    self._on_ransomware_detected(triggered)

            # Periodic snapshots
            if time.time() - last_snapshot_time >= self._snapshot_interval:
                self._take_snapshot()
                last_snapshot_time = time.time()

        # Cleanup
        if canary_mgr:
            canary_mgr.remove_canaries()
        self.log.info("[RansomwareShield] Stopped")

    def _on_ransomware_detected(self, triggered_canaries) -> None:
        """Emergency response when ransomware is detected."""
        self.log.critical(
            f"[RansomwareShield] RANSOMWARE DETECTED! "
            f"{len(triggered_canaries)} canary files affected"
        )

        alert = {
            "type": "ransomware_alert",
            "timestamp": time.time(),
            "canaries_triggered": len(triggered_canaries),
            "paths": [c.path for c in triggered_canaries],
        }
        self._alerts.append(alert)

        # Fire EDR event
        event = EDREvent(
            event_type=EDREventType.RANSOMWARE_ALERT,
            target=triggered_canaries[0].path if triggered_canaries else "",
            details={"canaries_triggered": len(triggered_canaries)},
            severity="critical",
        )

        if self._event_callback:
            self._event_callback(event)

        # Send notification
        try:
            from core.notifications import NotificationManager

            nm = NotificationManager()
            nm.notify(
                "RANSOMWARE DETECTED",
                f"{len(triggered_canaries)} canary files have been modified or "
                "deleted. Immediate action recommended.",
                "critical",
            )
        except (ImportError, Exception):
            pass

    def _take_snapshot(self) -> None:
        """Take backup snapshot of protected directories."""
        try:
            from edr.backup_snapshots import BackupSnapshotManager

            mgr = BackupSnapshotManager()
            from pathlib import Path

            home = Path.home()
            for name in ["Documents", "Desktop"]:
                d = home / name
                if d.exists():
                    try:
                        mgr.create_snapshot(str(d), max_files=5000)
                    except Exception as e:
                        self.log.debug(
                            f"[RansomwareShield] Snapshot error for {d}: {e}"
                        )
        except ImportError:
            pass

    def get_alerts(self) -> list[dict]:
        return list(self._alerts)

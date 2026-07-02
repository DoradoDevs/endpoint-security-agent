"""
Sentinel Agent — Connection Monitor

Monitors network connections for suspicious activity.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


SUSPICIOUS_PORTS = {4444, 1337, 5555, 31337, 8888, 9999, 1234, 6666, 7777, 443, 80}
# Note: 443/80 only suspicious for non-browser processes

C2_PORTS = {4444, 1337, 5555, 31337, 8888, 9999, 1234, 6666, 7777}


class ConnectionMonitor:
    """Monitors network connections for suspicious activity."""

    def __init__(
        self,
        config: AgentConfig,
        on_event: Callable[[EDREvent], None] | None = None,
        ioc_db: Any = None,
    ):
        self.config = config
        self.log = get_logger()
        self._on_event = on_event
        self._ioc_db = ioc_db
        self._known_connections: set[tuple] = set()
        self._poll_interval = 5.0

    def start(self, stop_event: threading.Event) -> None:
        """Start monitoring. Blocks until stop_event is set."""
        self.log.info("[ConnectionMonitor] Starting connection monitoring")
        self._snapshot_connections()

        while not stop_event.is_set():
            stop_event.wait(timeout=self._poll_interval)
            if stop_event.is_set():
                break
            self._check_connections()

    def _snapshot_connections(self) -> None:
        """Take snapshot of current connections."""
        try:
            import psutil
            conns = psutil.net_connections(kind='inet')
            self._known_connections = {self._conn_key(c) for c in conns if c.raddr}
        except (ImportError, psutil.AccessDenied):
            pass

    def _conn_key(self, conn) -> tuple:
        """Create a hashable key for a connection."""
        raddr = (conn.raddr.ip, conn.raddr.port) if conn.raddr else ("", 0)
        laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else ("", 0)
        return (conn.pid or 0, laddr, raddr)

    def _check_connections(self) -> None:
        """Check for new connections."""
        try:
            import psutil
            current_conns = psutil.net_connections(kind='inet')
            current_keys = set()

            for conn in current_conns:
                if not conn.raddr:
                    continue
                key = self._conn_key(conn)
                current_keys.add(key)

                if key not in self._known_connections:
                    # New connection
                    self._handle_new_connection(conn)

            self._known_connections = current_keys
        except (ImportError, psutil.AccessDenied):
            pass
        except Exception as e:
            self.log.debug(f"[ConnectionMonitor] Error: {e}")

    def _handle_new_connection(self, conn) -> None:
        """Handle a newly detected connection."""
        import psutil

        pid = conn.pid or 0
        process_name = ""
        try:
            if pid:
                proc = psutil.Process(pid)
                process_name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        remote_ip = conn.raddr.ip if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else 0

        severity = "info"
        details = {
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_port": conn.laddr.port if conn.laddr else 0,
            "status": conn.status if hasattr(conn, 'status') else "",
        }

        # Check for C2 ports
        if remote_port in C2_PORTS:
            severity = "high"
            details["suspicious_port"] = True

        # Check IOC database for remote IP
        if self._ioc_db:
            match = self._ioc_db.lookup_ip(remote_ip)
            if match:
                severity = "critical"
                details["ioc_match"] = True
                details["ioc_category"] = match.threat_category.value

        event = EDREvent(
            event_type=EDREventType.NETWORK_CONNECT,
            source_pid=pid,
            source_process=process_name,
            target=f"{remote_ip}:{remote_port}",
            details=details,
            severity=severity,
        )

        if self._on_event:
            self._on_event(event)

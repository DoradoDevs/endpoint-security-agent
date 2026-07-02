"""
Sentinel Agent — Process Monitor

Monitors process creation/termination for threat detection.
Cross-platform using psutil with optional WMI on Windows.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Any

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


class ProcessMonitor:
    """Monitors process creation and termination."""

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
        self._known_pids: set[int] = set()
        self._poll_interval = 3.0  # seconds

    def start(self, stop_event: threading.Event) -> None:
        """Start monitoring. Blocks until stop_event is set."""
        self.log.info("[ProcessMonitor] Starting process monitoring")
        self._snapshot_pids()

        while not stop_event.is_set():
            stop_event.wait(timeout=self._poll_interval)
            if stop_event.is_set():
                break
            self._check_processes()

    def _snapshot_pids(self) -> None:
        """Take initial snapshot of running processes."""
        try:
            import psutil
            self._known_pids = set(psutil.pids())
        except ImportError:
            self.log.debug("[ProcessMonitor] psutil not available")

    def _check_processes(self) -> None:
        """Check for new/terminated processes."""
        try:
            import psutil
            current_pids = set(psutil.pids())

            # New processes
            new_pids = current_pids - self._known_pids
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    event = EDREvent(
                        event_type=EDREventType.PROCESS_START,
                        source_pid=pid,
                        source_process=proc.name(),
                        target=proc.exe() if proc.exe() else "",
                        details={
                            "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
                            "ppid": proc.ppid(),
                            "username": proc.username() if hasattr(proc, 'username') else "",
                            "create_time": proc.create_time(),
                        },
                        severity="info",
                    )
                    self._analyze_process(event, proc)
                    if self._on_event:
                        self._on_event(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Terminated processes
            gone_pids = self._known_pids - current_pids
            for pid in gone_pids:
                event = EDREvent(
                    event_type=EDREventType.PROCESS_STOP,
                    source_pid=pid,
                    severity="info",
                )
                if self._on_event:
                    self._on_event(event)

            self._known_pids = current_pids
        except ImportError:
            pass
        except Exception as e:
            self.log.debug(f"[ProcessMonitor] Error: {e}")

    def _analyze_process(self, event: EDREvent, proc) -> None:
        """Analyze a new process for threats."""
        # Check executable hash against IOC database
        exe_path = event.target
        if exe_path:
            try:
                import hashlib
                sha256 = hashlib.sha256(Path(exe_path).read_bytes()).hexdigest()
                event.details["sha256"] = sha256

                if self._ioc_db:
                    match = self._ioc_db.lookup_hash(sha256)
                    if match:
                        event.severity = "critical"
                        event.details["ioc_match"] = True
                        event.details["ioc_category"] = match.threat_category.value
            except (OSError, PermissionError):
                pass

        # Check for suspicious command line patterns
        cmdline = event.details.get("cmdline", "").lower()
        suspicious_patterns = [
            "powershell -enc", "powershell -e ", "cmd /c", "certutil -urlcache",
            "bitsadmin /transfer", "mshta ", "regsvr32 /s /n /u",
            "rundll32.exe javascript", "wscript.exe", "cscript.exe",
        ]
        for pattern in suspicious_patterns:
            if pattern in cmdline:
                event.severity = "high"
                event.details["suspicious_cmdline"] = True
                event.details["matched_pattern"] = pattern
                break

        # Check for known C2 ports in child network connections
        SUSPICIOUS_PORTS = {4444, 1337, 5555, 31337, 8888, 9999, 1234, 6666, 7777}
        try:
            import psutil
            connections = proc.net_connections(kind='inet')
            for conn in connections:
                if conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
                    event.severity = "high"
                    event.details["suspicious_port"] = conn.raddr.port
                    event.details["remote_addr"] = f"{conn.raddr.ip}:{conn.raddr.port}"
                    break
        except (Exception):
            pass

"""
Sentinel Agent — TUI Scanner Bridge

Runs scans in a background thread and updates TUI state in real time.
This decouples the scan execution from the UI rendering loop so the
dashboard remains responsive during long-running scans.
"""

from __future__ import annotations

import threading
from datetime import datetime

from core.config import AgentConfig
from core.agent import SentinelAgent
from tui.state import TUIState


class ScannerBridge:
    """Runs scans in a background thread and updates TUI state."""

    def __init__(self, config: AgentConfig, state: TUIState) -> None:
        self.config = config
        self.state = state
        self._thread: threading.Thread | None = None

    def start_scan(self) -> None:
        """Start a scan in a background thread.

        Does nothing if a scan is already in progress.
        """
        if self.state.scan_in_progress:
            return
        self.state.scan_in_progress = True
        self.state.status_message = "Scanning..."
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        """Execute the scan and update state with results."""
        try:
            agent = SentinelAgent(self.config)
            result = agent.scan()
            self.state.update_from_result(result)
            self.state.last_scan_time = datetime.now().strftime("%H:%M:%S")
            self.state.status_message = "Scan complete"
        except Exception as exc:
            self.state.status_message = f"Scan failed: {exc}"
        finally:
            self.state.scan_in_progress = False

    @property
    def is_running(self) -> bool:
        """Return whether a scan is currently in progress."""
        return self.state.scan_in_progress

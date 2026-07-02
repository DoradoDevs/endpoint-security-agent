"""
Sentinel Agent — TUI Dashboard Application

Interactive terminal dashboard using Rich Live display with keyboard navigation.
Provides real-time security posture visualization with panel-based navigation.

Usage:
    sentinel --tui        Launch the interactive dashboard
    sentinel --dashboard  (alias)

Keyboard controls:
    s     Start a new scan
    Tab   Switch to next panel
    1-4   Jump to specific panel
    f     Cycle severity filter
    q     Quit
"""

from __future__ import annotations

import sys
import time

from rich.console import Console
from rich.live import Live
from rich.layout import Layout

from core.config import AgentConfig
from tui.state import TUIState
from tui.panels import (
    render_header,
    render_overview,
    render_findings,
    render_scanners,
    render_actions,
    render_footer,
)
from tui.scanner_bridge import ScannerBridge


class TUIApp:
    """Interactive terminal dashboard using Rich Live.

    The app runs a main loop that:
    1. Renders the current layout based on active panel
    2. Polls for keyboard input (non-blocking, platform-specific)
    3. Dispatches key events to state mutations
    4. Re-renders at ~4 FPS via Rich Live
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.state = TUIState()
        self.console = Console()
        self.bridge = ScannerBridge(config, self.state)
        self._running = False

    def run(self) -> None:
        """Main event loop with keyboard input and live rendering."""
        self._running = True

        # Build layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        try:
            with Live(
                layout,
                console=self.console,
                refresh_per_second=4,
                screen=True,
            ) as live:
                while self._running:
                    # Update layout panels
                    layout["header"].update(render_header(self.state))
                    layout["footer"].update(render_footer(self.state))

                    # Render active panel in body
                    if self.state.active_panel == 0:
                        layout["body"].update(render_overview(self.state))
                    elif self.state.active_panel == 1:
                        layout["body"].update(render_findings(self.state))
                    elif self.state.active_panel == 2:
                        layout["body"].update(render_scanners(self.state))
                    else:
                        layout["body"].update(render_actions(self.state))

                    # Check for keyboard input (non-blocking)
                    key = self._get_key()
                    if key:
                        self._handle_key(key)

                    time.sleep(0.1)
        except KeyboardInterrupt:
            pass

    def _handle_key(self, key: str) -> None:
        """Process keyboard input and update state accordingly."""
        if key == "q":
            self._running = False
        elif key == "\t":  # Tab key
            self.state.active_panel = (
                (self.state.active_panel + 1) % len(self.state.panel_names)
            )
        elif key == "s":
            self.bridge.start_scan()
        elif key == "f":
            # Cycle severity filter
            filters = ["all", "critical", "high", "medium", "low"]
            idx = filters.index(self.state.severity_filter)
            self.state.severity_filter = filters[(idx + 1) % len(filters)]
        elif key == "1":
            self.state.active_panel = 0
        elif key == "2":
            self.state.active_panel = 1
        elif key == "3":
            self.state.active_panel = 2
        elif key == "4":
            self.state.active_panel = 3

    def _get_key(self) -> str | None:
        """Non-blocking keyboard input. Platform-specific.

        Returns a single character if a key was pressed, or None if no input
        is available. Uses msvcrt on Windows and termios/select on Unix.
        """
        try:
            if sys.platform == "win32":
                import msvcrt

                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    return ch
            else:
                import select
                import termios
                import tty

                old = termios.tcgetattr(sys.stdin)
                try:
                    tty.setcbreak(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0.0)[0]:
                        return sys.stdin.read(1)
                finally:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        except Exception:
            pass
        return None

"""
Sentinel Agent — Process Ancestry Tracker

Maintains a live process tree that tracks parent-child relationships
across the lifetime of a monitoring session. This enables:
- Full attack chain reconstruction (who spawned whom)
- Ancestor analysis (was this process spawned by Office? By a browser?)
- Descendant tracking (what did this malware spawn?)
- Process lineage scoring (how suspicious is the full chain?)

Unlike point-in-time snapshots, this tracker accumulates history —
so even after a parent process exits, its children retain their
ancestry information.

SECURITY: Read-only. We observe process relationships but never
modify, inject into, or terminate any process.
"""

from __future__ import annotations

import platform
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


# ---------------------------------------------------------------------------
# Process node
# ---------------------------------------------------------------------------

@dataclass
class ProcessNode:
    """A single node in the process tree."""
    pid: int
    ppid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    user: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    children: list[int] = field(default_factory=list)
    severity_score: float = 0.0
    tags: set[str] = field(default_factory=set)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_alive(self) -> bool:
        return self.end_time == ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "user": self.user,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "children": self.children,
            "severity_score": self.severity_score,
            "tags": list(self.tags),
            "is_alive": self.is_alive,
        }


# ---------------------------------------------------------------------------
# Suspicious ancestry patterns
# ---------------------------------------------------------------------------

# Office apps spawning shells — classic macro malware
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
               "msaccess.exe", "mspub.exe", "onenote.exe"}

# Shells and scripting engines
SHELL_EXECUTABLES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                     "cscript.exe", "mshta.exe", "bash", "sh", "zsh"}

# Browser processes
BROWSER_APPS = {"chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
                "iexplore.exe", "brave.exe", "safari"}

# Living-off-the-land binaries (LOLBins)
LOLBINS = {"certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
           "mshta.exe", "msiexec.exe", "cmstp.exe", "installutil.exe",
           "regasm.exe", "regsvcs.exe", "msbuild.exe", "xwizard.exe",
           "syncappvpublishingserver.exe", "forfiles.exe", "pcalua.exe"}

# Known credential tools
CREDENTIAL_TOOLS = {"mimikatz.exe", "procdump.exe", "rubeus.exe",
                    "lazagne.exe", "secretsdump.py", "hashcat.exe",
                    "john.exe"}

# Remote access tools
RAT_TOOLS = {"psexec.exe", "psexec64.exe", "winrs.exe", "wmic.exe",
             "ssh.exe", "nc.exe", "ncat.exe", "plink.exe"}


# ---------------------------------------------------------------------------
# Process Tree Tracker
# ---------------------------------------------------------------------------

class ProcessTree:
    """Maintains a live process tree with ancestry tracking.

    Thread-safe: designed to be updated from multiple monitor threads.
    """

    def __init__(self, max_history: int = 10000):
        self._lock = threading.Lock()
        self._nodes: dict[int, ProcessNode] = {}
        self._max_history = max_history
        self.log = get_logger()

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def on_event(self, event: EDREvent) -> None:
        """Process an EDR event to update the tree."""
        if event.event_type == EDREventType.PROCESS_START:
            self._add_process(event)
        elif event.event_type == EDREventType.PROCESS_STOP:
            self._mark_terminated(event.source_pid)

    def _add_process(self, event: EDREvent) -> None:
        """Add a new process to the tree."""
        pid = event.source_pid
        ppid = event.details.get("ppid", 0)
        name = event.source_process
        exe = event.target or ""
        cmdline = event.details.get("cmdline", "")
        user = event.details.get("user", "")

        node = ProcessNode(
            pid=pid, ppid=ppid, name=name, exe=exe,
            cmdline=cmdline, user=user,
        )

        # Tag the process based on its characteristics
        self._tag_process(node)

        with self._lock:
            self._nodes[pid] = node

            # Link to parent
            if ppid in self._nodes:
                parent = self._nodes[ppid]
                if pid not in parent.children:
                    parent.children.append(pid)

            # Prune if too large
            if len(self._nodes) > self._max_history:
                self._prune_oldest()

    def _mark_terminated(self, pid: int) -> None:
        """Mark a process as terminated (but keep in tree for history)."""
        with self._lock:
            if pid in self._nodes:
                self._nodes[pid].end_time = datetime.now().isoformat()

    # ------------------------------------------------------------------
    # Process tagging
    # ------------------------------------------------------------------

    def _tag_process(self, node: ProcessNode) -> None:
        """Apply security-relevant tags to a process."""
        name_lower = node.name.lower()
        exe_lower = node.exe.lower()

        if name_lower in OFFICE_APPS:
            node.tags.add("office")
        if name_lower in SHELL_EXECUTABLES:
            node.tags.add("shell")
        if name_lower in BROWSER_APPS:
            node.tags.add("browser")
        if name_lower in LOLBINS:
            node.tags.add("lolbin")
        if name_lower in CREDENTIAL_TOOLS:
            node.tags.add("credential_tool")
            node.severity_score += 8.0
        if name_lower in RAT_TOOLS:
            node.tags.add("rat_tool")
            node.severity_score += 6.0

        # Check for temp directory execution
        temp_markers = ["\\temp\\", "\\tmp\\", "/tmp/", "/var/tmp/",
                        "\\appdata\\local\\temp\\"]
        if any(m in exe_lower for m in temp_markers):
            node.tags.add("temp_dir")
            node.severity_score += 3.0

        # Check for unsigned / unknown location
        if exe_lower and not any(
            exe_lower.startswith(d) for d in
            ["c:\\windows\\", "c:\\program files", "/usr/", "/bin/", "/sbin/"]
        ):
            node.tags.add("non_standard_path")
            node.severity_score += 1.0

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_ancestors(self, pid: int) -> list[ProcessNode]:
        """Get the full ancestor chain for a process (child → root)."""
        ancestors: list[ProcessNode] = []
        seen: set[int] = set()

        with self._lock:
            current_pid = pid
            while current_pid in self._nodes:
                if current_pid in seen:
                    break  # Prevent cycles
                seen.add(current_pid)
                node = self._nodes[current_pid]
                ancestors.append(node)
                current_pid = node.ppid

        return ancestors

    def get_descendants(self, pid: int) -> list[ProcessNode]:
        """Get all descendants of a process (BFS)."""
        descendants: list[ProcessNode] = []

        with self._lock:
            queue = [pid]
            seen: set[int] = {pid}

            while queue:
                current = queue.pop(0)
                if current in self._nodes:
                    for child_pid in self._nodes[current].children:
                        if child_pid not in seen:
                            seen.add(child_pid)
                            if child_pid in self._nodes:
                                descendants.append(self._nodes[child_pid])
                                queue.append(child_pid)

        return descendants

    def get_chain_score(self, pid: int) -> float:
        """Calculate a cumulative severity score for the full process chain."""
        ancestors = self.get_ancestors(pid)
        if not ancestors:
            return 0.0

        score = 0.0
        for node in ancestors:
            score += node.severity_score

        # Bonus for suspicious patterns
        tags_in_chain = set()
        for node in ancestors:
            tags_in_chain.update(node.tags)

        # Office → Shell is a strong malware indicator
        if "office" in tags_in_chain and "shell" in tags_in_chain:
            score += 15.0

        # Browser → Shell → Temp is a drive-by download
        if "browser" in tags_in_chain and "shell" in tags_in_chain and "temp_dir" in tags_in_chain:
            score += 12.0

        # LOLBin usage in chain
        if "lolbin" in tags_in_chain:
            score += 5.0

        # Credential tool in chain
        if "credential_tool" in tags_in_chain:
            score += 10.0

        return score

    def analyze_chain(self, pid: int) -> dict[str, Any]:
        """Full analysis of a process and its ancestry."""
        ancestors = self.get_ancestors(pid)
        descendants = self.get_descendants(pid)
        chain_score = self.get_chain_score(pid)

        # Collect all tags across the chain
        all_tags: set[str] = set()
        for node in ancestors + descendants:
            all_tags.update(node.tags)

        # Determine attack pattern
        patterns: list[str] = []
        tag_set = all_tags
        if "office" in tag_set and "shell" in tag_set:
            patterns.append("macro_execution")
        if "browser" in tag_set and "temp_dir" in tag_set:
            patterns.append("drive_by_download")
        if "credential_tool" in tag_set:
            patterns.append("credential_theft")
        if "rat_tool" in tag_set:
            patterns.append("lateral_movement")
        if "lolbin" in tag_set:
            patterns.append("lolbin_abuse")

        return {
            "pid": pid,
            "ancestors": [n.to_dict() for n in ancestors],
            "descendants": [n.to_dict() for n in descendants],
            "ancestor_count": len(ancestors),
            "descendant_count": len(descendants),
            "chain_score": chain_score,
            "chain_tags": list(all_tags),
            "attack_patterns": patterns,
            "chain_depth": len(ancestors),
        }

    def get_node(self, pid: int) -> ProcessNode | None:
        """Get a single process node."""
        with self._lock:
            return self._nodes.get(pid)

    def get_suspicious_chains(self, min_score: float = 10.0) -> list[dict[str, Any]]:
        """Find all process chains with a severity score above threshold."""
        results: list[dict[str, Any]] = []

        with self._lock:
            leaf_pids = [
                pid for pid, node in self._nodes.items()
                if not node.children and node.is_alive
            ]

        for pid in leaf_pids:
            score = self.get_chain_score(pid)
            if score >= min_score:
                results.append(self.analyze_chain(pid))

        results.sort(key=lambda x: x["chain_score"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _prune_oldest(self) -> None:
        """Remove oldest terminated processes to stay within limits."""
        terminated = [
            (pid, node) for pid, node in self._nodes.items()
            if not node.is_alive
        ]
        terminated.sort(key=lambda x: x[1].end_time)

        to_remove = len(self._nodes) - self._max_history
        for pid, _ in terminated[:to_remove]:
            del self._nodes[pid]

    def get_stats(self) -> dict[str, Any]:
        """Return tree statistics."""
        with self._lock:
            alive = sum(1 for n in self._nodes.values() if n.is_alive)
            terminated = sum(1 for n in self._nodes.values() if not n.is_alive)
            return {
                "total_tracked": len(self._nodes),
                "alive": alive,
                "terminated": terminated,
            }

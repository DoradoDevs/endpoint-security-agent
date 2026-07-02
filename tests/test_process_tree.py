"""
Tests for the Process Ancestry Tracker.

Covers process tree building, ancestry queries, chain scoring,
attack pattern detection, and thread safety.
"""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.event_types import EDREvent, EDREventType
from edr.process_tree import (
    ProcessTree, ProcessNode,
    OFFICE_APPS, SHELL_EXECUTABLES, LOLBINS, CREDENTIAL_TOOLS,
)


def _make_process_event(pid, ppid, name, exe="", cmdline=""):
    return EDREvent(
        event_type=EDREventType.PROCESS_START,
        source_pid=pid,
        source_process=name,
        target=exe,
        details={"ppid": ppid, "cmdline": cmdline},
    )


class TestProcessTreeBasic:
    """Basic tree operations."""

    def test_add_process(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "test.exe"))
        node = tree.get_node(100)
        assert node is not None
        assert node.name == "test.exe"
        assert node.is_alive

    def test_terminate_process(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "test.exe"))
        tree.on_event(EDREvent(event_type=EDREventType.PROCESS_STOP, source_pid=100))
        node = tree.get_node(100)
        assert node is not None
        assert not node.is_alive

    def test_parent_child_linking(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(1, 0, "init"))
        tree.on_event(_make_process_event(100, 1, "parent.exe"))
        tree.on_event(_make_process_event(200, 100, "child.exe"))

        parent = tree.get_node(100)
        assert 200 in parent.children

    def test_stats(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "a.exe"))
        tree.on_event(_make_process_event(200, 1, "b.exe"))
        tree.on_event(EDREvent(event_type=EDREventType.PROCESS_STOP, source_pid=200))

        stats = tree.get_stats()
        assert stats["total_tracked"] == 2
        assert stats["alive"] == 1
        assert stats["terminated"] == 1


class TestAncestryQueries:
    """Test ancestry and descendant queries."""

    def test_get_ancestors(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(1, 0, "init"))
        tree.on_event(_make_process_event(100, 1, "explorer.exe"))
        tree.on_event(_make_process_event(200, 100, "cmd.exe"))
        tree.on_event(_make_process_event(300, 200, "powershell.exe"))

        ancestors = tree.get_ancestors(300)
        names = [a.name for a in ancestors]
        assert names == ["powershell.exe", "cmd.exe", "explorer.exe", "init"]

    def test_get_descendants(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "parent.exe"))
        tree.on_event(_make_process_event(200, 100, "child1.exe"))
        tree.on_event(_make_process_event(300, 100, "child2.exe"))
        tree.on_event(_make_process_event(400, 200, "grandchild.exe"))

        descendants = tree.get_descendants(100)
        pids = {d.pid for d in descendants}
        assert pids == {200, 300, 400}

    def test_no_ancestors_for_root(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(1, 0, "init"))
        ancestors = tree.get_ancestors(1)
        assert len(ancestors) == 1  # Just itself


class TestChainScoring:
    """Test process chain severity scoring."""

    def test_office_to_shell_high_score(self):
        """Office spawning a shell should produce a high chain score."""
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "winword.exe",
                                           exe="C:\\Program Files\\Office\\winword.exe"))
        tree.on_event(_make_process_event(200, 100, "cmd.exe",
                                           exe="C:\\Windows\\System32\\cmd.exe"))
        tree.on_event(_make_process_event(300, 200, "powershell.exe",
                                           exe="C:\\Windows\\System32\\powershell.exe"))

        score = tree.get_chain_score(300)
        assert score >= 15.0  # Office→Shell bonus

    def test_credential_tool_high_score(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "cmd.exe"))
        tree.on_event(_make_process_event(200, 100, "mimikatz.exe",
                                           exe="C:\\temp\\mimikatz.exe"))

        score = tree.get_chain_score(200)
        assert score >= 10.0  # credential_tool + temp_dir

    def test_clean_chain_low_score(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "explorer.exe",
                                           exe="C:\\Windows\\explorer.exe"))
        tree.on_event(_make_process_event(200, 100, "notepad.exe",
                                           exe="C:\\Windows\\System32\\notepad.exe"))

        score = tree.get_chain_score(200)
        assert score < 5.0

    def test_temp_dir_adds_score(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "dropper.exe",
                                           exe="C:\\Users\\victim\\AppData\\Local\\Temp\\dropper.exe"))
        node = tree.get_node(100)
        assert "temp_dir" in node.tags
        assert node.severity_score >= 3.0


class TestChainAnalysis:
    """Test full chain analysis."""

    def test_analyze_macro_attack(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "winword.exe"))
        tree.on_event(_make_process_event(200, 100, "powershell.exe"))
        tree.on_event(_make_process_event(300, 200, "mimikatz.exe",
                                           exe="C:\\temp\\mimikatz.exe"))

        analysis = tree.analyze_chain(300)
        assert "macro_execution" in analysis["attack_patterns"]
        assert "credential_theft" in analysis["attack_patterns"]
        assert analysis["chain_score"] > 20.0

    def test_get_suspicious_chains(self):
        tree = ProcessTree()
        # Suspicious chain
        tree.on_event(_make_process_event(100, 1, "excel.exe"))
        tree.on_event(_make_process_event(200, 100, "cmd.exe"))
        # Clean chain
        tree.on_event(_make_process_event(300, 1, "notepad.exe",
                                           exe="C:\\Windows\\notepad.exe"))

        suspicious = tree.get_suspicious_chains(min_score=10.0)
        assert len(suspicious) >= 1
        assert suspicious[0]["pid"] == 200


class TestProcessTagging:
    """Test automatic process tagging."""

    def test_office_tagged(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "winword.exe"))
        assert "office" in tree.get_node(100).tags

    def test_shell_tagged(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "powershell.exe"))
        assert "shell" in tree.get_node(100).tags

    def test_lolbin_tagged(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "certutil.exe"))
        assert "lolbin" in tree.get_node(100).tags

    def test_non_standard_path_tagged(self):
        tree = ProcessTree()
        tree.on_event(_make_process_event(100, 1, "suspicious.exe",
                                           exe="D:\\custom\\suspicious.exe"))
        assert "non_standard_path" in tree.get_node(100).tags


class TestThreadSafety:
    """Test concurrent access to the process tree."""

    def test_concurrent_updates(self):
        tree = ProcessTree()

        def add_processes(start_pid):
            for i in range(50):
                tree.on_event(_make_process_event(
                    start_pid + i, 1, f"proc_{start_pid + i}.exe"))

        threads = [threading.Thread(target=add_processes, args=(t * 1000,))
                   for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        stats = tree.get_stats()
        assert stats["total_tracked"] == 250

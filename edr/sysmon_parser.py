"""
Sentinel Agent — Sysmon Event Log Parser

Parses Microsoft Sysmon (System Monitor) event logs for enriched
security telemetry. Sysmon provides detailed process creation,
network connection, file creation, and driver loading events that
go far beyond standard Windows event logs.

Sysmon Event IDs:
  1  - Process creation (full command line, hashes, parent process)
  3  - Network connection (source/dest IP, port, process)
  5  - Process terminated
  7  - Image loaded (DLL loading)
  8  - CreateRemoteThread (process injection indicator)
  10 - ProcessAccess (LSASS access = credential theft)
  11 - File created
  12 - Registry event (create/delete key)
  13 - Registry event (value set)
  15 - FileCreateStreamHash (ADS creation)
  22 - DNS query
  23 - File delete (archived)
  25 - Process tampering

SECURITY: Read-only. We only read Sysmon event logs, never modify them.

DEPENDENCY: Requires Sysmon to be installed on the system.
Install from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
"""

from __future__ import annotations

import platform
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Callable

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


# Sysmon Event IDs we care about
SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_PROCESS_TERMINATE = 5
SYSMON_IMAGE_LOAD = 7
SYSMON_CREATE_REMOTE_THREAD = 8
SYSMON_PROCESS_ACCESS = 10
SYSMON_FILE_CREATE = 11
SYSMON_REGISTRY_EVENT = 12
SYSMON_REGISTRY_VALUE = 13
SYSMON_DNS_QUERY = 22
SYSMON_PROCESS_TAMPERING = 25


class SysmonParser:
    """Parses Sysmon event logs for enriched security telemetry.

    Continuously reads new Sysmon events from the Windows Event Log
    and converts them to EDREvent objects for the correlation engine.
    """

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
        self._is_windows = platform.system().lower() == "windows"
        self._last_record_id = 0
        self._sysmon_available = False
        self._events_processed = 0

    def start(self, stop_event: threading.Event) -> None:
        """Start Sysmon log monitoring. Blocks until stop_event is set."""
        if not self._is_windows:
            self.log.debug("[Sysmon] Not on Windows, skipping")
            return

        if not self._check_sysmon_installed():
            self.log.info("[Sysmon] Sysmon not installed — skipping. "
                          "Install from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon")
            return

        self._sysmon_available = True
        self.log.info("[Sysmon] Starting Sysmon event log parser")

        # Get initial record ID to avoid processing old events
        self._last_record_id = self._get_latest_record_id()

        while not stop_event.is_set():
            stop_event.wait(timeout=2.0)
            if stop_event.is_set():
                break
            self._poll_sysmon_events()

    # ------------------------------------------------------------------
    # Sysmon detection
    # ------------------------------------------------------------------

    def _check_sysmon_installed(self) -> bool:
        """Check if Sysmon is installed by querying the event log."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                 "-MaxEvents 1 -ErrorAction Stop | Select-Object -ExpandProperty Id"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_latest_record_id(self) -> int:
        """Get the latest Sysmon event record ID."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                 "-MaxEvents 1 -ErrorAction Stop | "
                 "Select-Object -ExpandProperty RecordId"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, OSError):
            pass
        return 0

    # ------------------------------------------------------------------
    # Event polling
    # ------------------------------------------------------------------

    def _poll_sysmon_events(self) -> None:
        """Poll for new Sysmon events since last check."""
        try:
            # Query events newer than our last known record
            ps_cmd = (
                f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                f"-FilterXPath '*[System[EventRecordID > {self._last_record_id}]]' "
                f"-MaxEvents 100 -ErrorAction SilentlyContinue | "
                f"Select-Object Id,RecordId,TimeCreated,Message,@{{N='XML';E={{$_.ToXml()}}}} | "
                f"ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )

            if result.returncode != 0 or not result.stdout.strip():
                return

            try:
                data = self._parse_json_safe(result.stdout.strip())
            except Exception:
                return

            if isinstance(data, dict):
                data = [data]

            for entry in data:
                record_id = entry.get("RecordId", 0)
                if record_id > self._last_record_id:
                    self._last_record_id = record_id

                event_id = entry.get("Id", 0)
                xml_str = entry.get("XML", "")

                if xml_str:
                    self._process_sysmon_event(event_id, xml_str)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self.log.debug(f"[Sysmon] Poll error: {exc}")

    def _process_sysmon_event(self, event_id: int, xml_str: str) -> None:
        """Parse a Sysmon XML event and convert to EDREvent."""
        try:
            fields = self._parse_sysmon_xml(xml_str)
        except ET.ParseError:
            return

        event: EDREvent | None = None

        if event_id == SYSMON_PROCESS_CREATE:
            event = self._handle_process_create(fields)
        elif event_id == SYSMON_NETWORK_CONNECT:
            event = self._handle_network_connect(fields)
        elif event_id == SYSMON_PROCESS_TERMINATE:
            event = self._handle_process_terminate(fields)
        elif event_id == SYSMON_CREATE_REMOTE_THREAD:
            event = self._handle_remote_thread(fields)
        elif event_id == SYSMON_PROCESS_ACCESS:
            event = self._handle_process_access(fields)
        elif event_id == SYSMON_FILE_CREATE:
            event = self._handle_file_create(fields)
        elif event_id == SYSMON_DNS_QUERY:
            event = self._handle_dns_query(fields)
        elif event_id == SYSMON_PROCESS_TAMPERING:
            event = self._handle_process_tampering(fields)

        if event and self._on_event:
            self._events_processed += 1
            self._on_event(event)

    # ------------------------------------------------------------------
    # Sysmon event handlers
    # ------------------------------------------------------------------

    def _handle_process_create(self, f: dict) -> EDREvent:
        """Sysmon Event 1: Process Creation."""
        severity = "info"
        details = {
            "cmdline": f.get("CommandLine", ""),
            "ppid": int(f.get("ParentProcessId", 0)),
            "parent_image": f.get("ParentImage", ""),
            "parent_cmdline": f.get("ParentCommandLine", ""),
            "user": f.get("User", ""),
            "integrity_level": f.get("IntegrityLevel", ""),
            "hashes": f.get("Hashes", ""),
            "current_directory": f.get("CurrentDirectory", ""),
            "logon_guid": f.get("LogonGuid", ""),
            "source": "sysmon",
        }

        # Check for IOC hash match
        hashes = f.get("Hashes", "")
        if hashes and self._ioc_db:
            for hash_pair in hashes.split(","):
                if "=" in hash_pair:
                    algo, hash_val = hash_pair.split("=", 1)
                    if algo.strip().upper() == "SHA256":
                        match = self._ioc_db.lookup_hash(hash_val.strip().lower())
                        if match:
                            severity = "critical"
                            details["ioc_match"] = True
                            details["ioc_hash"] = hash_val.strip()

        return EDREvent(
            event_type=EDREventType.PROCESS_START,
            source_pid=int(f.get("ProcessId", 0)),
            source_process=f.get("Image", "").split("\\")[-1],
            target=f.get("Image", ""),
            severity=severity,
            details=details,
        )

    def _handle_network_connect(self, f: dict) -> EDREvent:
        """Sysmon Event 3: Network Connection."""
        remote_ip = f.get("DestinationIp", "")
        remote_port = int(f.get("DestinationPort", 0))
        severity = "info"
        details = {
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "source_ip": f.get("SourceIp", ""),
            "source_port": int(f.get("SourcePort", 0)),
            "protocol": f.get("Protocol", ""),
            "initiated": f.get("Initiated", ""),
            "user": f.get("User", ""),
            "source": "sysmon",
        }

        if self._ioc_db and remote_ip:
            match = self._ioc_db.lookup_ip(remote_ip)
            if match:
                severity = "critical"
                details["ioc_match"] = True

        return EDREvent(
            event_type=EDREventType.NETWORK_CONNECT,
            source_pid=int(f.get("ProcessId", 0)),
            source_process=f.get("Image", "").split("\\")[-1],
            target=f"{remote_ip}:{remote_port}",
            severity=severity,
            details=details,
        )

    def _handle_process_terminate(self, f: dict) -> EDREvent:
        """Sysmon Event 5: Process Terminated."""
        return EDREvent(
            event_type=EDREventType.PROCESS_STOP,
            source_pid=int(f.get("ProcessId", 0)),
            source_process=f.get("Image", "").split("\\")[-1],
            severity="info",
            details={"source": "sysmon"},
        )

    def _handle_remote_thread(self, f: dict) -> EDREvent:
        """Sysmon Event 8: CreateRemoteThread — potential injection."""
        return EDREvent(
            event_type=EDREventType.PROCESS_START,
            source_pid=int(f.get("SourceProcessId", 0)),
            source_process=f.get("SourceImage", "").split("\\")[-1],
            target=f.get("TargetImage", ""),
            severity="high",
            details={
                "target_pid": int(f.get("TargetProcessId", 0)),
                "target_image": f.get("TargetImage", ""),
                "start_address": f.get("StartAddress", ""),
                "start_module": f.get("StartModule", ""),
                "start_function": f.get("StartFunction", ""),
                "injection_indicator": True,
                "source": "sysmon",
            },
        )

    def _handle_process_access(self, f: dict) -> EDREvent:
        """Sysmon Event 10: ProcessAccess — credential theft indicator."""
        target_image = f.get("TargetImage", "").lower()
        severity = "medium"

        # LSASS access is a strong credential theft indicator
        if "lsass.exe" in target_image:
            severity = "critical"

        return EDREvent(
            event_type=EDREventType.PRIVILEGE_ESCALATION,
            source_pid=int(f.get("SourceProcessId", 0)),
            source_process=f.get("SourceImage", "").split("\\")[-1],
            target=f.get("TargetImage", ""),
            severity=severity,
            details={
                "target_pid": int(f.get("TargetProcessId", 0)),
                "granted_access": f.get("GrantedAccess", ""),
                "call_trace": f.get("CallTrace", ""),
                "lsass_access": "lsass.exe" in target_image,
                "source": "sysmon",
            },
        )

    def _handle_file_create(self, f: dict) -> EDREvent:
        """Sysmon Event 11: File Creation."""
        return EDREvent(
            event_type=EDREventType.FILE_CREATE,
            source_pid=int(f.get("ProcessId", 0)),
            source_process=f.get("Image", "").split("\\")[-1],
            target=f.get("TargetFilename", ""),
            severity="info",
            details={
                "creation_utc_time": f.get("CreationUtcTime", ""),
                "source": "sysmon",
            },
        )

    def _handle_dns_query(self, f: dict) -> EDREvent:
        """Sysmon Event 22: DNS Query."""
        domain = f.get("QueryName", "")
        severity = "info"
        details: dict[str, Any] = {
            "dns_query": domain,
            "query_type": f.get("QueryType", ""),
            "query_status": f.get("QueryStatus", ""),
            "query_results": f.get("QueryResults", ""),
            "source": "sysmon",
        }

        if self._ioc_db and domain:
            match = self._ioc_db.lookup_domain(domain)
            if match:
                severity = "critical"
                details["ioc_match"] = True
                details["detection"] = "ioc_domain_match"

        return EDREvent(
            event_type=EDREventType.NETWORK_CONNECT,
            source_pid=int(f.get("ProcessId", 0)),
            source_process=f.get("Image", "").split("\\")[-1],
            target=domain,
            severity=severity,
            details=details,
        )

    def _handle_process_tampering(self, f: dict) -> EDREvent:
        """Sysmon Event 25: Process Tampering."""
        return EDREvent(
            event_type=EDREventType.THREAT_DETECTED,
            source_pid=int(f.get("ProcessId", 0)),
            source_process=f.get("Image", "").split("\\")[-1],
            severity="critical",
            details={
                "tampering_type": f.get("Type", ""),
                "source": "sysmon",
            },
        )

    # ------------------------------------------------------------------
    # XML parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_sysmon_xml(xml_str: str) -> dict[str, str]:
        """Extract EventData fields from Sysmon XML."""
        fields: dict[str, str] = {}
        try:
            root = ET.fromstring(xml_str)
            # Sysmon uses namespace
            ns = {"": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for data_elem in root.iter():
                if data_elem.tag.endswith("Data"):
                    name = data_elem.get("Name", "")
                    if name:
                        fields[name] = data_elem.text or ""
        except ET.ParseError:
            pass
        return fields

    @staticmethod
    def _parse_json_safe(text: str) -> Any:
        """Parse JSON, handling PowerShell output quirks."""
        import json
        # PowerShell sometimes outputs BOM or trailing whitespace
        text = text.strip().lstrip("\ufeff")
        return json.loads(text)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return parser statistics."""
        return {
            "sysmon_available": self._sysmon_available,
            "events_processed": self._events_processed,
            "last_record_id": self._last_record_id,
        }

"""
Sentinel Agent — SIEM/Webhook Integration

Forwards security findings and EDR events to SIEM systems via
webhooks and syslog in CEF/LEEF format.
"""

from __future__ import annotations

import json
import socket
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.config import AgentConfig
from core.logging import get_logger


@dataclass
class SIEMConfig:
    webhook_url: str = ""
    webhook_auth_header: str = ""  # e.g. "Authorization: Bearer <token>"
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp or tcp
    syslog_format: str = "cef"  # cef or leef
    forward_min_severity: str = "low"
    retry_attempts: int = 3
    retry_delay: float = 2.0


class SIEMIntegration:
    """Forwards findings and events to SIEM systems."""

    def __init__(self, config: SIEMConfig | None = None):
        self.config = config or SIEMConfig()
        self.log = get_logger()
        self._forwarded_count = 0
        self._error_count = 0

    def forward_finding(self, finding, device_info: dict | None = None) -> bool:
        """Forward a security finding to configured SIEM destinations."""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        finding_sev = getattr(finding, 'severity', None)
        sev_str = finding_sev.value if hasattr(finding_sev, 'value') else str(finding_sev).lower()
        min_sev = severity_order.get(self.config.forward_min_severity, 0)

        if severity_order.get(sev_str, 0) < min_sev:
            return False  # Below threshold

        payload = self._finding_to_payload(finding, device_info)
        success = False

        if self.config.webhook_url:
            success = self._send_webhook(payload) or success

        if self.config.syslog_host:
            syslog_msg = self._format_syslog(finding, device_info)
            success = self._send_syslog(syslog_msg) or success

        if success:
            self._forwarded_count += 1
        return success

    def forward_event(self, event, device_info: dict | None = None) -> bool:
        """Forward an EDR event to SIEM."""
        payload = {
            "event_type": "edr_event",
            "timestamp": getattr(event, 'timestamp', datetime.now().isoformat()),
            "event_id": getattr(event, 'id', ''),
            "type": event.event_type.value if hasattr(event, 'event_type') else str(event),
            "source_process": getattr(event, 'source_process', ''),
            "source_pid": getattr(event, 'source_pid', 0),
            "target": getattr(event, 'target', ''),
            "severity": getattr(event, 'severity', 'info'),
            "details": getattr(event, 'details', {}),
        }
        if device_info:
            payload["device"] = device_info

        success = False
        if self.config.webhook_url:
            success = self._send_webhook(payload)
        if self.config.syslog_host:
            msg = self._format_cef_event(event)
            success = self._send_syslog(msg) or success
        return success

    def _finding_to_payload(self, finding, device_info) -> dict:
        """Convert finding to webhook payload."""
        return {
            "event_type": "security_finding",
            "timestamp": datetime.now().isoformat(),
            "finding": {
                "title": getattr(finding, 'title', ''),
                "description": getattr(finding, 'description', ''),
                "severity": getattr(finding, 'severity', 'info').value if hasattr(getattr(finding, 'severity', ''), 'value') else str(getattr(finding, 'severity', 'info')),
                "category": getattr(finding, 'category', ''),
                "scanner": getattr(finding, 'scanner', ''),
                "evidence": getattr(finding, 'evidence', {}),
                "remediation": getattr(finding, 'remediation', ''),
            },
            "device": device_info or {},
        }

    def _send_webhook(self, payload: dict) -> bool:
        """Send payload to webhook URL with retry."""
        for attempt in range(self.config.retry_attempts):
            try:
                import urllib.request
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(
                    self.config.webhook_url,
                    data=data,
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                )
                if self.config.webhook_auth_header:
                    parts = self.config.webhook_auth_header.split(":", 1)
                    if len(parts) == 2:
                        req.add_header(parts[0].strip(), parts[1].strip())

                urllib.request.urlopen(req, timeout=10)
                return True
            except Exception as e:
                self.log.debug(f"[SIEM] Webhook attempt {attempt+1} failed: {e}")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay * (2 ** attempt))

        self._error_count += 1
        return False

    def _send_syslog(self, message: str) -> bool:
        """Send syslog message."""
        try:
            if self.config.syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.config.syslog_host, self.config.syslog_port))
                sock.sendall(message.encode('utf-8'))
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode('utf-8'), (self.config.syslog_host, self.config.syslog_port))
                sock.close()
            return True
        except Exception as e:
            self.log.debug(f"[SIEM] Syslog failed: {e}")
            self._error_count += 1
            return False

    def _format_syslog(self, finding, device_info) -> str:
        """Format finding as syslog message."""
        if self.config.syslog_format == "leef":
            return self._format_leef(finding, device_info)
        return self._format_cef(finding, device_info)

    def _format_cef(self, finding, device_info) -> str:
        """Format as CEF (Common Event Format)."""
        sev_map = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}
        sev = getattr(finding, 'severity', 'info')
        sev_str = sev.value if hasattr(sev, 'value') else str(sev).lower()
        sev_num = sev_map.get(sev_str, 0)

        title = getattr(finding, 'title', '').replace('|', '_')
        category = getattr(finding, 'category', '').replace('|', '_')

        return (
            f"CEF:0|Sentinel|SecurityAgent|4.0|{category}|{title}|{sev_num}|"
            f"msg={getattr(finding, 'description', '')[:200]} "
            f"cat={category}"
        )

    def _format_leef(self, finding, device_info) -> str:
        """Format as LEEF (Log Event Extended Format)."""
        sev = getattr(finding, 'severity', 'info')
        sev_str = sev.value if hasattr(sev, 'value') else str(sev).lower()
        sev_num = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}.get(sev_str, 0)

        return (
            f"LEEF:2.0|Sentinel|SecurityAgent|4.0|{getattr(finding, 'category', '')}|"
            f"sev={sev_num}\ttitle={getattr(finding, 'title', '')}\t"
            f"msg={getattr(finding, 'description', '')[:200]}"
        )

    def _format_cef_event(self, event) -> str:
        """Format EDR event as CEF."""
        sev_map = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}
        sev_num = sev_map.get(getattr(event, 'severity', 'info'), 0)
        evt_type = event.event_type.value if hasattr(event, 'event_type') else str(event)

        return (
            f"CEF:0|Sentinel|EDR|4.0|{evt_type}|EDR Event|{sev_num}|"
            f"src={getattr(event, 'source_process', '')} "
            f"dst={getattr(event, 'target', '')} "
            f"pid={getattr(event, 'source_pid', 0)}"
        )

    def get_stats(self) -> dict:
        return {"forwarded": self._forwarded_count, "errors": self._error_count}

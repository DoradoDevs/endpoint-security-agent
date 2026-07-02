"""
Sentinel Agent — Email Report Configuration

Re-exports email configuration dataclasses defined in core.config.
These are defined in core.config to avoid circular imports, since
multiple modules depend on these dataclasses.
"""

from __future__ import annotations

from core.config import SMTPConfig, EmailSchedule, EmailReportConfig

__all__ = ["SMTPConfig", "EmailSchedule", "EmailReportConfig"]

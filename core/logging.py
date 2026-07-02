"""
Sentinel Agent — Logging Infrastructure

All agent activity is logged transparently. No hidden operations.
Logs are structured, timestamped, and include operation context.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter for machine-parseable audit trails."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "message": record.getMessage(),
        }
        if hasattr(record, "scan_context"):
            entry["scan_context"] = record.scan_context
        if hasattr(record, "finding"):
            entry["finding"] = record.finding
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
        return json.dumps(entry)


class HumanFormatter(logging.Formatter):
    """Human-readable formatter for console output."""

    LEVEL_SYMBOLS = {
        "DEBUG": "DBG",
        "INFO": "INF",
        "WARNING": "WRN",
        "ERROR": "ERR",
        "CRITICAL": "CRT",
    }

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now().strftime("%H:%M:%S")
        sym = self.LEVEL_SYMBOLS.get(record.levelname, "???")
        return f"[{ts}] [{sym}] {record.getMessage()}"


_logger: logging.Logger | None = None


def init_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    """Initialize the global Sentinel logger with file and console handlers."""
    global _logger

    logger = logging.getLogger("sentinel")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # Console handler — human-readable
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(HumanFormatter())
    logger.addHandler(console)

    # File handler — structured JSON, one entry per line
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(StructuredFormatter())
    logger.addHandler(file_handler)

    _logger = logger
    logger.info(f"Sentinel logging initialized — log file: {log_file}")
    return logger


def get_logger() -> logging.Logger:
    """Get the Sentinel logger. Falls back to a basic logger if not initialized."""
    global _logger
    if _logger is None:
        _logger = logging.getLogger("sentinel")
        if not _logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(HumanFormatter())
            _logger.addHandler(handler)
            _logger.setLevel(logging.INFO)
    return _logger


def log_finding(severity: str, category: str, title: str, details: str, **extra: Any) -> None:
    """Log a security finding with structured context."""
    logger = get_logger()
    record = logger.makeRecord(
        name="sentinel",
        level=logging.WARNING if severity in ("critical", "high") else logging.INFO,
        fn="",
        lno=0,
        msg=f"[{severity.upper()}] [{category}] {title}: {details}",
        args=(),
        exc_info=None,
    )
    record.finding = {  # type: ignore[attr-defined]
        "severity": severity,
        "category": category,
        "title": title,
        "details": details,
        **extra,
    }
    logger.handle(record)


def log_action(action: str, target: str, result: str, dry_run: bool = False) -> None:
    """Log a remediation or hardening action."""
    logger = get_logger()
    prefix = "[DRY-RUN] " if dry_run else ""
    logger.info(f"{prefix}ACTION: {action} on {target} — {result}")

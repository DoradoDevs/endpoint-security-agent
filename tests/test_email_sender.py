"""Tests for email report delivery — config, sender, and scheduler."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.config import SMTPConfig, EmailSchedule, EmailReportConfig
from core.telemetry import Finding, ScanResult, SystemInfo
from core.config import Severity
from reporting.email_sender import EmailSender
from reporting.email_scheduler import EmailScheduleChecker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan_result(**overrides) -> ScanResult:
    """Create a ScanResult with sensible defaults for testing."""
    result = ScanResult(
        system_info=SystemInfo(hostname="test-host", os_name="TestOS"),
        findings=[
            Finding(
                title="Test Critical Finding",
                description="A critical test finding",
                severity=Severity.CRITICAL,
                category="test",
                scanner="test_scanner",
            ),
            Finding(
                title="Test High Finding",
                description="A high-severity test finding",
                severity=Severity.HIGH,
                category="test",
                scanner="test_scanner",
            ),
            Finding(
                title="Test Medium Finding",
                description="A medium test finding",
                severity=Severity.MEDIUM,
                category="test",
                scanner="test_scanner",
            ),
            Finding(
                title="Test Low Finding",
                description="A low test finding",
                severity=Severity.LOW,
                category="test",
                scanner="test_scanner",
            ),
            Finding(
                title="Test Info Finding",
                description="An informational finding",
                severity=Severity.INFO,
                category="test",
                scanner="test_scanner",
            ),
        ],
        scanners_run=["test_scanner"],
        scan_duration_seconds=12.5,
        risk_score=65.0,
        risk_grade="D",
    )
    for k, v in overrides.items():
        setattr(result, k, v)
    return result


def _make_email_config(**overrides) -> EmailReportConfig:
    """Create a usable EmailReportConfig for testing."""
    cfg = EmailReportConfig(
        enabled=True,
        smtp=SMTPConfig(
            host="smtp.example.com",
            port=587,
            username="sentinel@example.com",
            password="secret",
            use_tls=True,
            from_address="sentinel@example.com",
        ),
        recipients=["admin@example.com"],
        subject_prefix="[Sentinel]",
        include_html_attachment=True,
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


# ---------------------------------------------------------------------------
# Config Defaults
# ---------------------------------------------------------------------------

class TestSMTPConfigDefaults:

    def test_default_host(self):
        cfg = SMTPConfig()
        assert cfg.host == ""

    def test_default_port(self):
        cfg = SMTPConfig()
        assert cfg.port == 587

    def test_default_use_tls(self):
        cfg = SMTPConfig()
        assert cfg.use_tls is True

    def test_default_username(self):
        cfg = SMTPConfig()
        assert cfg.username == ""

    def test_default_password(self):
        cfg = SMTPConfig()
        assert cfg.password == ""

    def test_default_from_address(self):
        cfg = SMTPConfig()
        assert cfg.from_address == ""


class TestEmailScheduleDefaults:

    def test_default_frequency(self):
        sched = EmailSchedule()
        assert sched.frequency == "weekly"

    def test_default_day_of_week(self):
        sched = EmailSchedule()
        assert sched.day_of_week == 1

    def test_default_hour(self):
        sched = EmailSchedule()
        assert sched.hour == 8

    def test_default_minute(self):
        sched = EmailSchedule()
        assert sched.minute == 0


class TestEmailReportConfigDefaults:

    def test_default_enabled(self):
        cfg = EmailReportConfig()
        assert cfg.enabled is False

    def test_default_recipients_empty(self):
        cfg = EmailReportConfig()
        assert cfg.recipients == []

    def test_default_subject_prefix(self):
        cfg = EmailReportConfig()
        assert cfg.subject_prefix == "[Sentinel]"

    def test_default_include_html_attachment(self):
        cfg = EmailReportConfig()
        assert cfg.include_html_attachment is True

    def test_default_smtp_nested(self):
        cfg = EmailReportConfig()
        assert isinstance(cfg.smtp, SMTPConfig)
        assert cfg.smtp.port == 587

    def test_default_schedule_nested(self):
        cfg = EmailReportConfig()
        assert isinstance(cfg.schedule, EmailSchedule)
        assert cfg.schedule.frequency == "weekly"


# ---------------------------------------------------------------------------
# EmailSender._build_email_body
# ---------------------------------------------------------------------------

class TestBuildEmailBody:

    def test_contains_risk_score(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result(risk_score=65.0)
        html = sender._build_email_body(result)
        assert "65" in html

    def test_contains_risk_grade(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result(risk_grade="D")
        html = sender._build_email_body(result)
        assert "D" in html

    def test_contains_finding_counts(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result()
        html = sender._build_email_body(result)
        # The body should show severity labels and counts
        assert "Critical" in html
        assert "High" in html
        assert "Medium" in html
        assert "Low" in html
        assert "Info" in html

    def test_contains_total_findings(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result()
        html = sender._build_email_body(result)
        assert "Total" in html
        # 5 findings total
        assert ">5<" in html

    def test_is_valid_html(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result()
        html = sender._build_email_body(result)
        assert html.strip().startswith("<html>")
        assert html.strip().endswith("</html>")

    def test_green_color_for_low_risk(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result(risk_score=15.0)
        html = sender._build_email_body(result)
        assert "#198754" in html  # green

    def test_red_color_for_high_risk(self):
        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result(risk_score=85.0)
        html = sender._build_email_body(result)
        assert "#dc3545" in html  # red


# ---------------------------------------------------------------------------
# EmailSender.send_report
# ---------------------------------------------------------------------------

class TestSendReport:

    @patch("reporting.email_sender.smtplib.SMTP")
    def test_send_report_success(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result()

        success, message = sender.send_report(result)
        assert success is True
        assert "1 recipient" in message

        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("sentinel@example.com", "secret")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("reporting.email_sender.smtplib.SMTP")
    def test_send_report_with_html_attachment(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result()

        success, _ = sender.send_report(result, html_content="<html><body>Full Report</body></html>")
        assert success is True

        # Verify sendmail was called with content that includes the attachment
        call_args = mock_server.sendmail.call_args
        raw_message = call_args[0][2]
        assert "sentinel_report_" in raw_message

    def test_send_report_no_recipients_fails(self):
        config = _make_email_config(recipients=[])
        sender = EmailSender(config)
        result = _make_scan_result()

        success, message = sender.send_report(result)
        assert success is False
        assert "No recipients" in message

    def test_send_report_no_host_fails(self):
        config = _make_email_config(smtp=SMTPConfig(host="", port=587))
        sender = EmailSender(config)
        result = _make_scan_result()

        success, message = sender.send_report(result)
        assert success is False
        assert "SMTP host not configured" in message

    @patch("reporting.email_sender.smtplib.SMTP")
    def test_send_report_smtp_error(self, mock_smtp_cls):
        import smtplib
        mock_smtp_cls.side_effect = smtplib.SMTPException("Auth failed")

        config = _make_email_config()
        sender = EmailSender(config)
        result = _make_scan_result()

        success, message = sender.send_report(result)
        assert success is False
        assert "SMTP error" in message


# ---------------------------------------------------------------------------
# EmailSender.send_test_email
# ---------------------------------------------------------------------------

class TestSendTestEmail:

    @patch("reporting.email_sender.smtplib.SMTP")
    def test_send_test_email_success(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        config = _make_email_config()
        sender = EmailSender(config)

        success, message = sender.send_test_email()
        assert success is True
        assert "Test email sent" in message

        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    def test_send_test_email_no_recipients(self):
        config = _make_email_config(recipients=[])
        sender = EmailSender(config)

        success, message = sender.send_test_email()
        assert success is False
        assert "No recipients" in message

    def test_send_test_email_no_host(self):
        config = _make_email_config(smtp=SMTPConfig(host="", port=587))
        sender = EmailSender(config)

        success, message = sender.send_test_email()
        assert success is False
        assert "SMTP host not configured" in message


# ---------------------------------------------------------------------------
# EmailScheduleChecker
# ---------------------------------------------------------------------------

class TestEmailScheduleChecker:

    def test_is_due_when_never_sent(self, tmp_path):
        config = _make_email_config()
        checker = EmailScheduleChecker(config, state_dir=tmp_path)
        assert checker.is_due() is True

    def test_mark_sent_creates_state_file(self, tmp_path):
        config = _make_email_config()
        checker = EmailScheduleChecker(config, state_dir=tmp_path)
        checker.mark_sent()

        state_file = tmp_path / "email_schedule_state.json"
        assert state_file.exists()
        data = json.loads(state_file.read_text())
        assert "last_sent" in data

    def test_is_due_false_right_after_mark_sent(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="daily")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)
        checker.mark_sent()
        assert checker.is_due() is False

    def test_is_due_daily_after_24h(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="daily")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        # Write a last_sent timestamp 25 hours ago
        past = datetime.now(timezone.utc) - timedelta(hours=25)
        state = {"last_sent": past.isoformat()}
        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text(json.dumps(state))

        assert checker.is_due() is True

    def test_is_due_daily_before_24h(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="daily")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        # Write a last_sent timestamp 12 hours ago
        past = datetime.now(timezone.utc) - timedelta(hours=12)
        state = {"last_sent": past.isoformat()}
        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text(json.dumps(state))

        assert checker.is_due() is False

    def test_is_due_weekly_after_7_days(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="weekly")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        past = datetime.now(timezone.utc) - timedelta(days=8)
        state = {"last_sent": past.isoformat()}
        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text(json.dumps(state))

        assert checker.is_due() is True

    def test_is_due_weekly_before_7_days(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="weekly")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        past = datetime.now(timezone.utc) - timedelta(days=3)
        state = {"last_sent": past.isoformat()}
        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text(json.dumps(state))

        assert checker.is_due() is False

    def test_is_due_monthly_after_30_days(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="monthly")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        past = datetime.now(timezone.utc) - timedelta(days=31)
        state = {"last_sent": past.isoformat()}
        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text(json.dumps(state))

        assert checker.is_due() is True

    def test_is_due_monthly_before_30_days(self, tmp_path):
        config = _make_email_config()
        config.schedule = EmailSchedule(frequency="monthly")
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        past = datetime.now(timezone.utc) - timedelta(days=15)
        state = {"last_sent": past.isoformat()}
        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text(json.dumps(state))

        assert checker.is_due() is False

    def test_last_sent_returns_none_when_no_state_file(self, tmp_path):
        config = _make_email_config()
        checker = EmailScheduleChecker(config, state_dir=tmp_path)
        assert checker._last_sent() is None

    def test_last_sent_returns_none_for_invalid_json(self, tmp_path):
        config = _make_email_config()
        checker = EmailScheduleChecker(config, state_dir=tmp_path)

        state_file = tmp_path / "email_schedule_state.json"
        state_file.write_text("not valid json {{{")

        assert checker._last_sent() is None

    def test_not_due_when_disabled(self, tmp_path):
        config = _make_email_config()
        config.enabled = False
        checker = EmailScheduleChecker(config, state_dir=tmp_path)
        assert checker.is_due() is False

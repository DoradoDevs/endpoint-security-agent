"""
Sentinel Agent — Email Report Sender

Sends HTML scan reports via SMTP with TLS support. Builds inline-CSS
email bodies that render correctly in Outlook, Gmail, and other major
email clients.
"""

from __future__ import annotations

import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from core.config import EmailReportConfig
from core.telemetry import ScanResult


class EmailSender:
    """Sends HTML scan reports via SMTP with TLS."""

    def __init__(self, config: EmailReportConfig):
        self.config = config

    def send_report(
        self, scan_result: ScanResult, html_content: str | None = None
    ) -> tuple[bool, str]:
        """Send a scan report email.

        Args:
            scan_result: The scan result to summarize in the email body.
            html_content: Optional full HTML report to attach.

        Returns:
            A (success, message) tuple.
        """
        if not self.config.recipients:
            return False, "No recipients configured"

        if not self.config.smtp.host:
            return False, "SMTP host not configured"

        body_html = self._build_email_body(scan_result)

        msg = MIMEMultipart("mixed")
        msg["Subject"] = (
            f"{self.config.subject_prefix} Security Report "
            f"— Risk {scan_result.risk_score:.0f}/100 ({scan_result.risk_grade})"
        )
        msg["From"] = self.config.smtp.from_address or self.config.smtp.username
        msg["To"] = ", ".join(self.config.recipients)

        # Inline HTML body
        body_part = MIMEText(body_html, "html", "utf-8")
        msg.attach(body_part)

        # Optional full HTML report attachment
        if self.config.include_html_attachment and html_content:
            attachment = MIMEText(html_content, "html", "utf-8")
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=f"sentinel_report_{timestamp}.html",
            )
            msg.attach(attachment)

        try:
            server = self._connect_smtp()
            server.sendmail(
                msg["From"],
                self.config.recipients,
                msg.as_string(),
            )
            server.quit()
            return True, f"Report sent to {len(self.config.recipients)} recipient(s)"
        except smtplib.SMTPException as exc:
            return False, f"SMTP error: {exc}"
        except OSError as exc:
            return False, f"Connection error: {exc}"

    def send_test_email(self) -> tuple[bool, str]:
        """Send a test email to verify SMTP configuration.

        Returns:
            A (success, message) tuple.
        """
        if not self.config.recipients:
            return False, "No recipients configured"

        if not self.config.smtp.host:
            return False, "SMTP host not configured"

        msg = MIMEMultipart("mixed")
        msg["Subject"] = f"{self.config.subject_prefix} Test Email"
        msg["From"] = self.config.smtp.from_address or self.config.smtp.username
        msg["To"] = ", ".join(self.config.recipients)

        body_html = (
            "<html><body>"
            "<h2 style='color:#0d6efd;'>Sentinel Email Test</h2>"
            "<p>This is a test email from the Sentinel Security Agent.</p>"
            "<p>If you received this message, your SMTP configuration is working "
            "correctly.</p>"
            "<hr>"
            "<p style='color:#6c757d;font-size:12px;'>"
            "Sentinel Security Agent — Automated Report Delivery</p>"
            "</body></html>"
        )
        body_part = MIMEText(body_html, "html", "utf-8")
        msg.attach(body_part)

        try:
            server = self._connect_smtp()
            server.sendmail(
                msg["From"],
                self.config.recipients,
                msg.as_string(),
            )
            server.quit()
            return True, f"Test email sent to {len(self.config.recipients)} recipient(s)"
        except smtplib.SMTPException as exc:
            return False, f"SMTP error: {exc}"
        except OSError as exc:
            return False, f"Connection error: {exc}"

    def _build_email_body(self, scan_result: ScanResult) -> str:
        """Build HTML email body with inline CSS for email clients.

        Uses a simple table-based layout that renders reliably in
        Outlook, Gmail, Apple Mail, and other major clients.
        """
        score = scan_result.risk_score
        grade = scan_result.risk_grade

        if score <= 30:
            score_color = "#198754"  # green
        elif score <= 60:
            score_color = "#ffc107"  # amber
        else:
            score_color = "#dc3545"  # red

        findings_total = len(scan_result.findings)
        critical = scan_result.critical_count
        high = scan_result.high_count
        medium = scan_result.medium_count
        low = scan_result.low_count
        info = scan_result.info_count

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        html = f"""\
<html>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background-color:#f8f9fa;">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;margin:0 auto;background:#ffffff;">
  <tr>
    <td style="background:#1a1a2e;color:#ffffff;padding:20px 30px;">
      <h1 style="margin:0;font-size:22px;">Sentinel Security Report</h1>
      <p style="margin:5px 0 0;font-size:13px;color:#a0a0b0;">{timestamp}</p>
    </td>
  </tr>
  <tr>
    <td style="padding:30px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="text-align:center;padding:15px;border:2px solid {score_color};border-radius:8px;">
            <div style="font-size:48px;font-weight:bold;color:{score_color};">{score:.0f}</div>
            <div style="font-size:14px;color:#6c757d;">Risk Score</div>
            <div style="font-size:24px;font-weight:bold;color:{score_color};margin-top:4px;">{grade}</div>
          </td>
        </tr>
      </table>

      <h2 style="font-size:16px;margin:25px 0 10px;color:#333;">Finding Summary</h2>
      <table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
        <tr style="background:#f1f3f5;">
          <th style="text-align:left;border-bottom:2px solid #dee2e6;font-size:13px;">Severity</th>
          <th style="text-align:right;border-bottom:2px solid #dee2e6;font-size:13px;">Count</th>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #dee2e6;color:#dc3545;font-weight:bold;">Critical</td>
          <td style="border-bottom:1px solid #dee2e6;text-align:right;">{critical}</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #dee2e6;color:#fd7e14;font-weight:bold;">High</td>
          <td style="border-bottom:1px solid #dee2e6;text-align:right;">{high}</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #dee2e6;color:#ffc107;font-weight:bold;">Medium</td>
          <td style="border-bottom:1px solid #dee2e6;text-align:right;">{medium}</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #dee2e6;color:#0d6efd;">Low</td>
          <td style="border-bottom:1px solid #dee2e6;text-align:right;">{low}</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #dee2e6;color:#6c757d;">Info</td>
          <td style="border-bottom:1px solid #dee2e6;text-align:right;">{info}</td>
        </tr>
        <tr style="font-weight:bold;">
          <td style="padding-top:8px;">Total</td>
          <td style="padding-top:8px;text-align:right;">{findings_total}</td>
        </tr>
      </table>

      <p style="margin-top:25px;font-size:13px;color:#6c757d;">
        Scan duration: {scan_result.scan_duration_seconds:.1f}s
        &bull; Scanners run: {len(scan_result.scanners_run)}
      </p>
    </td>
  </tr>
  <tr>
    <td style="background:#f1f3f5;padding:15px 30px;text-align:center;font-size:12px;color:#6c757d;">
      Sentinel Security Agent &mdash; Automated Report
    </td>
  </tr>
</table>
</body>
</html>"""
        return html

    def _connect_smtp(self) -> smtplib.SMTP:
        """Connect to SMTP server with TLS.

        Returns:
            An authenticated SMTP connection ready to send.
        """
        smtp = self.config.smtp
        server = smtplib.SMTP(smtp.host, smtp.port, timeout=30)

        if smtp.use_tls:
            server.starttls()

        if smtp.username and smtp.password:
            server.login(smtp.username, smtp.password)

        return server

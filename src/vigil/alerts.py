"""Email alerting for Vigil findings that require attention.

Sends email alerts for non-blocking specialists (e.g. Security) so findings
are visible even though they don't block the review.

Configuration via environment variables:
    VIGIL_ALERT_EMAIL    — recipient email address(es), comma-separated
    SMTP_HOST            — SMTP server hostname (default: smtp.gmail.com)
    SMTP_PORT            — SMTP server port (default: 587)
    SMTP_USER            — SMTP username (usually your email)
    SMTP_PASSWORD        — SMTP password or app password
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .models import Finding, PersonaVerdict, Severity

log = logging.getLogger(__name__)


def _severity_emoji(sev: Severity) -> str:
    return {
        Severity.critical: "\U0001f534",
        Severity.high: "\U0001f7e0",
        Severity.medium: "\U0001f7e1",
        Severity.low: "\U0001f535",
    }.get(sev, "")


def _format_findings_html(findings: list[Finding]) -> str:
    """Format findings as HTML for email body."""
    rows = []
    for f in findings:
        emoji = _severity_emoji(f.severity)
        loc = f.file
        if f.line:
            loc += f":{f.line}"
        suggestion = f"<br><em>Suggestion: {f.suggestion}</em>" if f.suggestion else ""
        rows.append(
            f"<tr>"
            f"<td>{emoji} {f.severity.value.upper()}</td>"
            f"<td><code>{loc}</code></td>"
            f"<td>[{f.category}] {f.message}{suggestion}</td>"
            f"</tr>"
        )
    return (
        "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;'>"
        "<tr><th>Severity</th><th>Location</th><th>Finding</th></tr>"
        + "\n".join(rows)
        + "</table>"
    )


def _format_findings_text(findings: list[Finding]) -> str:
    """Format findings as plain text for email body."""
    lines = []
    for f in findings:
        loc = f.file + (f":{f.line}" if f.line else "")
        lines.append(f"  [{f.severity.value.upper()}] {loc} — [{f.category}] {f.message}")
        if f.suggestion:
            lines.append(f"    Suggestion: {f.suggestion}")
    return "\n".join(lines)


def send_alert(
    persona_name: str,
    findings: list[Finding],
    pr_url: str = "",
    pr_title: str = "",
) -> bool:
    """Send an email alert for findings from a specialist.

    Returns True if email was sent, False if alerting is not configured.
    """
    alert_email = os.environ.get("VIGIL_ALERT_EMAIL", "").strip()
    if not alert_email:
        log.debug("VIGIL_ALERT_EMAIL not set — skipping email alert")
        return False

    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASSWORD", "")

    if not smtp_user or not smtp_pass:
        log.warning("SMTP_USER/SMTP_PASSWORD not set — cannot send alert email")
        return False

    recipients = [e.strip() for e in alert_email.split(",") if e.strip()]

    # Count by severity
    crit = sum(1 for f in findings if f.severity == Severity.critical)
    high = sum(1 for f in findings if f.severity == Severity.high)
    severity_tag = ""
    if crit:
        severity_tag = f"\U0001f534 {crit} CRITICAL"
    elif high:
        severity_tag = f"\U0001f7e0 {high} HIGH"

    subject = f"Vigil {persona_name} Alert: {len(findings)} finding(s)"
    if severity_tag:
        subject += f" — {severity_tag}"
    if pr_title:
        subject += f" in \"{pr_title}\""

    # Build email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = ", ".join(recipients)

    # Plain text version
    text_body = f"Vigil {persona_name} Review Alert\n{'=' * 40}\n\n"
    if pr_url:
        text_body += f"PR: {pr_url}\n"
    if pr_title:
        text_body += f"Title: {pr_title}\n"
    text_body += f"\n{len(findings)} finding(s) detected (non-blocking):\n\n"
    text_body += _format_findings_text(findings)
    text_body += "\n\nThese findings are non-blocking but should be reviewed."
    text_body += "\n\n— Vigil (AI-powered PR review)"

    # HTML version
    html_body = f"""
    <h2>Vigil {persona_name} Review Alert</h2>
    {'<p><a href="' + pr_url + '">' + pr_title + '</a></p>' if pr_url else ''}
    <p><strong>{len(findings)} finding(s) detected</strong> (non-blocking — review not blocked)</p>
    {_format_findings_html(findings)}
    <br>
    <p><em>These findings are non-blocking but should be reviewed.</em></p>
    <hr>
    <p style="color: #888; font-size: 12px;">
        Sent by <a href="https://github.com/F2iProject/vigil">Vigil</a> — AI-powered PR review
    </p>
    """

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, recipients, msg.as_string())
        log.info("Alert email sent to %s for %d %s findings", recipients, len(findings), persona_name)
        return True
    except Exception as e:
        log.warning("Failed to send alert email: %s", e)
        return False


def send_alerts_for_verdicts(
    verdicts: list[PersonaVerdict],
    alert_personas: set[str],
    pr_url: str = "",
    pr_title: str = "",
) -> int:
    """Send alerts for all verdicts from alert-enabled personas.

    Args:
        verdicts: All specialist verdicts.
        alert_personas: Set of persona names that have alert=True.
        pr_url: PR URL for context in the email.
        pr_title: PR title for the email subject.

    Returns count of alerts sent.
    """
    sent = 0
    for v in verdicts:
        if v.persona not in alert_personas:
            continue
        # For non-blocking personas, findings were moved to observations
        # Send alert for both findings and observations from alert personas
        all_findings = v.findings + v.observations
        if not all_findings:
            continue
        if send_alert(v.persona, all_findings, pr_url, pr_title):
            sent += 1
    return sent

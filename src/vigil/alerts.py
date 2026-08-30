"""Email alerting for Vigil findings that require attention.

Sends email alerts for non-blocking specialists (e.g. Security) so findings
are visible even though they don't block the review. Also POSTs the same
findings to LunaOS's escalation-gate webhook so they surface in the Telegram
escalation pipeline.

Configuration via environment variables:
    VIGIL_ALERT_EMAIL       — recipient email address(es), comma-separated
    SMTP_HOST               — SMTP server hostname (default: smtp.gmail.com)
    SMTP_PORT               — SMTP server port (default: 587)
    SMTP_USER               — SMTP username (usually your email)
    SMTP_PASSWORD           — SMTP password or app password
    LUNAOS_ESCALATION_URL   — LunaOS /api/escalations endpoint URL; unset disables
                              the webhook delivery path
    ESCALATION_INGEST_TOKEN — shared secret sent as the X-Escalation-Token header
"""

import logging
import os
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from .models import Finding, PersonaVerdict, Severity
from .utils import severity_emoji as _severity_emoji

log = logging.getLogger(__name__)

_PR_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)")


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


def send_escalation_webhook(
    persona_name: str,
    findings: list[Finding],
    pr_url: str = "",
    pr_title: str = "",
) -> bool:
    """POST findings from an alert-enabled specialist to LunaOS's escalation gate.

    This feeds the same non-blocking-but-visible findings that `send_alert`
    emails into LunaOS's `/api/escalations` endpoint, which fans them out to
    Telegram. See LunaOS `skills/escalation-gate/SKILL.md` for the contract.

    Returns True only on a 2xx response, False otherwise (including when the
    webhook is not configured, the PR URL can't be parsed, or the request
    fails) — this must never raise.
    """
    escalation_url = os.environ.get("LUNAOS_ESCALATION_URL", "").strip()
    escalation_token = os.environ.get("ESCALATION_INGEST_TOKEN", "").strip()
    if not escalation_url or not escalation_token:
        log.debug("LUNAOS_ESCALATION_URL/ESCALATION_INGEST_TOKEN not set — skipping escalation webhook")
        return False

    match = _PR_URL_RE.match(pr_url)
    if not match:
        log.warning("Cannot parse owner/repo and PR number from pr_url %r — skipping escalation webhook", pr_url)
        return False
    repo, pr_number = match.group(1), match.group(2)

    # Count by severity (mirrors send_alert's subject-line logic)
    crit = sum(1 for f in findings if f.severity == Severity.critical)
    high = sum(1 for f in findings if f.severity == Severity.high)
    severity_tag = ""
    if crit:
        severity_tag = f"\U0001f534 {crit} CRITICAL"
    elif high:
        severity_tag = f"\U0001f7e0 {high} HIGH"

    title = f"Vigil {persona_name} Alert: {len(findings)} finding(s)"
    if severity_tag:
        title += f" — {severity_tag}"
    if pr_title:
        title += f" in \"{pr_title}\""

    top = findings[0]
    top_loc = top.file + (f":{top.line}" if top.line else "")
    reason = f"[{top.severity.value.upper()}] {top_loc} — {top.message}"
    if len(reason) > 200:
        reason = reason[:197] + "..."

    payload = {
        "source": "vigil",
        "repo": repo,
        "subjectType": "pr",
        "subjectId": pr_number,
        "kind": "needs-human-review",
        "title": title,
        "reason": reason,
        "deepLink": pr_url,
    }

    try:
        resp = httpx.post(
            escalation_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Escalation-Token": escalation_token,
            },
            timeout=10,
        )
        if 200 <= resp.status_code < 300:
            log.info(
                "Escalation webhook sent for %d %s findings on %s#%s",
                len(findings), persona_name, repo, pr_number,
            )
            return True
        log.warning(
            "Escalation webhook returned %d for %s#%s: %s",
            resp.status_code, repo, pr_number, resp.text[:200],
        )
        return False
    except Exception as e:
        log.warning("Failed to send escalation webhook: %s", e)
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

    Sends both an email alert (send_alert) and, if configured, an escalation
    webhook POST to LunaOS (send_escalation_webhook) for each alert-enabled
    verdict with findings. Either delivery succeeding counts toward `sent`.

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
        email_sent = send_alert(v.persona, all_findings, pr_url, pr_title)
        webhook_sent = send_escalation_webhook(v.persona, all_findings, pr_url, pr_title)
        if email_sent or webhook_sent:
            sent += 1
    return sent

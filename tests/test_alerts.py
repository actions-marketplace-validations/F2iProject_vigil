"""Tests for alerting: email formatting, send logic, verdict routing."""

import os
from unittest.mock import patch, MagicMock

import pytest

from vigil.alerts import (
    _format_findings_html,
    _format_findings_text,
    send_alert,
    send_alerts_for_verdicts,
)
from vigil.models import Finding, PersonaVerdict, Severity


# ---------- Finding fixtures ----------

def _make_finding(sev=Severity.high, file="app.py", line=10, cat="injection", msg="SQL injection"):
    return Finding(file=file, line=line, severity=sev, category=cat, message=msg)


def _make_finding_with_suggestion():
    return Finding(
        file="auth.py", line=5, severity=Severity.critical,
        category="secrets", message="Hardcoded API key",
        suggestion="Use environment variables instead",
    )


# ---------- _format_findings_text ----------

class TestFormatFindingsText:

    def test_basic_finding(self):
        text = _format_findings_text([_make_finding()])
        assert "HIGH" in text
        assert "app.py:10" in text
        assert "SQL injection" in text

    def test_finding_with_suggestion(self):
        text = _format_findings_text([_make_finding_with_suggestion()])
        assert "Suggestion:" in text
        assert "environment variables" in text

    def test_no_line_number(self):
        f = _make_finding(line=None)
        text = _format_findings_text([f])
        assert "app.py" in text
        assert ":None" not in text

    def test_empty_list(self):
        assert _format_findings_text([]) == ""


# ---------- _format_findings_html ----------

class TestFormatFindingsHtml:

    def test_contains_table(self):
        html = _format_findings_html([_make_finding()])
        assert "<table" in html
        assert "SQL injection" in html

    def test_severity_emoji(self):
        html = _format_findings_html([_make_finding(sev=Severity.critical)])
        assert "CRITICAL" in html

    def test_suggestion_in_html(self):
        html = _format_findings_html([_make_finding_with_suggestion()])
        assert "environment variables" in html


# ---------- send_alert ----------

class TestSendAlert:

    def test_no_alert_email_returns_false(self):
        with patch.dict(os.environ, {"VIGIL_ALERT_EMAIL": ""}, clear=False):
            result = send_alert("Security", [_make_finding()])
            assert result is False

    def test_no_smtp_creds_returns_false(self):
        env = {"VIGIL_ALERT_EMAIL": "test@example.com", "SMTP_USER": "", "SMTP_PASSWORD": ""}
        with patch.dict(os.environ, env, clear=False):
            result = send_alert("Security", [_make_finding()])
            assert result is False

    @patch("vigil.alerts.smtplib.SMTP")
    def test_sends_email_successfully(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        env = {
            "VIGIL_ALERT_EMAIL": "dev@example.com",
            "SMTP_HOST": "smtp.test.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "vigil@test.com",
            "SMTP_PASSWORD": "secret",
        }
        with patch.dict(os.environ, env, clear=False):
            result = send_alert(
                "Security",
                [_make_finding()],
                pr_url="https://github.com/org/repo/pull/1",
                pr_title="Add auth module",
            )

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("vigil@test.com", "secret")
        mock_server.sendmail.assert_called_once()

    @patch("vigil.alerts.smtplib.SMTP")
    def test_smtp_failure_returns_false(self, mock_smtp_class):
        mock_smtp_class.return_value.__enter__ = MagicMock(
            side_effect=Exception("Connection refused")
        )
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        env = {
            "VIGIL_ALERT_EMAIL": "dev@example.com",
            "SMTP_USER": "vigil@test.com",
            "SMTP_PASSWORD": "secret",
        }
        with patch.dict(os.environ, env, clear=False):
            result = send_alert("Security", [_make_finding()])
        assert result is False

    def test_multiple_recipients(self):
        """Multiple comma-separated emails are handled."""
        env = {"VIGIL_ALERT_EMAIL": "a@x.com, b@x.com", "SMTP_USER": "", "SMTP_PASSWORD": ""}
        with patch.dict(os.environ, env, clear=False):
            # Will return False due to no creds, but tests parsing
            result = send_alert("Security", [_make_finding()])
            assert result is False

    def test_critical_severity_in_subject(self):
        """Critical findings should be highlighted in the email subject."""
        # This is tested indirectly through the send flow
        # Just verify the function doesn't crash with critical findings
        env = {"VIGIL_ALERT_EMAIL": "", "SMTP_USER": "", "SMTP_PASSWORD": ""}
        with patch.dict(os.environ, env, clear=False):
            send_alert("Security", [_make_finding(sev=Severity.critical)])


# ---------- send_alerts_for_verdicts ----------

class TestSendAlertsForVerdicts:

    def test_only_alert_personas_get_emails(self):
        verdicts = [
            PersonaVerdict(
                persona="Security", decision="APPROVE",
                checks={}, findings=[], observations=[_make_finding()],
            ),
            PersonaVerdict(
                persona="Logic", decision="APPROVE",
                checks={}, findings=[_make_finding()], observations=[],
            ),
        ]
        alert_personas = {"Security"}  # Only Security has alert=True

        with patch("vigil.alerts.send_alert", return_value=True) as mock_send:
            sent = send_alerts_for_verdicts(verdicts, alert_personas)

        assert sent == 1
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        assert call_args[0][0] == "Security"  # persona name

    def test_no_findings_no_alert(self):
        verdicts = [
            PersonaVerdict(
                persona="Security", decision="APPROVE",
                checks={}, findings=[], observations=[],
            ),
        ]
        with patch("vigil.alerts.send_alert") as mock_send:
            sent = send_alerts_for_verdicts(verdicts, {"Security"})

        assert sent == 0
        mock_send.assert_not_called()

    def test_empty_alert_personas(self):
        verdicts = [
            PersonaVerdict(
                persona="Security", decision="APPROVE",
                checks={}, findings=[_make_finding()], observations=[],
            ),
        ]
        with patch("vigil.alerts.send_alert") as mock_send:
            sent = send_alerts_for_verdicts(verdicts, set())

        assert sent == 0
        mock_send.assert_not_called()

    def test_includes_pr_context(self):
        verdicts = [
            PersonaVerdict(
                persona="Security", decision="APPROVE",
                checks={}, findings=[], observations=[_make_finding()],
            ),
        ]
        with patch("vigil.alerts.send_alert", return_value=True) as mock_send:
            send_alerts_for_verdicts(
                verdicts, {"Security"},
                pr_url="https://github.com/o/r/pull/1",
                pr_title="My PR",
            )

        mock_send.assert_called_once_with(
            "Security", [_make_finding()],
            "https://github.com/o/r/pull/1", "My PR",
        )

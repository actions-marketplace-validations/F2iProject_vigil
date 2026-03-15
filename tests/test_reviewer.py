"""Tests for reviewer.py: non-blocking persona logic and decision filtering."""

import json
import pytest
from unittest.mock import patch, MagicMock

from vigil.models import Finding, PersonaVerdict, ReviewResult, Severity
from vigil.personas import Persona, ReviewProfile
from vigil.reviewer import _parse_json_response, _parse_findings, review_diff


# ---------- _parse_json_response ----------

class TestParseJsonResponse:

    def test_plain_json(self):
        raw = '{"decision": "APPROVE", "findings": []}'
        assert _parse_json_response(raw)["decision"] == "APPROVE"

    def test_code_fenced_json(self):
        raw = '```json\n{"decision": "APPROVE"}\n```'
        assert _parse_json_response(raw)["decision"] == "APPROVE"

    def test_json_with_trailing_text(self):
        raw = '{"decision": "APPROVE"} some trailing text'
        assert _parse_json_response(raw)["decision"] == "APPROVE"

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_json_response("not json at all")


# ---------- _parse_findings ----------

class TestParseFindings:

    def test_basic_finding(self):
        raw = [{"file": "a.py", "line": 10, "severity": "high",
                "category": "bug", "message": "Off by one"}]
        findings = _parse_findings(raw)
        assert len(findings) == 1
        assert findings[0].file == "a.py"
        assert findings[0].severity == Severity.high

    def test_null_file_coerced(self):
        raw = [{"file": None, "line": 1, "severity": "low",
                "category": "test", "message": "msg"}]
        findings = _parse_findings(raw)
        assert findings[0].file == "unknown"

    def test_invalid_line_coerced(self):
        raw = [{"file": "a.py", "line": "not-a-number", "severity": "low",
                "category": "test", "message": "msg"}]
        findings = _parse_findings(raw)
        assert findings[0].line is None


# ---------- Non-blocking persona logic in review_diff ----------

class TestNonBlockingPersonaLogic:

    def _make_mock_profile(self, blocking=True):
        """Create a profile with one specialist (optionally non-blocking)."""
        persona = Persona(
            name="TestSpecialist",
            focus="Testing",
            system_prompt="You are a test reviewer.",
            blocking=blocking,
        )
        return ReviewProfile(
            name="test",
            specialists=[persona],
            lead_prompt="You are the lead.",
        )

    def _mock_completion(self, decision="REQUEST_CHANGES", findings=None, observations=None):
        """Build a mock LLM response."""
        resp = {
            "decision": decision,
            "checks": {"test_check": "CONCERN"},
            "findings": findings or [
                {"file": "a.py", "line": 1, "severity": "high",
                 "category": "bug", "message": "Found a bug"}
            ],
            "observations": observations or [],
        }
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock(message=MagicMock(content=json.dumps(resp)))]
        return mock_resp

    def _mock_lead_response(self, decision="APPROVE"):
        resp = {"decision": decision, "summary": "Looks good", "findings": []}
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock(message=MagicMock(content=json.dumps(resp)))]
        return mock_resp

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer.completion")
    def test_blocking_persona_keeps_findings(self, mock_completion, mock_alerts):
        """Blocking personas keep their findings as-is."""
        mock_alerts.return_value = 0
        mock_completion.side_effect = [
            self._mock_completion(decision="REQUEST_CHANGES"),
            self._mock_lead_response(decision="REQUEST_CHANGES"),
        ]

        profile = self._make_mock_profile(blocking=True)
        pr_context = {
            "title": "Test PR", "author": "user", "head": "feature",
            "base": "main", "additions": 10, "deletions": 5,
            "changed_files": 1, "body": "Test",
        }

        result = review_diff("diff --git a/a.py b/a.py\n", pr_context, profile)
        # Blocking persona should keep findings
        specialist = result.specialist_verdicts[0]
        assert len(specialist.findings) == 1
        assert len(specialist.observations) == 0

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer.completion")
    def test_nonblocking_persona_moves_findings_to_observations(self, mock_completion, mock_alerts):
        """Non-blocking personas move findings to observations and force APPROVE."""
        mock_alerts.return_value = 0
        mock_completion.side_effect = [
            self._mock_completion(decision="REQUEST_CHANGES"),
            self._mock_lead_response(decision="APPROVE"),
        ]

        profile = self._make_mock_profile(blocking=False)
        pr_context = {
            "title": "Test PR", "author": "user", "head": "feature",
            "base": "main", "additions": 10, "deletions": 5,
            "changed_files": 1, "body": "Test",
        }

        result = review_diff("diff --git a/a.py b/a.py\n", pr_context, profile)
        specialist = result.specialist_verdicts[0]
        # Findings should be moved to observations
        assert len(specialist.findings) == 0
        assert len(specialist.observations) == 1
        # Decision should be forced to APPROVE
        assert specialist.decision == "APPROVE"

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer.completion")
    def test_nonblocking_observations_in_result(self, mock_completion, mock_alerts):
        """Non-blocking observations appear in result.observations."""
        mock_alerts.return_value = 0
        mock_completion.side_effect = [
            self._mock_completion(decision="REQUEST_CHANGES"),
            self._mock_lead_response(decision="APPROVE"),
        ]

        profile = self._make_mock_profile(blocking=False)
        pr_context = {
            "title": "Test PR", "author": "user", "head": "feature",
            "base": "main", "additions": 10, "deletions": 5,
            "changed_files": 1, "body": "Test",
        }

        result = review_diff("diff --git a/a.py b/a.py\n", pr_context, profile)
        assert len(result.observations) == 1
        assert result.observations[0].message == "Found a bug"

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer.completion")
    def test_observation_sources_tracked(self, mock_completion, mock_alerts):
        """observation_sources tracks which persona produced each observation."""
        mock_alerts.return_value = 0
        mock_completion.side_effect = [
            self._mock_completion(decision="REQUEST_CHANGES"),
            self._mock_lead_response(decision="APPROVE"),
        ]

        profile = self._make_mock_profile(blocking=False)
        pr_context = {
            "title": "Test PR", "author": "user", "head": "feature",
            "base": "main", "additions": 10, "deletions": 5,
            "changed_files": 1, "body": "Test",
        }

        result = review_diff("diff --git a/a.py b/a.py\n", pr_context, profile)
        assert len(result.observation_sources) == 1
        persona_name, finding = result.observation_sources[0]
        assert persona_name == "TestSpecialist"
        assert finding.message == "Found a bug"


# ---------- Decision filtering in review_diff ----------

class TestDecisionFiltering:

    @patch("vigil.reviewer.send_alerts_for_verdicts")
    @patch("vigil.reviewer.completion")
    @patch("vigil.decision_log.filter_known_findings")
    def test_known_findings_suppressed(self, mock_filter, mock_completion, mock_alerts):
        """When repo_key is provided, known findings are filtered out."""
        mock_alerts.return_value = 0
        # The filter returns empty list (all findings suppressed)
        mock_filter.return_value = []

        finding_data = {
            "decision": "REQUEST_CHANGES",
            "checks": {},
            "findings": [
                {"file": "a.py", "line": 1, "severity": "high",
                 "category": "bug", "message": "Known bug"}
            ],
            "observations": [],
        }
        specialist_resp = MagicMock()
        specialist_resp.choices = [MagicMock(message=MagicMock(content=json.dumps(finding_data)))]

        lead_data = {"decision": "APPROVE", "summary": "OK", "findings": []}
        lead_resp = MagicMock()
        lead_resp.choices = [MagicMock(message=MagicMock(content=json.dumps(lead_data)))]

        mock_completion.side_effect = [specialist_resp, lead_resp]

        persona = Persona(name="Logic", focus="Bugs", system_prompt="Test")
        profile = ReviewProfile(name="test", specialists=[persona], lead_prompt="Lead")
        pr_context = {
            "title": "Test", "author": "u", "head": "f", "base": "m",
            "additions": 1, "deletions": 0, "changed_files": 1, "body": "",
        }

        result = review_diff(
            "diff --git a/a.py b/a.py\n", pr_context, profile,
            repo_key="owner/repo",
        )

        # filter_known_findings should have been called
        assert mock_filter.call_count >= 1

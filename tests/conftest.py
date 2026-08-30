"""Shared test wiring.

The head-content guard added for F2iLLC/vigil#74 runs inside ``post_review``
and is real network I/O against the GitHub contents API. No test in this suite
is allowed to reach the network, and a guard that silently made HTTP calls from
every ``post_review`` test would be both slow and flaky-by-environment. It is
therefore stubbed out here by default, as an identity split: every finding is
supported, nothing is suppressed — i.e. exactly the pre-#74 contract each of
those tests was written against.

Tests that exercise the guard opt back in explicitly (see
``tests/test_finding_validation.py``), either by calling
``validate_findings_against_head`` directly with injected fetchers, or by
re-patching ``vigil.github_review.validate_findings_against_head`` back to the
real implementation and stubbing the blob fetch instead. A test's own
``monkeypatch.setattr`` runs after this fixture, so it wins.
"""

import pytest

from vigil import github_review


@pytest.fixture(autouse=True)
def stub_head_content_validation(monkeypatch):
    """Keep the network out of every ``post_review`` call by default."""
    monkeypatch.setattr(
        github_review,
        "validate_findings_against_head",
        lambda findings, *args, **kwargs: (list(findings), []),
    )

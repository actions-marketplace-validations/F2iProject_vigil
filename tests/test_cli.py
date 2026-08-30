import pytest
import typer

from vigil import cli


def test_resolve_addressed_checks_dismissed_threads_before_unchanged_head_skip(monkeypatch):
    calls: list[str] = []

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(cli, "parse_pr_url", lambda pr_url: ("F2iLLC", "demo", 1))
    monkeypatch.setattr(
        cli,
        "get_pr_data",
        lambda *args: {"head_sha": "same-sha", "diff": ""},
    )
    monkeypatch.setattr(cli, "get_last_reviewed_sha", lambda *args: "same-sha")

    def fake_resolve_dismissed_threads(*args):
        calls.append("dismissed")
        return 1

    def fail_if_compared(*args):
        raise AssertionError("unchanged heads should not compare commits")

    monkeypatch.setattr(cli, "resolve_dismissed_threads", fake_resolve_dismissed_threads)
    monkeypatch.setattr(cli, "get_changed_files_between_commits", fail_if_compared)

    with pytest.raises(typer.Exit) as exc:
        cli.resolve_addressed("https://github.com/F2iLLC/demo/pull/1")

    assert exc.value.exit_code == 0
    assert calls == ["dismissed"]

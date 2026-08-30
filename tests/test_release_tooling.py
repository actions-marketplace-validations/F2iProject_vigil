"""Tests for the release-tag tooling added for issue #58.

The single most important test in this file is
``test_resolve_peels_annotated_tag_to_commit``. `v1` in this repository is an
*annotated* tag, so ``git rev-parse v1`` yields the tag object rather than the
commit. A checker that skips the peel reports permanent phantom drift; that
mistake has already misled a prior automated run and was warned about twice in
the issue thread. These tests exist so it cannot come back silently.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TAGCTL = REPO_ROOT / ".github" / "scripts" / "tagctl.sh"
CHECK_INPUTS = REPO_ROOT / ".github" / "scripts" / "check_action_inputs.py"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        check=True,
        env={
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(repo),
        },
    )
    return out.stdout.decode().strip()


def tagctl(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(TAGCTL), *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def commit(repo: Path, message: str, filename: str = "f.txt") -> str:
    (repo / filename).write_text(message + "\n", encoding="utf-8")
    git(repo, "add", filename)
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A throwaway git repo with three commits on ``main``."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    # Persist an identity in the repo config, not just in the helper's env:
    # `tagctl.sh move` shells out to `git tag -a` itself, and an annotated tag
    # cannot be written without a tagger. (This is exactly why the release
    # workflow has to configure an identity too — the test found that first.)
    git(r, "config", "user.name", "Test")
    git(r, "config", "user.email", "test@example.com")
    commit(r, "one")
    commit(r, "two")
    commit(r, "three")
    return r


# --------------------------------------------------------------------------
# resolve — the regression guard that justifies this whole file
# --------------------------------------------------------------------------
def test_resolve_peels_annotated_tag_to_commit(repo: Path) -> None:
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "annotated release alias", head)

    tag_object = git(repo, "rev-parse", "v1")
    assert tag_object != head, (
        "fixture is not exercising the bug: an annotated tag must have its own "
        "object sha distinct from the commit"
    )

    result = tagctl(repo, "resolve", "v1")
    assert result.returncode == 0, result.stderr
    resolved = result.stdout.strip()

    assert resolved == head
    assert resolved != tag_object


def test_resolve_is_a_noop_on_a_lightweight_tag_and_a_branch(repo: Path) -> None:
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "light", head)

    assert tagctl(repo, "resolve", "light").stdout.strip() == head
    assert tagctl(repo, "resolve", "main").stdout.strip() == head
    assert tagctl(repo, "resolve", head).stdout.strip() == head


def test_resolve_reports_missing_ref_with_exit_4(repo: Path) -> None:
    result = tagctl(repo, "resolve", "no-such-ref")
    assert result.returncode == 4


# --------------------------------------------------------------------------
# drift
# --------------------------------------------------------------------------
def test_drift_reports_in_sync_for_annotated_alias_at_head(repo: Path) -> None:
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "alias", head)

    result = tagctl(repo, "drift", "--alias", "v1", "--branch", "main")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "status=in-sync" in result.stdout
    assert "drift_count=0" in result.stdout


def test_drift_counts_unshipped_commits_and_lists_them(repo: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "alias", base)
    commit(repo, "four")
    commit(repo, "five")

    result = tagctl(repo, "drift", "--alias", "v1", "--branch", "main")
    assert result.returncode == 3
    assert "drift_count=2" in result.stdout
    assert "status=behind" in result.stdout
    assert "four" in result.stdout and "five" in result.stdout


def test_drift_distinguishes_diverged_from_merely_behind(repo: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "-b", "side")
    side = commit(repo, "side-only")
    git(repo, "tag", "-a", "v1", "-m", "alias", side)
    git(repo, "checkout", "-q", "main")
    commit(repo, "main-only")

    result = tagctl(repo, "drift", "--alias", "v1", "--branch", "main")
    assert result.returncode == 3
    assert "status=diverged" in result.stdout
    assert "alias_ahead_by=1" in result.stdout
    assert base  # base is the shared ancestor; kept for readability


def test_drift_reports_missing_alias_with_exit_4(repo: Path) -> None:
    result = tagctl(repo, "drift", "--alias", "v1", "--branch", "main")
    assert result.returncode == 4
    assert "MISSING" in result.stdout


# --------------------------------------------------------------------------
# plan-move — the guards that keep a release from shipping the wrong thing
# --------------------------------------------------------------------------
def test_plan_move_accepts_a_forward_move_on_the_branch(repo: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "alias", base)
    newer = commit(repo, "four")

    result = tagctl(repo, "plan-move", "v1", newer, "--branch", "main")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == newer


def test_plan_move_refuses_a_target_not_contained_in_the_branch(repo: Path) -> None:
    """A tag pushed from a feature branch must not ship to consumers."""
    git(repo, "tag", "-a", "v1", "-m", "alias", "HEAD")
    git(repo, "checkout", "-q", "-b", "feature")
    off_branch = commit(repo, "not-on-main")
    git(repo, "checkout", "-q", "main")

    result = tagctl(repo, "plan-move", "v1", off_branch, "--branch", "main")
    assert result.returncode == 3
    assert "not contained in" in result.stderr


def test_plan_move_refuses_a_silent_rollback(repo: Path) -> None:
    older = git(repo, "rev-parse", "HEAD~1")
    git(repo, "tag", "-a", "v1", "-m", "alias", "HEAD")

    result = tagctl(repo, "plan-move", "v1", older, "--branch", "main")
    assert result.returncode == 3
    assert "BACKWARDS" in result.stderr


def test_plan_move_allows_an_explicit_rollback(repo: Path) -> None:
    older = git(repo, "rev-parse", "HEAD~1")
    git(repo, "tag", "-a", "v1", "-m", "alias", "HEAD")

    result = tagctl(repo, "plan-move", "v1", older, "--branch", "main", "--allow-rollback")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == older


def test_plan_move_does_not_mutate_the_tag(repo: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "alias", base)
    newer = commit(repo, "four")

    tagctl(repo, "plan-move", "v1", newer, "--branch", "main")

    assert tagctl(repo, "resolve", "v1").stdout.strip() == base


# --------------------------------------------------------------------------
# move
# --------------------------------------------------------------------------
def test_move_replaces_the_alias_and_keeps_it_annotated(repo: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "-a", "v1", "-m", "alias", base)
    newer = commit(repo, "four")

    result = tagctl(repo, "move", "v1", newer, "--message", "ship")
    assert result.returncode == 0, result.stderr

    assert tagctl(repo, "resolve", "v1").stdout.strip() == newer
    # Still annotated: the tag object sha must differ from the commit sha, and
    # `cat-file -t` must say "tag". A lightweight replacement would break every
    # checker written against the annotated shape.
    assert git(repo, "rev-parse", "v1") != newer
    assert git(repo, "cat-file", "-t", "v1") == "tag"


def test_move_never_pushes(repo: Path, tmp_path: Path) -> None:
    """`move` must be inert against a remote — pushing is the caller's act."""
    remote = tmp_path / "remote.git"
    remote.mkdir()
    git(remote, "init", "-q", "--bare")
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-q", "origin", "main")

    newer = commit(repo, "four")
    git(repo, "tag", "-a", "v1", "-m", "alias", "HEAD~1")
    tagctl(repo, "move", "v1", newer)

    remote_tags = git(remote, "tag", "-l")
    assert remote_tags == "", f"move pushed to the remote: {remote_tags!r}"


# --------------------------------------------------------------------------
# pins
# --------------------------------------------------------------------------
def test_pins_flags_a_self_pin_that_is_behind_the_branch(repo: Path) -> None:
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    old = git(repo, "rev-parse", "HEAD")
    (workflows / "wf.yml").write_text(
        f"jobs:\n  a:\n    steps:\n      - uses: F2iLLC/vigil@{old}\n",
        encoding="utf-8",
    )
    git(repo, "add", ".github")
    git(repo, "commit", "-m", "add workflow")
    commit(repo, "later")

    result = tagctl(repo, "pins", "--branch", "main")
    assert result.returncode == 3
    assert "status=stale" in result.stdout
    assert "behind:" in result.stdout


def test_pins_reports_all_current_when_the_pin_is_at_head(repo: Path) -> None:
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "wf.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: F2iLLC/vigil@main\n",
        encoding="utf-8",
    )
    git(repo, "add", ".github")
    git(repo, "commit", "-m", "add workflow")

    result = tagctl(repo, "pins", "--branch", "main")
    assert result.returncode == 0
    assert "status=all-current" in result.stdout


# --------------------------------------------------------------------------
# action.yml input compatibility
# --------------------------------------------------------------------------
def load_checker():
    spec = importlib.util.spec_from_file_location("check_action_inputs", CHECK_INPUTS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def checker():
    return load_checker()


def test_adding_an_optional_input_is_compatible(checker) -> None:
    old = {"a": {"required": False, "default": ""}}
    new = {"a": {"required": False, "default": ""}, "b": {"required": False}}
    breaking, warnings, info = checker.compare(old, new)
    assert breaking == []
    assert any("'b' added" in m for m in info)


def test_removing_an_input_is_breaking(checker) -> None:
    breaking, _, _ = checker.compare({"a": {}}, {})
    assert len(breaking) == 1
    assert "REMOVED" in breaking[0]


def test_making_an_input_required_is_breaking(checker) -> None:
    breaking, _, _ = checker.compare({"a": {"required": False}}, {"a": {"required": True}})
    assert len(breaking) == 1
    assert "became REQUIRED" in breaking[0]


def test_adding_a_required_input_is_breaking(checker) -> None:
    breaking, _, _ = checker.compare({}, {"a": {"required": True}})
    assert len(breaking) == 1
    assert "ADDED as REQUIRED" in breaking[0]


def test_changing_a_default_warns_but_does_not_block(checker) -> None:
    breaking, warnings, _ = checker.compare(
        {"model": {"default": "gemini/a"}}, {"model": {"default": "gemini/b"}}
    )
    assert breaking == []
    assert len(warnings) == 1
    assert "default changed" in warnings[0]


def test_required_is_read_as_yaml_does_not_as_python_truthiness(checker) -> None:
    """The string ``"false"`` is truthy in Python but means *not required* here."""
    assert checker.is_required({"required": "false"}) is False
    assert checker.is_required({"required": False}) is False
    assert checker.is_required({"required": "true"}) is True
    assert checker.is_required({"required": True}) is True
    assert checker.is_required({}) is False


def test_real_action_yml_v1_to_main_is_input_compatible() -> None:
    """The move this issue is actually asking about must not break consumers.

    Skips rather than fails when the refs are unavailable (shallow clone, or a
    checkout without the tag fetched), so the suite stays green off-network.
    """
    for ref in ("v1", "origin/main"):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=REPO_ROOT,
            capture_output=True,
        )
        if probe.returncode != 0:
            pytest.skip(f"ref {ref} not available in this checkout")

    result = subprocess.run(
        ["python3", str(CHECK_INPUTS), "--from", "v1", "--to", "origin/main"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

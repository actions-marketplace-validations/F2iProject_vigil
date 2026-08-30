"""Behavioral regression tests for action.yml's loud-failure guard step.

F2iLLC/vigil#51 item 1: on a runner whose python3 lacks ensurepip, the
"Install Vigil into a venv" step fails, "Run Vigil" is then skipped, and
because the consuming workflow sets continue-on-error: true, the job still
concludes success -- a failed review is indistinguishable from a passing
one at the check level. The final "Verify Vigil actually ran" step in
action.yml (id: guard) exists to make that unmissable.

These tests execute the *actual* run: scripts from action.yml -- extracted
via YAML parsing, not reimplemented -- under bash, with the GitHub-Actions-
templated values (steps.install.outcome, steps.run.outcome, inputs.*,
github.*) supplied the same way the step's own `env:` block supplies them
in production. A stub `curl` on PATH captures every invocation and can
simulate either call the guard makes: the dedup GET (comment listing) and
the comment POST -- so no network access is required.

Covers a second round of hardening after the guard's first review: the PR
comment is now restricted to the `review` command (dismiss-resolved and
resolve-addressed only get the annotation/summary/output, since
resolve-addressed fires on every `synchronize` event and would otherwise
spam every open PR on every push for the duration of an outage), and a
best-effort dedup GET skips reposting when a prior comment already carries
the `<!-- vigil-did-not-run -->` marker.
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
STEPS = ACTION["runs"]["steps"]


def _step(*, step_id=None, name=None):
    for step in STEPS:
        if step_id is not None and step.get("id") == step_id:
            return step
        if name is not None and step.get("name") == name:
            return step
    raise AssertionError(f"no step found (id={step_id!r}, name={name!r})")


GUARD_SCRIPT = _step(step_id="guard")["run"]
INSTALL_SCRIPT = _step(step_id="install")["run"]


def _write_curl_stub(
    bin_dir: Path,
    log_path: Path,
    response_path: Path,
    *,
    get_exit_code: int,
    post_exit_code: int,
) -> None:
    """A stub `curl` that logs every invocation and branches on whether the
    call is the dedup GET (comment listing) or the comment POST -- the guard
    script's GET never passes `-X POST`, its POST always does. The GET
    branch prints response_path's contents to stdout (if present) before
    exiting with get_exit_code, so a test can simulate an existing marker
    comment, a timeout, or a garbage/non-JSON response.
    """
    stub = bin_dir / "curl"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf \'%s\\n\' "$*" >> "{log_path}"\n'
        "if printf '%s' \"$*\" | grep -q -- '-X POST'; then\n"
        f"  exit {post_exit_code}\n"
        "fi\n"
        f'if [ -f "{response_path}" ]; then\n'
        f'  cat "{response_path}"\n'
        "fi\n"
        f"exit {get_exit_code}\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)


def _run_guard_script(
    work_dir: Path,
    env_overrides: dict,
    *,
    get_exit_code: int = 0,
    post_exit_code: int = 0,
    get_response: str = "",
):
    """Run action.yml's real guard-step script in isolation.

    get_response simulates the dedup GET's response body (e.g. existing PR
    comments JSON containing -- or not containing -- the marker string).
    get_exit_code/post_exit_code simulate curl failing (network error,
    timeout, HTTP error) on either call independently.

    Returns (CompletedProcess, github_output_text, github_summary_text,
    curl_invocation_log_text). curl_invocation_log_text has one line per
    curl call in order (GET first, then POST if reached), so tests can
    distinguish "no calls", "GET only", and "GET then POST" by counting
    lines / checking for "-X POST".
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    script_path = work_dir / "guard.sh"
    script_path.write_text(GUARD_SCRIPT)

    github_output = work_dir / "github_output"
    github_output.write_text("")
    github_summary = work_dir / "github_summary"
    github_summary.write_text("")

    bin_dir = work_dir / "bin"
    bin_dir.mkdir(exist_ok=True)
    curl_log = work_dir / "curl_calls.log"
    response_path = work_dir / "get_response.json"
    if get_response:
        response_path.write_text(get_response)
    _write_curl_stub(
        bin_dir,
        curl_log,
        response_path,
        get_exit_code=get_exit_code,
        post_exit_code=post_exit_code,
    )

    env = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "GITHUB_OUTPUT": str(github_output),
        "GITHUB_STEP_SUMMARY": str(github_summary),
    }
    env.update(env_overrides)

    result = subprocess.run(
        ["bash", str(script_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    curl_calls = curl_log.read_text() if curl_log.exists() else ""
    return result, github_output.read_text(), github_summary.read_text(), curl_calls


def _post_calls(curl_calls: str) -> list:
    return [line for line in curl_calls.splitlines() if "-X POST" in line]


def _get_calls(curl_calls: str) -> list:
    return [line for line in curl_calls.splitlines() if "-X POST" not in line and line]


# --- Happy path -------------------------------------------------------------


def test_noop_when_install_and_run_both_succeeded(tmp_path):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "success",
            "RUN_OUTCOME": "success",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "review-ran=true" in output
    assert "::error" not in result.stdout
    assert summary == ""
    assert curl_calls == "", "must not post a PR comment when Vigil actually ran"


# --- Failure path: the exact scenario from the incident ---------------------


def test_fails_loudly_when_install_failed_and_run_was_skipped(tmp_path):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1, "the guard step must fail itself, not exit 0"
    assert "review-ran=false" in output

    assert "::error title=Vigil did not run::" in result.stdout
    assert "NO REVIEW WAS POSTED" in result.stdout
    assert "install step outcome='failure'" in result.stdout
    assert "run step outcome='skipped'" in result.stdout

    assert "Vigil did not run" in summary

    assert "repos/F2iLLC/relara/issues/701/comments" in curl_calls
    assert "Authorization: token test-token" in curl_calls
    assert '"body":' in curl_calls

    # The `review` command gets both the dedup lookup and the comment post.
    assert len(_get_calls(curl_calls)) == 1, f"expected one dedup GET: {curl_calls!r}"
    assert len(_post_calls(curl_calls)) == 1, f"expected one comment POST: {curl_calls!r}"


def test_fails_loudly_when_run_step_itself_failed_after_a_successful_install(tmp_path):
    """Install can succeed while Run Vigil still fails for an unrelated
    reason (GitHub API error, exhausted retries, ...) -- that must be
    flagged too, since no review was posted either way."""
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "success",
            "RUN_OUTCOME": "failure",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1
    assert "review-ran=false" in output
    assert "install step outcome='success'" in result.stdout
    assert "run step outcome='failure'" in result.stdout


# --- Comment-spam guard: only post when a PR number is resolvable -----------


def test_skips_comment_when_no_pr_number_is_resolvable(tmp_path):
    # COMMAND is "review" here so this exercises the PR-number-missing
    # branch specifically, distinct from the command-gating branch covered
    # below (that check runs first and would otherwise mask this one).
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1
    assert curl_calls == ""
    assert "No resolvable PR number" in result.stdout
    # The annotation/summary must still fire even without a PR to comment on.
    assert "::error title=Vigil did not run::" in result.stdout
    assert "Vigil did not run" in summary


# --- Comment gate: only the `review` command may post -----------------------
#
# resolve-addressed fires on every `synchronize` event; posting there too
# would mean a comment on every open PR on every push for as long as an
# outage lasts. dismiss-resolved and resolve-addressed also never create
# the "false attestation of a completed review" this guard exists to catch
# in the first place, since neither posts a review in any outcome.


@pytest.mark.parametrize("command", ["dismiss-resolved", "resolve-addressed"])
def test_comment_suppressed_for_non_review_commands(tmp_path, command):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": command,
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1
    assert "review-ran=false" in output

    # Not even the dedup GET should fire -- the command gate short-circuits
    # before any curl call at all.
    assert curl_calls == "", f"expected zero curl calls for {command!r}: {curl_calls!r}"
    assert f"Command is '{command}', not 'review'" in result.stdout

    # The annotation, summary, and output must still fire regardless of
    # command -- only the comment is gated.
    assert "::error title=Vigil did not run::" in result.stdout
    assert "Vigil did not run" in summary

    # Wording fix: a non-review command never claims a review was posted.
    assert "NO REVIEW WAS POSTED" not in result.stdout
    assert f"Vigil's '{command}' step did NOT run for this PR." in result.stdout
    assert f"run its '{command}' command" in result.stdout


def test_comment_posted_for_the_review_command(tmp_path):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1
    assert "NO REVIEW WAS POSTED" in result.stdout
    assert len(_get_calls(curl_calls)) == 1
    assert len(_post_calls(curl_calls)) == 1
    assert "Posted a PR comment noting Vigil did not run." in result.stdout


def test_comment_posted_when_command_input_is_unset(tmp_path):
    """inputs.command defaults to "review" in action.yml, so an empty
    COMMAND env var (unset input) must behave the same as COMMAND=review,
    not silently fall into the non-review suppression branch."""
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1
    assert len(_post_calls(curl_calls)) == 1


# --- Dedup: skip a repost when the marker is already present ----------------


def test_dedup_skips_posting_when_the_marker_is_already_present(tmp_path):
    existing_comments = (
        '[{"id": 1, "body": "Vigil did not run on this PR. Details here. '
        '<!-- vigil-did-not-run -->"}]'
    )
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
        get_response=existing_comments,
    )
    assert result.returncode == 1
    # The annotation/summary/output must still fire even when the comment
    # is suppressed as a duplicate.
    assert "::error title=Vigil did not run::" in result.stdout
    assert "Vigil did not run" in summary
    assert "review-ran=false" in output

    assert "already exists on this PR" in result.stdout
    assert len(_get_calls(curl_calls)) == 1, "the dedup GET should still run"
    assert _post_calls(curl_calls) == [], (
        f"must not repost when the marker is already present: {curl_calls!r}"
    )


def test_dedup_posts_anyway_when_the_marker_is_absent(tmp_path):
    existing_comments = '[{"id": 1, "body": "some unrelated comment"}]'
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
        get_response=existing_comments,
    )
    assert len(_post_calls(curl_calls)) == 1


def test_dedup_posts_anyway_when_the_lookup_fails(tmp_path):
    """A GET that errors or times out must fall through to posting, not go
    silent -- curl's exit 28 is its own timeout code."""
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
        get_exit_code=28,
    )
    assert result.returncode == 1
    assert len(_post_calls(curl_calls)) == 1, (
        f"a failed/timed-out dedup lookup must fall through to posting: {curl_calls!r}"
    )


def test_dedup_posts_anyway_when_the_lookup_returns_junk(tmp_path):
    """A 200 with an unparseable/unexpected body must also fall through to
    posting rather than being (mis)treated as a marker match."""
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
        get_response="<html>not json, some proxy error page</html>",
    )
    assert result.returncode == 1
    assert len(_post_calls(curl_calls)) == 1, (
        f"junk from the dedup GET must fall through to posting: {curl_calls!r}"
    )


def test_skips_comment_when_github_token_is_missing(tmp_path):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "REPO": "F2iLLC/relara",
        },
    )
    assert result.returncode == 1
    assert curl_calls == ""
    assert "No github-token available" in result.stdout


def test_falls_back_to_event_pull_request_url_when_pr_url_input_is_empty(tmp_path):
    # COMMAND is "review" so the comment path (which exercises PR-URL
    # resolution) actually runs; resolve-addressed would suppress the
    # comment entirely regardless of whether a PR URL resolves.
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "EVENT_PR_URL": "https://github.com/F2iLLC/bioqms-core/pull/1234",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/bioqms-core",
        },
    )
    assert "repos/F2iLLC/bioqms-core/issues/1234/comments" in curl_calls
    assert len(_post_calls(curl_calls)) == 1


def test_falls_back_to_event_pull_request_number_as_last_resort(tmp_path):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "EVENT_PR_NUMBER": "42",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/praxislms",
        },
    )
    assert "repos/F2iLLC/praxislms/issues/42/comments" in curl_calls
    assert len(_post_calls(curl_calls)) == 1


# --- The annotation must never be masked by a failed comment post -----------


def test_survives_a_failing_pr_comment_post_without_masking_the_annotation(tmp_path):
    result, output, summary, curl_calls = _run_guard_script(
        tmp_path,
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
        post_exit_code=22,  # curl's --fail exit code for an HTTP error
    )
    assert curl_calls != "", "curl should still have been attempted"
    assert len(_post_calls(curl_calls)) == 1, "the POST must still have been attempted"
    assert "::error title=Vigil did not run::" in result.stdout
    assert "Vigil did not run" in summary
    assert "::warning::" in result.stdout
    assert result.returncode == 1, (
        "a failed best-effort comment must not change the step's own "
        "(already-determined) failing outcome"
    )


# --- End-to-end: reproduce the actual incident from F2iLLC/vigil#51 ---------


def test_install_step_fails_when_venv_creation_fails_and_the_guard_catches_it(tmp_path):
    """Chains the real 'Install Vigil into a venv' script into the real
    guard script, using a stub python3 whose `-m venv` fails exactly like
    the ensurepip-missing error from the incident (F2iLLC/relara run
    30927732554 / F2iLLC/LunaOS#3775). Confirms end-to-end that (a) the
    install script itself exits non-zero -- which is what makes GitHub
    Actions record its outcome as failure and skip Run Vigil -- and (b)
    feeding that real outcome into the real guard script correctly flips
    review-ran to false and fires every loud-failure mechanism.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub_python = bin_dir / "broken-python3"
    stub_python.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then\n'
        "  echo 'The virtual environment was not created successfully"
        " because ensurepip is not available.' >&2\n"
        "  exit 1\n"
        "fi\n"
        'echo "unsupported stub invocation: $*" >&2\n'
        "exit 1\n"
    )
    stub_python.chmod(stub_python.stat().st_mode | stat.S_IEXEC)

    action_path = tmp_path / "fake-action-checkout"
    action_path.mkdir()

    # Substitute the GH-expression placeholders the same way GitHub Actions
    # would template them, using needs_setup=false so the script resolves
    # PYTHON_BIN straight to our broken stub (equivalent to: Detect Python
    # believed the system interpreter was fine).
    install_script = (
        INSTALL_SCRIPT.replace("${{ steps.py.outputs.needs_setup }}", "false")
        .replace("${{ steps.py.outputs.python }}", str(stub_python))
        .replace("${{ github.action_path }}", str(action_path))
    )
    assert "${{" not in install_script, "left an unsubstituted GH expression in the script"

    install_dir = tmp_path / "install"
    install_dir.mkdir()
    install_path = install_dir / "install.sh"
    install_path.write_text(install_script)

    env = dict(os.environ)
    env["GITHUB_OUTPUT"] = str(install_dir / "github_output")
    env["RUNNER_TEMP"] = str(install_dir)
    env["GITHUB_RUN_ID"] = "test-run"
    (install_dir / "github_output").write_text("")

    install_result = subprocess.run(
        ["bash", str(install_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert install_result.returncode != 0, (
        "the real Install-Vigil script must exit non-zero when "
        f"`python3 -m venv` fails; stdout={install_result.stdout!r} "
        f"stderr={install_result.stderr!r}"
    )
    assert "ensurepip" in install_result.stderr

    # GitHub Actions would now record steps.install.outcome=failure and
    # skip Run Vigil entirely (outcome=skipped) since it has no
    # if: always(). Feed those real semantics into the real guard script.
    guard_result, guard_output, guard_summary, curl_calls = _run_guard_script(
        tmp_path / "guard",
        {
            "INSTALL_OUTCOME": "failure",
            "RUN_OUTCOME": "skipped",
            "COMMAND": "review",
            "PR_URL_INPUT": "https://github.com/F2iLLC/relara/pull/701",
            "GITHUB_TOKEN": "test-token",
            "REPO": "F2iLLC/relara",
        },
    )
    assert guard_result.returncode == 1
    assert "review-ran=false" in guard_output
    assert "::error title=Vigil did not run::" in guard_result.stdout
    assert "NO REVIEW WAS POSTED" in guard_result.stdout
    assert "Vigil did not run" in guard_summary
    assert "repos/F2iLLC/relara/issues/701/comments" in curl_calls

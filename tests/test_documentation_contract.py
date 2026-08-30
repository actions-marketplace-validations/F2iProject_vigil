"""Regression tests for the public setup and workflow documentation."""

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
ACTION = (ROOT / "action.yml").read_text(encoding="utf-8")
CALLER = (ROOT / ".github" / "workflows" / "vigil.yml").read_text(encoding="utf-8")
REUSABLE = (ROOT / ".github" / "workflows" / "reusable-vigil.yml").read_text(
    encoding="utf-8"
)

ACTION_YAML = yaml.safe_load(ACTION)
REUSABLE_YAML = yaml.safe_load(REUSABLE)


def _action_default(input_name: str) -> str:
    match = re.search(
        rf"^  {re.escape(input_name)}:\n"
        rf"(?:^    .*\n)*?"
        rf"^    default: [\"']?([^\"'\n]+)",
        ACTION,
        re.MULTILINE,
    )
    assert match, f"Could not find the {input_name!r} default in action.yml"
    return match.group(1).strip()


def test_readme_tracks_the_action_model_and_profile_defaults():
    model = _action_default("model")
    profile = _action_default("profile")

    assert f"Default: {model}" in README
    assert f"| `profile` | `{profile}` |" in README


def test_readme_documents_every_public_action_input():
    documented_inputs = {
        "pr-url",
        "command",
        "model",
        "lead-model",
        "profile",
        "force",
        "reason",
        "github-token",
        "gemini-api-key",
        "openai-api-key",
        "anthropic-api-key",
        "context-provider",
        "context-label",
        "context-token",
    }

    assert documented_inputs <= set(ACTION_YAML["inputs"]), (
        "this set must track action.yml's actual inputs"
    )

    for input_name in documented_inputs:
        assert f"| `{input_name}` |" in README


def test_public_examples_do_not_recommend_the_stale_v1_tag():
    stale_reference = "uses: F2iLLC/vigil@v1"

    assert stale_reference not in README
    assert stale_reference not in CALLER
    assert stale_reference not in REUSABLE


def test_central_workflow_owns_approval_token_and_current_model():
    model = _action_default("model")

    assert "workflow_call:" in REUSABLE
    assert "VIGIL_REVIEW_TOKEN:" in REUSABLE
    assert "github-token: ${{ secrets.VIGIL_REVIEW_TOKEN || github.token }}" in REUSABLE
    assert f"default: {model}" in REUSABLE
    assert "uses: ./.github/workflows/reusable-vigil.yml" in CALLER


def test_readme_explains_comment_fallback_and_central_caller():
    assert "cannot satisfy a required-approval branch rule" in README
    assert "F2iLLC/vigil/.github/workflows/reusable-vigil.yml@main" in README


# --- F2iLLC/vigil#51 item 1 ("fail loudly") -------------------------------
#
# A venv/install failure inside the composite action must never be
# indistinguishable from a passing review at the check level. These tests
# assert the contract from the parsed YAML (not regex over raw text) so a
# future edit that quietly drops the guard step, its `if: always()`, the
# `review-ran` output, or the `advisory` default gets caught here instead
# of by another silent outage. See tests/test_fail_loudly_guard.py for
# behavioral (shell-level) coverage of the guard step itself.


def _find_step(steps, *, step_id=None, name=None):
    for step in steps:
        if step_id is not None and step.get("id") == step_id:
            return step
        if name is not None and step.get("name") == name:
            return step
    return None


def test_action_declares_a_review_ran_output():
    outputs = ACTION_YAML.get("outputs") or {}
    assert "review-ran" in outputs, "action.yml must declare a review-ran output"
    assert outputs["review-ran"]["value"] == "${{ steps.guard.outputs.review-ran }}"
    assert "review-ran" in README, "README should document the review-ran output"


def test_guard_step_exists_and_always_runs():
    steps = ACTION_YAML["runs"]["steps"]
    guard = _find_step(steps, step_id="guard")
    assert guard is not None, (
        "action.yml must have a step with id: guard that verifies Vigil "
        "actually ran"
    )
    assert guard.get("if") == "always()", (
        "the guard step must run with if: always() so it still executes "
        "when an earlier step (e.g. the venv install) failed"
    )
    assert guard.get("shell") == "bash"

    # The guard step reads steps.install.outcome and steps.run.outcome, so
    # both referenced steps need stable ids for that to resolve.
    install_step = _find_step(steps, step_id="install")
    assert install_step is not None
    run_step = _find_step(steps, name="Run Vigil")
    assert run_step is not None
    assert run_step.get("id") == "run", (
        "the 'Run Vigil' step needs an id so the guard step can read "
        "steps.run.outcome"
    )


def test_reusable_workflow_advisory_still_defaults_to_true():
    # `on:` is parsed by PyYAML's default (YAML 1.1) resolver as the
    # boolean key True rather than the string "on".
    trigger_key = True if True in REUSABLE_YAML else "on"
    advisory = REUSABLE_YAML[trigger_key]["workflow_call"]["inputs"]["advisory"]

    assert advisory["default"] is True, (
        "advisory must stay true by default -- flipping it turns every "
        "Vigil infrastructure hiccup into a merge blocker fleet-wide and "
        "is a deliberate operator decision, not a side effect of the "
        "fail-loudly guard (F2iLLC/vigil#51 item 1 explicitly keeps this "
        "unchanged; only item 3 documents the tradeoff)."
    )
    # The tradeoff must actually be documented, not just preserved.
    assert "advisory" in REUSABLE, "sanity: the input is still present"


# --- F2iLLC/vigil#47 (external context provider) --------------------------
#
# The provider can be an arbitrary command and can carry an operator token.
# The issue requires fork safety to be enforced in the workflow, not only in
# documentation, so these assert the gate structurally: a step that resolves
# the provider inputs, and action inputs wired through that step's outputs
# rather than straight from the workflow inputs.


def _review_steps():
    return REUSABLE_YAML["jobs"]["review"]["steps"]


def test_reusable_workflow_gates_the_context_provider_on_fork_prs():
    gate = _find_step(_review_steps(), step_id="context")
    assert gate is not None, (
        "reusable-vigil.yml must have a step with id: context that decides "
        "whether the external context provider is reachable"
    )
    assert gate.get("shell") == "bash"

    script = gate["run"]
    # Positive logic: allowed only on a pull_request whose head repository is
    # this repository. Everything else -- including issue_comment, where the
    # payload carries no head-repository provenance -- must fail closed.
    assert 'allowed="false"' in script, "the gate must default to disabled"
    assert "github.event.pull_request.head.repo.full_name" in REUSABLE
    assert '"${HEAD_REPO}" != "${BASE_REPO:-}"' in script
    assert '"${EVENT_NAME:-}" != "pull_request"' in script


def test_context_inputs_reach_the_action_only_through_the_fork_gate():
    action_step = next(
        step for step in _review_steps()
        if str(step.get("uses", "")).startswith("F2iLLC/vigil@")
    )
    provided = action_step["with"]

    assert provided["context-provider"] == "${{ steps.context.outputs.provider }}"
    assert provided["context-label"] == "${{ steps.context.outputs.label }}"
    assert "steps.context.outputs.allowed == 'true'" in provided["context-token"], (
        "the opaque provider token must be withheld unless the fork gate allowed it"
    )
    # A raw passthrough would defeat the gate entirely.
    assert "inputs.context-provider" not in str(provided.values())


def test_readme_documents_the_fork_constraint_for_external_context():
    assert "### External review context" in README
    assert "head.repo.full_name" in README
    assert "VIGIL_CONTEXT_PROVIDER" in README
    # The one-opaque-token rule and the fail-open rule are load-bearing
    # promises of this seam, not incidental prose.
    assert "VIGIL_CONTEXT_TOKEN" in README
    assert "Fails open" in README

"""CLI entry point for Vigil."""

import logging
import os

from dotenv import load_dotenv
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .audit import write_audit_entry
from .comment_manager import (
    build_conversation_context,
    dismiss_stale_vigil_blocks,
    fetch_all_pr_reviews,
    fetch_all_vigil_comments,
    fetch_pr_conversation_comments,
    fetch_vigil_comments,
    get_last_reviewed_sha,
    get_vigil_review_state,
    resolve_addressed_threads,
    resolve_dismissed_threads,
    resolve_vigil_threads_on_approval,
)
from .decision_log import clear_decisions, get_decisions, remove_decision
from .diff_parser import commentable_lines, parse_diff
from .github import (
    get_changed_files_between_commits,
    get_pr_data,
    is_ancestor_commit,
    parse_pr_url,
)
from .github_review import post_review, react, remove_reaction
from .issue_manager import create_issues_for_observations
from .models import DECISION_NOT_REVIEWED, Finding, PersonaVerdict, ReviewResult, Severity
from .personas import PROFILES
from .reviewer import review_diff
from .utils import NOT_REVIEWED_ICON, NOT_REVIEWED_LABEL, not_reviewed_reason_text

load_dotenv(override=True)
app = typer.Typer(name="vigil", help="AI-powered, model-agnostic PR review tool.")
console = Console()

SEV_STYLE = {
    Severity.critical: "[bold red]CRIT[/bold red]",
    Severity.high: "[red]HIGH[/red]",
    Severity.medium: "[yellow]MED [/yellow]",
    Severity.low: "[blue]LOW [/blue]",
}

DECISION_COLORS = {
    "APPROVE": "green",
    "REQUEST_CHANGES": "red",
    "BLOCK": "bold red",
    "ERROR": "magenta",
    # Never green: no specialist examined the diff, so the operator watching
    # this panel must not read it as a pass (#79).
    DECISION_NOT_REVIEWED: "yellow",
}


def _print_specialist_done(verdict: PersonaVerdict):
    """Callback: print a line as each specialist finishes.

    A specialist that made no model call is never printed green, never as
    APPROVE, and above all never as "clean" — the zero-findings fallback
    below said exactly that about a domain nobody examined (F2iLLC/vigil#66).
    This is the surface an operator watches live while deciding whether to
    trust a run, so it reports a skip the same way the posted review body
    does: the reason takes the slot "clean" used to occupy.
    """
    if not verdict.reviewed:
        sid = f" [dim]{verdict.session_id}[/dim]" if verdict.session_id else ""
        reason = not_reviewed_reason_text(verdict.skip_reason)
        detail = f" - {reason}" if reason else ""
        console.print(
            f"  [yellow]{NOT_REVIEWED_ICON} {NOT_REVIEWED_LABEL}[/yellow] "
            f"{verdict.persona}{sid}{detail}"
        )
        return

    color = "green" if verdict.decision == "APPROVE" else "red"
    n = len(verdict.findings)
    obs = len(verdict.observations)
    detail = ""
    if n:
        detail += f" {n} findings"
    if obs:
        detail += f" {obs} observations"
    if not detail:
        detail = " clean"
    sid = f" [dim]{verdict.session_id}[/dim]" if verdict.session_id else ""
    console.print(f"  [{color}]{verdict.decision}[/{color}] {verdict.persona}{sid} -{detail}")


def _print_findings(findings: list[Finding], title: str):
    """Print a findings table."""
    if not findings:
        return

    console.print(f"\n[bold]{title}[/bold]")
    table = Table(show_header=True, padding=(0, 1))
    table.add_column("Sev", width=6)
    table.add_column("Cat", width=16)
    table.add_column("Location", width=34)
    table.add_column("Issue")

    for f in findings:
        loc = f.file
        if f.line:
            loc += f":{f.line}"
        table.add_row(SEV_STYLE.get(f.severity, "?"), f.category, loc, f.message)

    console.print(table)

    suggestions = [f for f in findings if f.suggestion]
    if suggestions:
        console.print("\n[bold]Suggestions:[/bold]")
        for f in suggestions:
            loc = f.file + (f":{f.line}" if f.line else "")
            console.print(f"  [dim]{loc}[/dim] -> {f.suggestion}")


def _print_summary_stats(result: ReviewResult):
    """Print the one-line tally that closes a console review.

    A specialist that never ran did not approve anything, so it is excluded
    from the approval count and reported separately (F2iLLC/vigil#66) —
    "6/6 specialists approved" was the same false green as the verdict table,
    just in prose. Wording is kept in step with the identical tally in
    ``github_review._build_review_body()``.
    """
    total_findings = sum(len(v.findings) for v in result.specialist_verdicts) + len(result.lead_findings)
    total_obs = len(result.observations)
    approvals = sum(
        1 for v in result.specialist_verdicts if v.reviewed and v.decision == "APPROVE"
    )
    total = len(result.specialist_verdicts)
    not_run = sum(1 for v in result.specialist_verdicts if not v.reviewed)
    not_run_note = f" · {not_run} not reviewed" if not_run else ""
    console.print(f"\n[dim]{approvals}/{total} specialists approved{not_run_note} · {total_findings} findings · {total_obs} observations[/dim]")


def _rereview_reasons(
    *,
    forced: bool,
    reason: str,
    outstanding_blocks: list[dict],
    settled_verdict_at_head: bool,
    resolved_threads: int,
) -> list[str]:
    """Why a review should run even though no files changed since last review.

    Pure, so the gate can be tested without a network. An empty list means the
    ordinary case — no new commits, no standing block, nobody asked — and the
    caller must keep short-circuiting. That short-circuit is what keeps
    re-review cost down across the fleet; do not weaken it (issue #49).

    The three exits, and the real incidents each one covers:

    1. ``forced`` — an on-demand ``/vigil review``. The documented escape
       hatch routed through the same skip and was a no-op (praxislms#263).
    2. a standing block, or no settled verdict on the current head. These are
       two shapes of the same deadlock: bioqms-core#1472 left a live
       CHANGES_REQUESTED at head, praxislms#263 had that same verdict
       *dismissed* at head. Keying only on "an outstanding CHANGES_REQUESTED
       exists" would have missed the second; keying only on "no live review at
       head" would have missed the first. Both are checked.
    3. ``resolved_threads`` — Vigil threads were resolved during this run, so
       the evidence the prior verdict rested on has changed.
    """
    reasons: list[str] = []
    if forced:
        reasons.append(f"explicitly requested ({reason})" if reason else "explicitly requested")
    if outstanding_blocks:
        reasons.append(f"{len(outstanding_blocks)} outstanding Vigil block(s) to reconsider")
    if not settled_verdict_at_head:
        reasons.append("no live Vigil verdict on the current head")
    if resolved_threads:
        reasons.append(f"{resolved_threads} Vigil thread(s) resolved since the last review")
    return reasons


def _history_diverged(
    owner: str, repo: str, last_sha: str, head_sha: str, token: str,
) -> bool:
    """Has the branch been rebased/force-pushed since ``last_sha``?

    A rebase does not announce itself. ``compare/{base}...{head}`` does not
    404 for an orphaned-but-reachable base SHA — it quietly answers against
    the merge base instead, so ``changed_files`` silently becomes the whole
    PR rather than "changed since the last review", and the ``except`` around
    that call only fires when the SHA is unreachable outright. The
    consequence is not a bigger review (the review always uses the full
    base-to-head diff anyway) but a bogus ``changed_line_map``, which is fed
    to ``resolve_addressed_threads`` — that map is the sole evidence for
    auto-resolving Vigil's own threads, so a rebase could resolve threads
    whose code nobody touched (F2iLLC/vigil#74).

    Fails **open**: an error here reports "not diverged", which is exactly
    the behaviour that shipped before this check existed. Losing the check
    must never cost more than the check was worth.
    """
    try:
        return not is_ancestor_commit(owner, repo, last_sha, head_sha, token)
    except Exception as e:
        console.print(
            f"[dim yellow]Could not check whether {last_sha[:7]} is still an "
            f"ancestor of head ({e}) — assuming it is[/dim yellow]"
        )
        return False


@app.command()
def review(
    pr_url: str = typer.Argument(help="GitHub PR URL"),
    model: str = typer.Option("gemini/gemini-3.1-flash-lite", "--model", "-m", help="LLM model for specialists"),
    lead_model: str = typer.Option(None, "--lead-model", help="LLM model for lead reviewer (defaults to --model)"),
    profile: str = typer.Option("default", "--profile", "-p", help="Review profile: default, enterprise"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON result"),
    post: bool = typer.Option(False, "--post", help="Post review as GitHub PR comment"),
    force: bool = typer.Option(
        False, "--force",
        help="Review even when no files changed since the last review (on-demand '/vigil review')",
    ),
    reason: str = typer.Option(
        "", "--reason",
        help="Why this review was requested; recorded in the run log",
    ),
):
    """Review a GitHub pull request with multi-persona specialist team."""
    # Validate profile
    if profile not in PROFILES:
        console.print(f"[red]Unknown profile:[/red] {profile}. Available: {', '.join(PROFILES)}")
        raise typer.Exit(1)

    review_profile = PROFILES[profile]

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        console.print("[red]Error:[/red] Set GITHUB_TOKEN environment variable.")
        raise typer.Exit(1)

    # Fetch PR
    console.print("[dim]Fetching PR...[/dim]")
    try:
        owner, repo, pr_number = parse_pr_url(pr_url)
        pr_data = get_pr_data(owner, repo, pr_number, token)
    except Exception as e:
        console.print(f"[red]Error fetching PR:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"[bold]{pr_data['title']}[/bold]")
    console.print(
        f"[dim]{pr_data['author']} · "
        f"+{pr_data['additions']} -{pr_data['deletions']} · "
        f"{pr_data['changed_files']} files[/dim]"
    )
    console.print(f"[dim]Profile: {review_profile.name} ({len(review_profile.specialists)} specialists)[/dim]\n")

    # Fetch PR conversation (comments + prior reviews) so specialists and the
    # lead reviewer can cross-check factual claims in the diff/description
    # against what's already been said in the thread. Best-effort: a fetch
    # failure degrades to no conversation context, not a review failure.
    try:
        conversation_comments = fetch_pr_conversation_comments(owner, repo, pr_number, token)
        conversation_reviews = fetch_all_pr_reviews(owner, repo, pr_number, token)
        pr_data["conversation"] = build_conversation_context(
            conversation_comments,
            conversation_reviews,
            head_sha=pr_data["head_sha"],
        )
        if pr_data["conversation"]:
            console.print(f"[dim]{len(conversation_comments)} conversation comment(s), {len(conversation_reviews)} review(s) fetched for context[/dim]")
    except Exception as e:
        console.print(f"[dim yellow]Could not fetch PR conversation: {e}[/dim yellow]")
        pr_data["conversation"] = ""

    # --- Pre-review pipeline: incremental review, resolve, dedup ---
    last_sha = None
    outstanding_blocks: list[dict] = []
    settled_verdict_at_head = True
    existing_comments: list[dict] = []
    review_diff_text = pr_data["diff"]

    if post:
        try:
            # Sibling of get_last_reviewed_sha that keeps the review *state*
            # the SHA alone collapses away (issue #49). One fetch, not two.
            review_state = get_vigil_review_state(
                owner, repo, pr_number, token, pr_data["head_sha"],
            )
            last_sha = review_state.last_reviewed_sha
            outstanding_blocks = review_state.outstanding_blocks
            settled_verdict_at_head = review_state.settled_verdict_at_head
        except Exception as e:
            console.print(f"[dim yellow]Could not check previous reviews: {e}[/dim yellow]")

    if last_sha:
        console.print(f"[dim]Previous review at commit {last_sha[:7]}[/dim]")

        # Resolve threads with "resolved" replies
        dismissed = 0
        try:
            dismissed = resolve_dismissed_threads(owner, repo, pr_number, token)
            if dismissed:
                console.print(f"[dim]Resolved {dismissed} dismissed thread(s)[/dim]")
        except Exception as e:
            console.print(f"[dim yellow]Could not resolve dismissed threads: {e}[/dim yellow]")

        # Get incremental changes and resolve addressed threads
        try:
            changed_files = get_changed_files_between_commits(
                owner, repo, last_sha, pr_data["head_sha"], token,
            )
            if not changed_files:
                # No new commits. Ordinarily that means there is nothing to say
                # and skipping is correct — but a PR can be sitting on a verdict
                # only a fresh review can clear, and until this gate existed
                # there was no way back in (issue #49).
                reasons = _rereview_reasons(
                    forced=force,
                    reason=reason,
                    outstanding_blocks=outstanding_blocks,
                    settled_verdict_at_head=settled_verdict_at_head,
                    resolved_threads=dismissed,
                )
                if not reasons:
                    console.print("[dim]No files changed since last review — skipping[/dim]")
                    raise typer.Exit(0)
                console.print(
                    "[dim]No files changed since last review, but re-reviewing: "
                    f"{'; '.join(reasons)}[/dim]"
                )
            elif _history_diverged(owner, repo, last_sha, pr_data["head_sha"], token):
                # The last-reviewed commit is no longer an ancestor of head:
                # the branch was rebased or force-pushed, so `changed_files`
                # above is the whole PR against the merge base, not what
                # moved since the last review. Treat the round as a fresh
                # review — the review itself is unaffected (it always uses the
                # full base-to-head diff), but thread auto-resolution is
                # skipped rather than run against evidence that does not mean
                # what it says (F2iLLC/vigil#74).
                console.print(
                    f"[dim yellow]History diverged since {last_sha[:7]} "
                    "(rebase or force-push) — reviewing fresh and leaving "
                    "existing threads for this round to re-evaluate"
                    "[/dim yellow]"
                )
            else:
                console.print(f"[dim]Incremental review: {len(changed_files)} file(s) changed since {last_sha[:7]}[/dim]")

                # Auto-resolve threads at changed lines
                # Build line map ONLY for changed files (to auto-resolve outdated threads)
                incremental_lines = commentable_lines(pr_data["diff"])
                changed_set = set(changed_files)
                changed_line_map = {f: lines for f, lines in incremental_lines.items() if f in changed_set}
                resolved = resolve_addressed_threads(
                    owner, repo, pr_number, token, changed_line_map,
                )
                if resolved:
                    console.print(f"[dim]Auto-resolved {resolved} outdated thread(s)[/dim]")

            # IMPORTANT: Review the FULL PR diff, not just changed files.
            # This ensures we see all commits in the PR, not just the latest one.
            # The full diff is against the base branch (e.g., main), so it includes
            # all changes from all commits, which is what we want. This holds for
            # every re-review path above, including the no-new-commits ones.
            review_diff_text = pr_data["diff"]

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[dim yellow]Incremental diff failed (force-push?), falling back to full review: {e}[/dim yellow]")
            review_diff_text = pr_data["diff"]

        # Fetch existing comments for deduplication (incl. resolved threads)
        try:
            existing_comments = fetch_all_vigil_comments(owner, repo, pr_number, token)
            if existing_comments:
                console.print(f"[dim]{len(existing_comments)} existing Vigil comment(s) for dedup (incl. resolved)[/dim]")
        except Exception as e:
            console.print(f"[dim yellow]Could not fetch existing comments: {e}[/dim yellow]")

    # Signal review start
    rocket_id = None
    if post:
        rocket_id = react(owner, repo, pr_number, token, "rocket")
        if rocket_id:
            console.print("[dim]Rocket sent[/dim]")

    # Run review on the appropriate diff (full or incremental)
    repo_key = f"{owner}/{repo}"
    console.print("[bold]Specialist reviews:[/bold]")
    try:
        result = review_diff(
            review_diff_text,
            pr_data,
            profile=review_profile,
            model=model,
            lead_model=lead_model,
            on_specialist_done=_print_specialist_done,
            repo_key=repo_key,
        )
    except Exception as e:
        console.print(f"[red]Error during review:[/red] {e}")
        raise typer.Exit(1)

    # Audit log - always write, regardless of output mode
    try:
        db_path = write_audit_entry(result, profile=profile)
        console.print(f"[dim]Audit logged -> {db_path}[/dim]")
    except Exception as e:
        console.print(f"[dim yellow]Audit log failed: {e}[/dim yellow]")

    # JSON output mode
    if output_json:
        console.print(result.model_dump_json(indent=2))
        return

    # --- Pretty output ---

    # Final decision
    console.print()
    color = DECISION_COLORS.get(result.decision, "white")
    console.print(Panel(result.summary, title=f"[{color}]{result.decision}[/{color}]"))

    # Specialist findings (grouped by persona)
    for v in result.specialist_verdicts:
        if v.findings:
            _print_findings(v.findings, f"{v.persona} Findings")

    # Lead findings
    _print_findings(result.lead_findings, "Lead Review Findings")

    # Observations (non-blocking, should become issues per CR-002)
    if result.observations:
        console.print(f"\n[bold yellow]Observations ({len(result.observations)} - non-blocking, worth tracking):[/bold yellow]")
        for obs in result.observations:
            loc = obs.file + (f":{obs.line}" if obs.line else "")
            console.print(f"  [dim]{loc}[/dim] [{obs.category}] {obs.message}")

    # Summary stats
    _print_summary_stats(result)

    # Post to GitHub
    if post:
        console.print("\n[dim]Posting review to GitHub...[/dim]")
        # Enable debug logging for github_review module
        logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")

        # Create issues for observations before posting the review
        observation_issues: list[tuple[Finding, str]] | None = None
        if result.observations:
            console.print(f"[dim]Creating issues for {len(result.observations)} observation(s)...[/dim]")
            try:
                observation_issues = create_issues_for_observations(
                    owner, repo, token, result,
                    pr_url=pr_data.get("url", f"https://github.com/{owner}/{repo}/pull/{pr_number}"),
                )
                if observation_issues:
                    console.print(f"[dim]{len(observation_issues)} observation(s) tracked as issues[/dim]")
            except Exception as e:
                console.print(f"[dim yellow]Could not create observation issues: {e}[/dim yellow]")

        review_posted = False
        post_outcome: dict = {}
        try:
            review_url = post_review(
                owner, repo, pr_number, result, token,
                diff=pr_data["diff"],
                existing_comments=existing_comments or None,
                observation_issues=observation_issues,
                outcome=post_outcome,
            )
            console.print(f"[green]Review posted:[/green] {review_url}")
            review_posted = True
        except Exception as e:
            console.print(f"[red]Error posting review:[/red] {e}")

        # --- Clean up Vigil's own leftovers: stale blocks (issue #48) and
        # --- open review threads (issue #61) ---
        # Only ever on the way UP: an APPROVE that GitHub actually accepted AS
        # an approval. Three guards, all of which must hold, and all phrased
        # positively so that missing or unexpected data fails closed:
        #   1. the replacement review posted without raising,
        #   2. this run's verdict is APPROVE,
        #   3. GitHub accepted it as event=APPROVE — NOT a degraded COMMENT or
        #      an issue-comment fallback. A COMMENT review does not clear a
        #      block, so dismissing the old one there would leave the PR
        #      completely unguarded. That is the worst failure mode available
        #      in this change, hence the explicit equality check.
        # A REQUEST_CHANGES verdict deliberately changes nothing: Vigil
        # standing its ground is correct, and the escalation path exists for it.
        if review_posted and result.decision == "APPROVE":
            if post_outcome.get("submitted_event") == "APPROVE":
                head_sha = pr_data["head_sha"]
                # Belt and braces: dismiss_stale_vigil_blocks is written not to
                # raise, but this cleanup must never be able to fail a review
                # that has already posted. Vigil gates merges fleet-wide.
                try:
                    dismissed_ids = dismiss_stale_vigil_blocks(
                        owner, repo, pr_number, token,
                        message=(
                            f"Superseded: Vigil re-reviewed {head_sha} and approved. "
                            "This blocking review is withdrawn by its author."
                        ),
                    )
                    if dismissed_ids:
                        console.print(
                            f"[dim]Dismissed {len(dismissed_ids)} stale Vigil block(s) "
                            f"superseded by the approval at {head_sha[:7]}[/dim]"
                        )
                except Exception as e:
                    console.print(
                        f"[dim yellow]Could not dismiss stale Vigil block(s): {e}[/dim yellow]"
                    )

                # --- Resolve Vigil's own open threads (issue #61) ---
                # Same three guards, same reasoning, deliberately inside the
                # same accepted-APPROVE branch: an APPROVE that degraded to a
                # COMMENT has approved nothing, and resolving threads there
                # would clear the visible findings while the PR stays blocked —
                # strictly worse than the bug this fixes.
                #
                # Scope is every open Vigil thread on the PR, not this run's.
                # session_id is per-SPECIALIST-RUN, not per-review-round
                # (models.py: PersonaVerdict.session_id), so the stranded
                # threads this exists to clear necessarily carry OTHER session
                # IDs; a current-session-only filter would resolve nothing in
                # the exact reported scenario. Human threads are excluded by
                # the VGL marker gate inside the resolver.
                try:
                    thread_count = resolve_vigil_threads_on_approval(
                        owner, repo, pr_number, token,
                    )
                    if thread_count:
                        console.print(
                            f"[dim]Resolved {thread_count} open Vigil thread(s) "
                            f"cleared by the approval at {head_sha[:7]}[/dim]"
                        )
                # Belt and braces again: this cleanup must never be able to
                # fail a review that has already posted.
                except Exception as e:
                    console.print(
                        f"[dim yellow]Could not resolve open Vigil thread(s): {e}[/dim yellow]"
                    )
            else:
                console.print(
                    "[dim yellow]Approval did not post as an APPROVE event "
                    f"({post_outcome.get('submitted_event', 'unknown')}) — "
                    "leaving prior Vigil blocks and threads in place[/dim yellow]"
                )

        # Swap rocket for final reaction
        if rocket_id:
            remove_reaction(owner, repo, pr_number, token, rocket_id)
        if result.decision == "APPROVE":
            react(owner, repo, pr_number, token, "+1")
        elif result.decision in ("REQUEST_CHANGES", "BLOCK"):
            react(owner, repo, pr_number, token, "eyes")
        elif result.decision == DECISION_NOT_REVIEWED:
            # Without this the rocket is removed and nothing replaces it, so a
            # completed run that reviewed nothing is indistinguishable — to a
            # human or to anything watching reactions — from Vigil never
            # having run at all. That is the #79 defect in a different medium.
            react(owner, repo, pr_number, token, "confused")


@app.command(name="dismiss-resolved")
def dismiss_resolved(
    pr_url: str = typer.Argument(help="GitHub PR URL"),
):
    """Resolve Vigil comment threads that received a 'resolved' reply."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        console.print("[red]Error:[/red] Set GITHUB_TOKEN environment variable.")
        raise typer.Exit(1)

    owner, repo, pr_number = parse_pr_url(pr_url)
    count = resolve_dismissed_threads(owner, repo, pr_number, token)
    console.print(f"[dim]Resolved {count} dismissed thread(s)[/dim]")


@app.command(name="resolve-addressed")
def resolve_addressed(
    pr_url: str = typer.Argument(
        default="",
        help="GitHub PR URL (auto-detected from event context if omitted)",
    ),
):
    """Auto-resolve Vigil threads where the commented code has changed.

    Compares the current PR head against the last Vigil review commit.
    Any Vigil thread whose file+line was modified since the last review
    is resolved automatically (the code was addressed).
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        console.print("[red]Error:[/red] Set GITHUB_TOKEN environment variable.")
        raise typer.Exit(1)

    if not pr_url:
        console.print("[red]Error:[/red] PR URL required.")
        raise typer.Exit(1)

    owner, repo, pr_number = parse_pr_url(pr_url)
    pr_data = get_pr_data(owner, repo, pr_number, token)

    # Find the last Vigil review SHA
    last_sha = get_last_reviewed_sha(owner, repo, pr_number, token)
    if not last_sha:
        console.print("[dim]No previous Vigil review found — nothing to resolve[/dim]")
        raise typer.Exit(0)

    console.print(f"[dim]Last Vigil review at {last_sha[:7]}, head is {pr_data['head_sha'][:7]}[/dim]")

    dismissed = resolve_dismissed_threads(owner, repo, pr_number, token)
    if dismissed:
        console.print(f"[dim]Resolved {dismissed} dismissed thread(s)[/dim]")

    if last_sha == pr_data["head_sha"]:
        console.print("[dim]No new commits since last review — nothing to resolve[/dim]")
        raise typer.Exit(0)

    # Get files changed since last review
    try:
        changed_files = get_changed_files_between_commits(
            owner, repo, last_sha, pr_data["head_sha"], token,
        )
    except Exception as e:
        console.print(f"[dim yellow]Could not compare commits (force-push?): {e}[/dim yellow]")
        raise typer.Exit(0)

    if not changed_files:
        console.print("[dim]No files changed since last review[/dim]")
        raise typer.Exit(0)

    # Same rebase guard as the review path: after a force-push `changed_files`
    # is the whole PR, so the line map below would authorize resolving threads
    # whose code this push never touched (F2iLLC/vigil#74).
    if _history_diverged(owner, repo, last_sha, pr_data["head_sha"], token):
        console.print(
            f"[dim yellow]History diverged since {last_sha[:7]} (rebase or "
            "force-push) — not resolving threads against a comparison that no "
            "longer means 'changed since the last review'[/dim yellow]"
        )
        raise typer.Exit(0)

    console.print(f"[dim]{len(changed_files)} file(s) changed since last review[/dim]")

    # Build the line map from the full PR diff
    incremental_lines = commentable_lines(pr_data["diff"])
    changed_set = set(changed_files)
    changed_line_map = {f: lines for f, lines in incremental_lines.items() if f in changed_set}

    count = resolve_addressed_threads(owner, repo, pr_number, token, changed_line_map)
    console.print(f"[dim]Auto-resolved {count} addressed thread(s)[/dim]")

@app.command()
def serve(
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind to"),
    model: str = typer.Option("gemini/gemini-3.1-flash-lite", "--model", "-m", help="LLM model for reviews"),
    lead_model: str = typer.Option(None, "--lead-model", help="LLM model for lead reviewer"),
    profile: str = typer.Option("default", "--profile", help="Review profile"),
):
    """Start the webhook server to receive GitHub events."""
    try:
        import uvicorn
        from .webhook import create_app
    except ImportError:
        console.print("[red]Error:[/red] Webhook dependencies not installed. Run: pip install vigil[webhook]")
        raise typer.Exit(1)

    webhook_app = create_app(model=model, lead_model=lead_model, profile=profile)
    console.print(f"[bold green]Vigil webhook server starting on {host}:{port}[/bold green]")
    console.print(f"[dim]Model: {model} | Profile: {profile}[/dim]")
    uvicorn.run(webhook_app, host=host, port=port)


@app.command()
def profiles():
    """List available review profiles."""
    for name, p in PROFILES.items():
        console.print(f"[bold]{name}[/bold] - {p.description}")
        for s in p.specialists:
            console.print(f"  - {s.name}: {s.focus}")


@app.command()
def decisions(
    repo: str = typer.Argument(help="Repository in 'owner/repo' format"),
    file: str = typer.Option(None, "--file", "-f", help="Filter by file path"),
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    remove_id: int = typer.Option(None, "--remove", help="Remove a specific decision by ID"),
    clear: bool = typer.Option(False, "--clear", help="Clear all decisions for the repo"),
):
    """Browse, filter, and manage the decision log for a repository.

    The decision log tracks findings that have been acknowledged (resolved,
    wontfix, or marked as false positives). Vigil suppresses these patterns
    in future reviews. Use --remove to re-enable specific patterns as the
    repo matures.
    """
    if remove_id is not None:
        if remove_decision(repo, remove_id):
            console.print(f"[green]Removed decision #{remove_id}[/green] — pattern will be flagged again")
        else:
            console.print(f"[red]Decision #{remove_id} not found[/red] (or doesn't belong to {repo})")
        return

    if clear:
        confirm = typer.confirm(
            f"Clear ALL decisions for {repo}"
            + (f" (file={file})" if file else "")
            + (f" (category={category})" if category else "")
            + "? This will re-enable all suppressed patterns."
        )
        if not confirm:
            console.print("[dim]Cancelled[/dim]")
            return
        count = clear_decisions(repo, file_path=file, category=category)
        console.print(f"[green]Cleared {count} decision(s)[/green]")
        return

    # List decisions
    records = get_decisions(repo, file_path=file, category=category)
    if not records:
        console.print(f"[dim]No decisions logged for {repo}[/dim]")
        if file or category:
            console.print("[dim]Try without --file/--category filters[/dim]")
        return

    table = Table(title=f"Decision Log — {repo}", show_header=True, padding=(0, 1))
    table.add_column("ID", width=5, style="dim")
    table.add_column("File", width=28)
    table.add_column("Category", width=14)
    table.add_column("Decision", width=14)
    table.add_column("Reason", width=40)
    table.add_column("Date", width=12, style="dim")

    decision_colors = {
        "accepted": "green",
        "wontfix": "yellow",
        "false_positive": "cyan",
    }
    for r in records:
        decision = r["decision"]
        color = decision_colors.get(decision, "white")
        reason = r.get("reason", "") or ""
        if len(reason) > 38:
            reason = reason[:35] + "..."
        date = r.get("created_at", "")[:10]  # YYYY-MM-DD
        decided_by = r.get("decided_by", "")
        if decided_by:
            reason = f"@{decided_by}: {reason}" if reason else f"@{decided_by}"
            if len(reason) > 38:
                reason = reason[:35] + "..."
        table.add_row(
            str(r["id"]),
            r["file_path"],
            r["category"],
            f"[{color}]{decision}[/{color}]",
            reason,
            date,
        )

    console.print(table)
    console.print(f"\n[dim]{len(records)} decision(s) · Use --remove <ID> to re-enable a pattern[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()

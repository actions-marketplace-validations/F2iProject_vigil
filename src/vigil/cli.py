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
    fetch_vigil_comments,
    get_last_reviewed_sha,
    resolve_addressed_threads,
    resolve_dismissed_threads,
)
from .diff_parser import commentable_lines, parse_diff, reassemble_diff
from .github import get_changed_files_between_commits, get_pr_data, parse_pr_url
from .github_review import post_review, react, remove_reaction
from .models import Finding, PersonaVerdict, ReviewResult, Severity
from .personas import PROFILES
from .reviewer import review_diff

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
}


def _print_specialist_done(verdict: PersonaVerdict):
    """Callback: print a line as each specialist finishes."""
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


@app.command()
def review(
    pr_url: str = typer.Argument(help="GitHub PR URL"),
    model: str = typer.Option("claude-sonnet-4-6", "--model", "-m", help="LLM model for specialists"),
    lead_model: str = typer.Option(None, "--lead-model", help="LLM model for lead reviewer (defaults to --model)"),
    profile: str = typer.Option("default", "--profile", "-p", help="Review profile: default, enterprise"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON result"),
    post: bool = typer.Option(False, "--post", help="Post review as GitHub PR comment"),
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

    # --- Pre-review pipeline: incremental review, resolve, dedup ---
    last_sha = None
    existing_comments: list[dict] = []
    review_diff_text = pr_data["diff"]

    if post:
        try:
            last_sha = get_last_reviewed_sha(owner, repo, pr_number, token)
        except Exception as e:
            console.print(f"[dim yellow]Could not check previous reviews: {e}[/dim yellow]")

    if last_sha:
        console.print(f"[dim]Previous review at commit {last_sha[:7]}[/dim]")

        # Resolve threads with "resolved" replies
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
                console.print("[dim]No files changed since last review — skipping[/dim]")
                raise typer.Exit(0)

            console.print(f"[dim]Incremental review: {len(changed_files)} file(s) changed since {last_sha[:7]}[/dim]")

            # Auto-resolve threads at changed lines
            incremental_lines = commentable_lines(pr_data["diff"])
            # Narrow to only files that changed since last review
            changed_set = set(changed_files)
            changed_line_map = {f: lines for f, lines in incremental_lines.items() if f in changed_set}
            resolved = resolve_addressed_threads(
                owner, repo, pr_number, token, changed_line_map,
            )
            if resolved:
                console.print(f"[dim]Auto-resolved {resolved} outdated thread(s)[/dim]")

            # Filter diff to only changed files for specialist review
            all_hunks = parse_diff(pr_data["diff"])
            filtered_hunks = [h for h in all_hunks if h.path in changed_set]
            review_diff_text = reassemble_diff(filtered_hunks)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[dim yellow]Incremental diff failed (force-push?), falling back to full review: {e}[/dim yellow]")
            review_diff_text = pr_data["diff"]

        # Fetch existing comments for deduplication
        try:
            existing_comments = fetch_vigil_comments(owner, repo, pr_number, token)
            if existing_comments:
                console.print(f"[dim]{len(existing_comments)} existing Vigil comment(s) for dedup[/dim]")
        except Exception as e:
            console.print(f"[dim yellow]Could not fetch existing comments: {e}[/dim yellow]")

    # Signal review start
    rocket_id = None
    if post:
        rocket_id = react(owner, repo, pr_number, token, "rocket")
        if rocket_id:
            console.print("[dim]Rocket sent[/dim]")

    # Run review on the appropriate diff (full or incremental)
    console.print("[bold]Specialist reviews:[/bold]")
    try:
        result = review_diff(
            review_diff_text,
            pr_data,
            profile=review_profile,
            model=model,
            lead_model=lead_model,
            on_specialist_done=_print_specialist_done,
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
    total_findings = sum(len(v.findings) for v in result.specialist_verdicts) + len(result.lead_findings)
    total_obs = len(result.observations)
    approvals = sum(1 for v in result.specialist_verdicts if v.decision == "APPROVE")
    total = len(result.specialist_verdicts)
    console.print(f"\n[dim]{approvals}/{total} specialists approved · {total_findings} findings · {total_obs} observations[/dim]")

    # Post to GitHub
    if post:
        console.print("\n[dim]Posting review to GitHub...[/dim]")
        # Enable debug logging for github_review module
        logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")
        try:
            review_url = post_review(
                owner, repo, pr_number, result, token,
                diff=pr_data["diff"],
                existing_comments=existing_comments or None,
            )
            console.print(f"[green]Review posted:[/green] {review_url}")
        except Exception as e:
            console.print(f"[red]Error posting review:[/red] {e}")

        # Swap rocket for final reaction
        if rocket_id:
            remove_reaction(owner, repo, pr_number, token, rocket_id)
        if result.decision == "APPROVE":
            react(owner, repo, pr_number, token, "+1")
        elif result.decision in ("REQUEST_CHANGES", "BLOCK"):
            react(owner, repo, pr_number, token, "eyes")


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


@app.command()
def profiles():
    """List available review profiles."""
    for name, p in PROFILES.items():
        console.print(f"[bold]{name}[/bold] - {p.description}")
        for s in p.specialists:
            console.print(f"  - {s.name}: {s.focus}")


def main():
    app()


if __name__ == "__main__":
    main()

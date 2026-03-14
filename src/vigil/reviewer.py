"""Multi-persona review engine with parallel specialist dispatch."""

import json
import secrets
import time
from typing import Callable

from litellm import completion

from .alerts import send_alerts_for_verdicts
from .diff_parser import diff_summary, filter_hunks, parse_diff, reassemble_diff
from .models import Finding, PersonaVerdict, ReviewResult, Severity
from .personas import Persona, ReviewProfile

MAX_RETRIES = 5
INITIAL_BACKOFF = 5  # seconds


def _parse_json_response(text: str) -> dict:
    """Parse JSON from LLM response, handling code fences and trailing text."""
    text = text.strip()
    # Strip markdown code fences
    if text.startswith("```json"):
        text = text[len("```json"):]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # Try normal parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Handle trailing text after valid JSON (common with some models)
    # Find the last closing brace and try parsing up to there
    depth = 0
    end = -1
    for i, ch in enumerate(text):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end > 0:
        return json.loads(text[:end])

    raise json.JSONDecodeError("No valid JSON object found", text, 0)


def _parse_findings(raw_list: list[dict]) -> list[Finding]:
    """Parse findings with defensive handling for LLM output quirks."""
    results = []
    for f in raw_list:
        # Ensure 'file' is a string (LLMs sometimes return null or objects)
        if not isinstance(f.get("file"), str):
            f["file"] = str(f.get("file") or "unknown")
        # Coerce line to int or None
        if f.get("line") is not None:
            try:
                f["line"] = int(f["line"])
            except (ValueError, TypeError):
                f["line"] = None
        results.append(Finding(**f))
    return results


def _gen_session_id() -> str:
    """Generate a short agent session ID like VGL-a3f8b2."""
    return f"VGL-{secrets.token_hex(3)}"


def _call_llm_with_retry(messages: list[dict], model: str, **kwargs):
    """Call litellm completion with exponential backoff on rate limits."""
    for attempt in range(MAX_RETRIES):
        try:
            return completion(model=model, messages=messages, **kwargs)
        except Exception as e:
            err_str = str(e).lower()
            if "rate_limit" in err_str or "429" in err_str:
                wait = INITIAL_BACKOFF * (2 ** attempt)
                time.sleep(wait)
            else:
                raise
    # Final attempt — let it raise
    return completion(model=model, messages=messages, **kwargs)


def _build_pr_context_block(diff: str, pr_context: dict, file_summary: str = "") -> str:
    """Format PR metadata + diff for inclusion in review prompts."""
    summary_section = ""
    if file_summary:
        summary_section = f"""
### All Changed Files (full PR)
```
{file_summary}
```
"""
    return f"""## PR: {pr_context['title']}

**Author:** {pr_context['author']}
**Branch:** {pr_context['head']} -> {pr_context['base']}
**Stats:** +{pr_context['additions']} -{pr_context['deletions']} across {pr_context['changed_files']} files

### Description
{pr_context.get('body') or 'No description provided.'}
{summary_section}
### Diff (files relevant to your domain)
```diff
{diff}
```"""


def _run_specialist(persona: Persona, pr_block: str, model: str, delay: float = 0) -> PersonaVerdict:
    """Run a single specialist review. Called in parallel."""
    if delay > 0:
        time.sleep(delay)

    response = _call_llm_with_retry(
        messages=[
            {"role": "system", "content": persona.system_prompt},
            {"role": "user", "content": pr_block},
        ],
        model=model,
        response_format={"type": "json_object"},
        temperature=0.2,
    )

    content = response.choices[0].message.content
    if not content:
        raise ValueError(f"Empty response from model for {persona.name}")
    raw = _parse_json_response(content)

    findings = _parse_findings(raw.get("findings", []))
    observations = _parse_findings(raw.get("observations", []))
    checks = raw.get("checks", {})
    decision = raw.get("decision", "APPROVE")

    return PersonaVerdict(
        persona=persona.name,
        session_id=_gen_session_id(),
        decision=decision,
        checks=checks,
        findings=findings,
        observations=observations,
    )


def _run_lead_review(
    lead_prompt: str,
    pr_block: str,
    verdicts: list[PersonaVerdict],
    model: str,
) -> tuple[str, str, list[Finding]]:
    """Run the lead review after all specialists report."""
    verdicts_text = ""
    for v in verdicts:
        checks_str = ", ".join(f"{k}: {val}" for k, val in v.checks.items())
        findings_str = ""
        if v.findings:
            findings_str = "\n".join(
                f"  - [{f.severity.value}] {f.file}:{f.line or '?'} -- {f.message}"
                for f in v.findings
            )
        verdicts_text += f"""
### {v.persona} [{v.session_id}]: {v.decision}
Checks: {checks_str}
{"Findings:\n" + findings_str if findings_str else "No findings."}
"""

    user_message = f"""{pr_block}

---

## Specialist Verdicts
{verdicts_text}

Review this PR as the final gate. Consider the specialist verdicts above."""

    response = _call_llm_with_retry(
        messages=[
            {"role": "system", "content": lead_prompt},
            {"role": "user", "content": user_message},
        ],
        model=model,
        response_format={"type": "json_object"},
        temperature=0.2,
    )

    raw = _parse_json_response(response.choices[0].message.content)
    decision = raw.get("decision", "APPROVE")
    summary = raw.get("summary", "")
    findings = _parse_findings(raw.get("findings", []))
    return decision, summary, findings


def review_diff(
    diff: str,
    pr_context: dict,
    profile: ReviewProfile,
    model: str = "claude-sonnet-4-6",
    lead_model: str | None = None,
    on_specialist_done: Callable[[PersonaVerdict], None] | None = None,
    repo_key: str = "",
) -> ReviewResult:
    """Run the full multi-persona review pipeline.

    1. Dispatch all specialists with staggered starts
    2. Collect verdicts
    3. Run lead reviewer with all verdicts
    4. Return aggregated result
    """
    lead_model = lead_model or model

    # --- Parse diff into per-file hunks for targeted routing ---
    all_hunks = parse_diff(diff)
    full_summary = diff_summary(all_hunks)

    # --- Step 1: Sequential specialist reviews ---
    # Each specialist gets only the files matching their patterns
    verdicts: list[PersonaVerdict] = []

    for persona in profile.specialists:
        # Filter diff to this specialist's domain
        if persona.file_patterns:
            specialist_hunks = filter_hunks(all_hunks, persona.file_patterns)
            specialist_diff = reassemble_diff(specialist_hunks)
        else:
            specialist_hunks = all_hunks
            specialist_diff = diff

        # Build PR context with filtered diff + file summary
        pr_block = _build_pr_context_block(specialist_diff, pr_context, full_summary)

        if not specialist_diff.strip():
            # No relevant files for this specialist — auto-approve
            verdicts.append(
                PersonaVerdict(
                    persona=persona.name,
                    session_id=_gen_session_id(),
                    decision="APPROVE",
                    checks={},
                    findings=[],
                    observations=[],
                )
            )
            if on_specialist_done:
                on_specialist_done(verdicts[-1])
            continue

        try:
            verdict = _run_specialist(persona, pr_block, model)

            # Non-blocking personas: move findings to observations, force APPROVE
            if not persona.blocking and verdict.findings:
                verdict.observations = verdict.findings + verdict.observations
                verdict.findings = []
                verdict.decision = "APPROVE"

            verdicts.append(verdict)
            if on_specialist_done:
                on_specialist_done(verdict)
        except Exception as e:
            verdicts.append(
                PersonaVerdict(
                    persona=persona.name,
                    session_id=_gen_session_id(),
                    decision="ERROR",
                    checks={},
                    findings=[
                        Finding(
                            file="N/A",
                            severity=Severity.medium,
                            category="reviewer_error",
                            message=f"Specialist review failed: {e}",
                        )
                    ],
                    observations=[],
                )
            )

    # --- Step 1.5: Filter known decisions ---
    if repo_key:
        try:
            from .decision_log import filter_known_findings
            for v in verdicts:
                orig_findings = len(v.findings)
                orig_obs = len(v.observations)
                v.findings = filter_known_findings(repo_key, v.findings)
                v.observations = filter_known_findings(repo_key, v.observations)
                suppressed = (orig_findings - len(v.findings)) + (orig_obs - len(v.observations))
                if suppressed:
                    import logging
                    logging.getLogger(__name__).info(
                        "Suppressed %d known finding(s) for %s", suppressed, v.persona
                    )
        except Exception:
            pass  # decision log is best-effort

    # --- Step 1.6: Send email alerts for alert-enabled personas ---
    alert_personas = {p.name for p in profile.specialists if p.alert}
    if alert_personas:
        try:
            sent = send_alerts_for_verdicts(
                verdicts, alert_personas,
                pr_url=pr_context.get("url", ""),
                pr_title=pr_context.get("title", ""),
            )
            if sent:
                import logging
                logging.getLogger(__name__).info("Sent %d alert email(s)", sent)
        except Exception:
            pass  # alerting is best-effort, never blocks the review

    # --- Step 2: Lead review (gets file summary + specialist verdicts, not full diff) ---
    lead_pr_block = _build_pr_context_block(diff, pr_context, full_summary)
    decision, summary, lead_findings = _run_lead_review(
        profile.lead_prompt, lead_pr_block, verdicts, lead_model
    )

    # --- Step 3: Aggregate observations with persona tracking ---
    all_observations: list[Finding] = []
    observation_sources: list[tuple[str, Finding]] = []
    for v in verdicts:
        for obs in v.observations:
            all_observations.append(obs)
            observation_sources.append((v.persona, obs))

    return ReviewResult(
        decision=decision,
        summary=summary,
        commit_sha=pr_context.get("head_sha", ""),
        pr_url=pr_context.get("url", ""),
        model=model,
        specialist_verdicts=verdicts,
        lead_findings=lead_findings,
        observations=all_observations,
        observation_sources=observation_sources,
    )

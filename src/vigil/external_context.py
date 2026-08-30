"""Pluggable external review-context provider (F2iLLC/vigil#47).

Vigil reviews a PR against the PR itself: title, description, conversation,
diff. A claim that is only falsifiable against material *outside* the PR — a
completion report asserting a milestone is done while the code is an empty
stub — has no evidence base here, so no reviewer can challenge it.

This module is that missing seam, and nothing more. An operator configures
one provider; Vigil invokes it once per review with the PR's coordinates and
receives opaque text back. Vigil never parses, models, validates, or
interprets the payload, and has no vocabulary for any particular external
system. Text in, labeled as untrusted evidence, personas reason over it.

Deliberate non-goals (they are the design, not omissions):

* **No knowledge of any specific external system.** No schema, no record
  types, no per-service client, no per-service credential. There is exactly
  one opaque operator-supplied token, forwarded verbatim.
* **Read-only by construction.** Nothing is ever written back.
* **No injection detection.** A payload that tries to instruct the reviewer
  is neutralized by the block's framing (see
  ``reviewer._build_pr_context_block``) and otherwise ignored. Promoting it
  to a finding would let a hostile or merely buggy provider manufacture
  findings on an unrelated PR.
* **Fail open, always.** A missing, empty, slow, crashing, or garbage
  provider degrades to "no external context". This seam must never block or
  fail a review — Vigil gates merges fleet-wide.

Configuration (environment variables; unset disables the seam entirely).
This mirrors the optional escalation-delivery hook in ``alerts.py``: a
generic, opt-in integration point that keeps deployment-specific concerns
out of the codebase.

    VIGIL_CONTEXT_PROVIDER  — either a command to execute (argv-parsed, run
                              without a shell) or an ``http://``/``https://``
                              endpoint to POST the PR coordinates to.
    VIGIL_CONTEXT_LABEL     — optional short label naming the source; shown
                              in the prompt so a reviewer knows where the
                              evidence came from.
    VIGIL_CONTEXT_TOKEN     — one opaque operator-supplied token. Exported to
                              a command provider in its environment; sent to
                              an HTTP provider as ``X-Vigil-Context-Token``.
    VIGIL_CONTEXT_TIMEOUT   — seconds before the provider is abandoned
                              (default 20, clamped to 1-60).
    VIGIL_CONTEXT_MAX_CHARS — payload cap (default 8000, clamped to
                              500-50000). Truncation is deterministic and is
                              made visible to the reviewer, never silent.

The provider contract, in both forms:

    request   {"repo": "owner/repo", "pr_number": 12, "head_sha": "abc…",
               "changed_paths": ["src/a.py", …]}
    response  opaque text (stdout / response body), plus an optional short
              label (``X-Vigil-Context-Label`` response header for HTTP;
              VIGIL_CONTEXT_LABEL for a command).

A command provider additionally receives ``VIGIL_PR_REPO``,
``VIGIL_PR_NUMBER``, ``VIGIL_PR_HEAD_SHA``, and newline-separated
``VIGIL_PR_CHANGED_PATHS`` in its environment, so trivial providers can be
written without a JSON parser.
"""

import json
import logging
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Mapping

import httpx

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 20.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 60.0

DEFAULT_MAX_CHARS = 8000
MIN_MAX_CHARS = 500
MAX_MAX_CHARS = 50000

MAX_LABEL_CHARS = 60
DEFAULT_LABEL = "unlabeled external source"

TOKEN_HEADER = "X-Vigil-Context-Token"
LABEL_HEADER = "X-Vigil-Context-Label"


@dataclass(frozen=True)
class ProviderConfig:
    """Resolved provider configuration. ``target`` is a command or a URL."""

    target: str
    label: str = ""
    token: str = ""
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    max_chars: int = DEFAULT_MAX_CHARS

    @property
    def is_http(self) -> bool:
        return self.target.startswith(("http://", "https://"))


@dataclass(frozen=True)
class ExternalContext:
    """Opaque provider output, ready to be rendered as review evidence.

    ``text`` is already capped and, when it was capped, already carries the
    visible truncation marker — the reviewer must never be shown a silently
    shortened payload. ``kept_chars`` counts the payload characters that
    survived, excluding that marker, so the prompt can state the real ratio.
    """

    text: str
    label: str = DEFAULT_LABEL
    truncated: bool = False
    original_chars: int = 0
    kept_chars: int = 0


@dataclass(frozen=True)
class ProviderRequest:
    """PR coordinates handed to the provider. This is the whole request."""

    repo: str
    pr_number: int
    head_sha: str
    changed_paths: list[str] = field(default_factory=list)

    def as_payload(self) -> dict:
        return {
            "repo": self.repo,
            "pr_number": self.pr_number,
            "head_sha": self.head_sha,
            "changed_paths": list(self.changed_paths),
        }


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def sanitize_label(raw: str) -> str:
    """Reduce a provider-supplied label to one short, inert line.

    The label is the only provider-controlled text rendered *outside* the
    evidence fence, so it is flattened to a single line, stripped of
    backticks and control characters, and hard-capped. A provider cannot use
    it to forge prompt structure.
    """
    if not raw:
        return ""
    flattened = " ".join(str(raw).split())
    cleaned = "".join(
        ch for ch in flattened if ch.isprintable() and ch not in "`"
    ).strip()
    if len(cleaned) > MAX_LABEL_CHARS:
        cleaned = cleaned[: MAX_LABEL_CHARS - 1].rstrip() + "…"
    return cleaned


def truncate_context(text: str, max_chars: int) -> tuple[str, bool, int]:
    """Cap ``text`` deterministically, keeping the truncation visible.

    Always keeps the first ``max_chars`` characters — no summarizing, no
    sampling, no dependence on content — and appends a marker naming both
    the kept and the original size. Returns ``(text, truncated, original)``.
    """
    original_chars = len(text)
    if original_chars <= max_chars:
        return text, False, original_chars
    kept = text[:max_chars]
    marker = (
        f"\n\n[TRUNCATED BY VIGIL: showing the first {max_chars:,} of "
        f"{original_chars:,} characters supplied by the external context "
        f"provider. The remainder was NOT reviewed and must not be assumed "
        f"to agree or disagree with anything above.]"
    )
    return kept + marker, True, original_chars


def load_provider_config(
    env: Mapping[str, str] | None = None,
) -> ProviderConfig | None:
    """Build a :class:`ProviderConfig` from the environment.

    Returns ``None`` when no provider is configured, which is the normal
    case and disables the seam completely.
    """
    env = os.environ if env is None else env

    target = (env.get("VIGIL_CONTEXT_PROVIDER") or "").strip()
    if not target:
        return None

    timeout = DEFAULT_TIMEOUT_SECONDS
    raw_timeout = (env.get("VIGIL_CONTEXT_TIMEOUT") or "").strip()
    if raw_timeout:
        try:
            timeout = _clamp(float(raw_timeout), MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)
        except ValueError:
            log.warning(
                "VIGIL_CONTEXT_TIMEOUT=%r is not a number — using %ss",
                raw_timeout, DEFAULT_TIMEOUT_SECONDS,
            )

    max_chars = DEFAULT_MAX_CHARS
    raw_max = (env.get("VIGIL_CONTEXT_MAX_CHARS") or "").strip()
    if raw_max:
        try:
            max_chars = int(_clamp(int(raw_max), MIN_MAX_CHARS, MAX_MAX_CHARS))
        except ValueError:
            log.warning(
                "VIGIL_CONTEXT_MAX_CHARS=%r is not an integer — using %s",
                raw_max, DEFAULT_MAX_CHARS,
            )

    return ProviderConfig(
        target=target,
        label=sanitize_label(env.get("VIGIL_CONTEXT_LABEL") or ""),
        token=(env.get("VIGIL_CONTEXT_TOKEN") or "").strip(),
        timeout=timeout,
        max_chars=max_chars,
    )


def invoke_command_provider(
    config: ProviderConfig, request: ProviderRequest
) -> tuple[str, str]:
    """Run a command provider. Returns ``(text, label)``.

    The command is argv-parsed and run **without a shell**: the operator
    configures a program, not a shell snippet. A non-zero exit is treated as
    no context at all — a provider that half-failed is not evidence.
    """
    argv = shlex.split(config.target)
    if not argv:
        raise ValueError("VIGIL_CONTEXT_PROVIDER parsed to an empty command")

    child_env = dict(os.environ)
    child_env.update(
        {
            "VIGIL_PR_REPO": request.repo,
            "VIGIL_PR_NUMBER": str(request.pr_number),
            "VIGIL_PR_HEAD_SHA": request.head_sha,
            "VIGIL_PR_CHANGED_PATHS": "\n".join(request.changed_paths),
        }
    )
    if config.token:
        child_env["VIGIL_CONTEXT_TOKEN"] = config.token

    completed = subprocess.run(  # noqa: S603 — argv, shell=False, operator-configured
        argv,
        input=json.dumps(request.as_payload()),
        capture_output=True,
        text=True,
        timeout=config.timeout,
        env=child_env,
    )
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(
            f"context provider exited {completed.returncode}: {stderr[:300]}"
        )
    return completed.stdout or "", config.label


def invoke_http_provider(
    config: ProviderConfig, request: ProviderRequest
) -> tuple[str, str]:
    """POST the PR coordinates to an HTTP provider. Returns ``(text, label)``.

    Any non-2xx status is treated as no context. The response body is opaque
    text — it is never parsed, so a JSON provider simply gets its JSON read
    as text by the personas.
    """
    headers = {"Content-Type": "application/json", "Accept": "text/plain, */*"}
    if config.token:
        headers[TOKEN_HEADER] = config.token

    resp = httpx.post(
        config.target,
        json=request.as_payload(),
        headers=headers,
        timeout=config.timeout,
    )
    if not 200 <= resp.status_code < 300:
        raise RuntimeError(
            f"context provider returned HTTP {resp.status_code}: "
            f"{(resp.text or '')[:200]}"
        )
    label = config.label or sanitize_label(resp.headers.get(LABEL_HEADER, ""))
    return resp.text or "", label


def fetch_external_context(
    *,
    repo: str,
    pr_number: int,
    head_sha: str,
    changed_paths: list[str] | None = None,
    config: ProviderConfig | None = None,
    env: Mapping[str, str] | None = None,
    invoke: Callable[[ProviderConfig, ProviderRequest], tuple[str, str]] | None = None,
) -> ExternalContext | None:
    """Fetch external review context, or ``None`` if there is none to have.

    This function never raises. Absent, empty, failing, hanging, or garbage
    provider — every one of them returns ``None`` and the review proceeds
    with the PR as its only evidence.

    Args:
        repo: ``owner/repo``.
        pr_number: PR number.
        head_sha: The commit being reviewed.
        changed_paths: Paths touched by the PR.
        config: Pre-built config; loaded from ``env`` when omitted.
        env: Environment mapping to read configuration from (tests).
        invoke: Transport override, for tests that must supply fixed context
            without a network or a subprocess. Receives the config and the
            request, returns ``(text, label)``.
    """
    try:
        config = config if config is not None else load_provider_config(env)
        if config is None:
            log.debug("VIGIL_CONTEXT_PROVIDER not set — no external context")
            return None

        request = ProviderRequest(
            repo=repo,
            pr_number=pr_number,
            head_sha=head_sha,
            changed_paths=list(changed_paths or []),
        )

        transport = invoke
        if transport is None:
            transport = invoke_http_provider if config.is_http else invoke_command_provider

        raw_text, raw_label = transport(config, request)
    except subprocess.TimeoutExpired:
        log.warning(
            "External context provider timed out — continuing without external context"
        )
        return None
    except httpx.TimeoutException:
        log.warning(
            "External context provider timed out — continuing without external context"
        )
        return None
    except Exception as e:  # noqa: BLE001 — fail open by design
        log.warning(
            "External context provider failed (%s: %s) — continuing without "
            "external context", type(e).__name__, e,
        )
        return None

    text = (raw_text or "").replace("\x00", "").strip()
    if not text:
        log.info("External context provider returned nothing — section omitted")
        return None

    max_chars = config.max_chars if config else DEFAULT_MAX_CHARS
    text, truncated, original_chars = truncate_context(text, max_chars)
    label = sanitize_label(raw_label) or DEFAULT_LABEL

    log.info(
        "External context: %d char(s) from %s%s",
        original_chars, label, " (truncated)" if truncated else "",
    )
    return ExternalContext(
        text=text,
        label=label,
        truncated=truncated,
        original_chars=original_chars,
        kept_chars=min(max_chars, original_chars),
    )

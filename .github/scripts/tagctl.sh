#!/usr/bin/env bash
#
# tagctl.sh — Vigil release-tag control (issue #58).
#
# WHY THIS EXISTS, AND WHY THE PEEL IS IN ONE PLACE
# --------------------------------------------------
# `v1` is an ANNOTATED tag. `git rev-parse v1` returns the *tag object*
# (4a2f385...), NOT the commit it points at (67379a5...). Comparing that
# tag-object SHA against a branch head therefore reports drift that does not
# exist — and, worse, reports "in sync" as impossible, so a naive checker is
# permanently wrong in the alarming direction.
#
# This has already misled at least one prior automated run of this repo, and
# the issue thread had to warn about it twice. So the peel lives in exactly
# ONE function — `resolve()` — and every other subcommand goes through it.
# If you add a subcommand, do not call `git rev-parse` on a ref directly.
#
# This script NEVER pushes anything. `move` writes a local tag only; pushing
# is the caller's explicit, separate act. That keeps a fleet-wide release
# from ever being a side effect of running this file.
#
set -euo pipefail

PROG="${0##*/}"

die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 2; }

usage() {
  cat <<'EOF'
tagctl.sh — Vigil release-tag control

Usage:
  tagctl.sh resolve <ref>
      Print the COMMIT sha for <ref>, peeling annotated tags. The only
      sanctioned way to turn a ref into a commit in this repo.

  tagctl.sh drift [--alias <tag>] [--branch <ref>]
      Compare the alias tag against a branch. Prints a report.
      Exit 0 = in sync, 3 = drifted, 4 = alias missing.
      Defaults: --alias v1 --branch origin/main

  tagctl.sh pins [--branch <ref>]
      Report `uses: F2iLLC/vigil@<ref>` self-pins found in the workflow
      files of <branch> and how far behind <branch> each one is.
      Exit 0 = all current, 3 = at least one stale pin.

  tagctl.sh plan-move <alias> <target-ref> [--branch <ref>] [--allow-rollback]
      Validate a proposed alias move WITHOUT changing anything. Prints the
      resolved target commit on stdout. Exit 0 = safe, non-zero = refused.

  tagctl.sh move <alias> <target-ref> [--message <msg>]
      Create/replace <alias> LOCALLY as an ANNOTATED tag at <target-ref>.
      Does NOT push. Run plan-move first; move re-validates nothing.

Exit codes:
  0 ok    2 usage/internal error    3 drift/stale    4 missing ref
EOF
}

# ---------------------------------------------------------------------------
# resolve: THE peel. Annotated tag -> commit. Lightweight tag -> commit.
# Branch/sha -> commit. Anything unresolvable -> exit 4.
# ---------------------------------------------------------------------------
resolve() {
  local ref="$1"
  [ -n "$ref" ] || die "resolve: empty ref"
  # `^{commit}` dereferences a tag object all the way to the commit it wraps.
  # It is a no-op on a ref that is already a commit, which is what makes it
  # safe to apply unconditionally.
  local out
  if ! out=$(git rev-parse --verify --quiet "${ref}^{commit}" 2>/dev/null); then
    return 4
  fi
  [ -n "$out" ] || return 4
  printf '%s\n' "$out"
}

resolve_or_die() {
  local ref="$1" what="${2:-ref}" out rc
  set +e
  out=$(resolve "$ref"); rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    printf '%s: %s %s does not resolve to a commit\n' "$PROG" "$what" "$ref" >&2
    exit 4
  fi
  printf '%s\n' "$out"
}

cmd_resolve() {
  [ $# -eq 1 ] || die "resolve takes exactly one ref"
  resolve_or_die "$1" "ref"
}

# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------
cmd_drift() {
  local alias_tag="v1" branch="origin/main"
  while [ $# -gt 0 ]; do
    case "$1" in
      --alias)  alias_tag="${2:?--alias needs a value}"; shift 2 ;;
      --branch) branch="${2:?--branch needs a value}";   shift 2 ;;
      *) die "drift: unknown argument '$1'" ;;
    esac
  done

  local alias_commit branch_commit rc
  set +e
  alias_commit=$(resolve "$alias_tag"); rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    printf 'alias=%s MISSING\n' "$alias_tag"
    printf '::notice::alias tag %s does not exist\n' "$alias_tag"
    return 4
  fi
  branch_commit=$(resolve_or_die "$branch" "branch")

  printf 'alias=%s\n'         "$alias_tag"
  printf 'alias_commit=%s\n'  "$alias_commit"
  printf 'branch=%s\n'        "$branch"
  printf 'branch_commit=%s\n' "$branch_commit"

  if [ "$alias_commit" = "$branch_commit" ]; then
    printf 'drift_count=0\n'
    printf 'status=in-sync\n'
    return 0
  fi

  # Count only commits the branch has that the alias does not. If the alias
  # is somehow AHEAD of the branch this is 0, which we surface distinctly
  # rather than calling it "in sync".
  local ahead behind
  ahead=$(git rev-list --count "${alias_commit}..${branch_commit}")
  behind=$(git rev-list --count "${branch_commit}..${alias_commit}")
  printf 'drift_count=%s\n'  "$ahead"
  printf 'alias_ahead_by=%s\n' "$behind"
  if [ "$behind" -ne 0 ]; then
    printf 'status=diverged\n'
  else
    printf 'status=behind\n'
  fi
  printf 'unshipped<<EOF_UNSHIPPED\n'
  git log --format='%h %s' "${alias_commit}..${branch_commit}"
  printf 'EOF_UNSHIPPED\n'
  return 3
}

# ---------------------------------------------------------------------------
# pins — the SECOND stale surface called out in issue #58's first comment.
# `reusable-vigil.yml` pins F2iLLC/vigil@<sha> in several places; those do
# not follow the alias tag, so fixing `v1` alone leaves them stale.
# Report only. This never edits a workflow.
# ---------------------------------------------------------------------------
cmd_pins() {
  local branch="origin/main"
  while [ $# -gt 0 ]; do
    case "$1" in
      --branch) branch="${2:?--branch needs a value}"; shift 2 ;;
      *) die "pins: unknown argument '$1'" ;;
    esac
  done

  local branch_commit
  branch_commit=$(resolve_or_die "$branch" "branch")

  local stale=0 found=0 file ref pin_commit behind
  while IFS= read -r file; do
    while IFS= read -r ref; do
      [ -n "$ref" ] || continue
      found=$((found + 1))
      local rc
      set +e
      pin_commit=$(resolve "$ref"); rc=$?
      set -e
      if [ "$rc" -ne 0 ]; then
        # A pin we cannot resolve locally (e.g. a tag that was never fetched)
        # is reported, not silently skipped.
        printf 'pin\t%s\t%s\tUNRESOLVABLE\n' "$file" "$ref"
        stale=1
        continue
      fi
      if [ "$pin_commit" = "$branch_commit" ]; then
        printf 'pin\t%s\t%s\tcurrent\n' "$file" "$ref"
      else
        behind=$(git rev-list --count "${pin_commit}..${branch_commit}")
        printf 'pin\t%s\t%s\tbehind:%s\n' "$file" "$ref" "$behind"
        stale=1
      fi
    done < <(git show "${branch}:${file}" 2>/dev/null \
               | sed -n 's|.*uses:[[:space:]]*F2iLLC/vigil@\([A-Za-z0-9._/-]*\).*|\1|p')
  done < <(git ls-tree -r --name-only "$branch" -- .github/workflows/)

  printf 'pins_found=%s\n' "$found"
  [ "$stale" -eq 0 ] && { printf 'status=all-current\n'; return 0; }
  printf 'status=stale\n'
  return 3
}

# ---------------------------------------------------------------------------
# plan-move — validate, never mutate.
# ---------------------------------------------------------------------------
cmd_plan_move() {
  [ $# -ge 2 ] || die "plan-move <alias> <target-ref> [--branch <ref>] [--allow-rollback]"
  local alias_tag="$1" target="$2"; shift 2
  local branch="origin/main" allow_rollback=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --branch)         branch="${2:?--branch needs a value}"; shift 2 ;;
      --allow-rollback) allow_rollback=1; shift ;;
      *) die "plan-move: unknown argument '$1'" ;;
    esac
  done

  local target_commit branch_commit
  target_commit=$(resolve_or_die "$target" "target")
  branch_commit=$(resolve_or_die "$branch" "branch")

  # Guard 1: never point a consumer-facing alias at code that is not on the
  # release branch. Without this, a tag pushed from a feature branch would
  # ship unreviewed work to every consumer.
  if ! git merge-base --is-ancestor "$target_commit" "$branch_commit"; then
    printf '%s: refusing: target %s is not contained in %s\n' \
      "$PROG" "$target_commit" "$branch" >&2
    exit 3
  fi

  # Guard 2: refuse a silent rollback. Moving the alias BACKWARDS un-ships
  # fixes from five repos at once and is almost never intended.
  local current rc
  set +e
  current=$(resolve "$alias_tag"); rc=$?
  set -e
  if [ "$rc" -eq 0 ] && [ "$allow_rollback" -eq 0 ]; then
    if [ "$current" != "$target_commit" ] \
       && git merge-base --is-ancestor "$target_commit" "$current"; then
      printf '%s: refusing: %s would move BACKWARDS from %s to %s (pass --allow-rollback if deliberate)\n' \
        "$PROG" "$alias_tag" "$current" "$target_commit" >&2
      exit 3
    fi
  fi

  printf '%s\n' "$target_commit"
}

# ---------------------------------------------------------------------------
# move — local annotated tag only. No push, ever.
# ---------------------------------------------------------------------------
cmd_move() {
  [ $# -ge 2 ] || die "move <alias> <target-ref> [--message <msg>]"
  local alias_tag="$1" target="$2"; shift 2
  local message=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --message) message="${2:?--message needs a value}"; shift 2 ;;
      *) die "move: unknown argument '$1'" ;;
    esac
  done

  local target_commit
  target_commit=$(resolve_or_die "$target" "target")
  [ -n "$message" ] || message="Vigil ${alias_tag} -> ${target_commit}"

  # -a keeps the alias ANNOTATED, matching how v1 already exists. A
  # lightweight replacement would quietly change what `git rev-parse v1`
  # returns and invalidate every checker written against the old shape.
  git tag -f -a "$alias_tag" -m "$message" "$target_commit" >/dev/null
  printf '%s\n' "$target_commit"
}

main() {
  [ $# -ge 1 ] || { usage; exit 2; }
  local sub="$1"; shift
  case "$sub" in
    resolve)     cmd_resolve "$@" ;;
    drift)       cmd_drift "$@" ;;
    pins)        cmd_pins "$@" ;;
    plan-move)   cmd_plan_move "$@" ;;
    move)        cmd_move "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown subcommand '$sub' (try --help)" ;;
  esac
}

main "$@"

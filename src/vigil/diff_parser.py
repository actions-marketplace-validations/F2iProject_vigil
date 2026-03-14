"""Parse unified diffs into per-file hunks for targeted routing."""

import bisect
import fnmatch
import re
from dataclasses import dataclass


@dataclass
class FileHunk:
    """A single file's diff content."""
    path: str
    header: str  # the diff --git line + index/mode lines
    content: str  # the actual diff hunks


def parse_diff(raw_diff: str) -> list[FileHunk]:
    """Split a unified diff into per-file hunks.

    Handles standard `git diff` format:
      diff --git a/path/to/file b/path/to/file
    """
    hunks: list[FileHunk] = []
    # Split on diff boundaries
    parts = re.split(r"(?=^diff --git )", raw_diff, flags=re.MULTILINE)

    for part in parts:
        part = part.strip()
        if not part.startswith("diff --git"):
            continue

        # Extract file path from the diff header
        match = re.match(r"diff --git a/(.+?) b/(.+)", part.split("\n")[0])
        if not match:
            continue
        path = match.group(2)  # use the b/ path (destination)

        # Split header from content at first @@ hunk marker
        hunk_start = part.find("\n@@")
        if hunk_start == -1:
            # Binary file or mode-only change
            header = part
            content = ""
        else:
            header = part[:hunk_start]
            content = part[hunk_start + 1:]  # skip the leading newline

        hunks.append(FileHunk(path=path, header=header, content=content))

    return hunks


def filter_hunks(hunks: list[FileHunk], patterns: list[str]) -> list[FileHunk]:
    """Filter file hunks by glob patterns.

    Patterns support:
      - Standard globs: "*.ts", "src/**/*.py"
      - Directory prefixes: "packages/dashboard/" (matches anything under it)
      - Negation: "!*.test.ts" (exclude matching files)
    """
    if not patterns:
        return hunks  # no patterns = see everything

    include: list[str] = []
    exclude: list[str] = []
    for p in patterns:
        if p.startswith("!"):
            exclude.append(p[1:])
        else:
            include.append(p)

    result = []
    for hunk in hunks:
        # Check includes — file must match at least one include pattern
        matched = False
        for pat in include:
            if pat.endswith("/"):
                # Directory prefix match
                if hunk.path.startswith(pat) or hunk.path.startswith(pat.rstrip("/")):
                    matched = True
                    break
            elif fnmatch.fnmatch(hunk.path, pat):
                matched = True
                break

        if not matched:
            continue

        # Check excludes — skip if matches any exclude pattern
        excluded = False
        for pat in exclude:
            if fnmatch.fnmatch(hunk.path, pat):
                excluded = True
                break

        if not excluded:
            result.append(hunk)

    return result


def reassemble_diff(hunks: list[FileHunk]) -> str:
    """Reassemble filtered hunks back into a unified diff string."""
    parts = []
    for hunk in hunks:
        if hunk.content:
            parts.append(f"{hunk.header}\n{hunk.content}")
        else:
            parts.append(hunk.header)
    return "\n".join(parts)


def diff_summary(hunks: list[FileHunk]) -> str:
    """Generate a compact summary of all changed files."""
    lines = []
    for h in hunks:
        adds = h.content.count("\n+") if h.content else 0
        dels = h.content.count("\n-") if h.content else 0
        lines.append(f"  {h.path} (+{adds} -{dels})")
    return "\n".join(lines)


def commentable_lines(raw_diff: str) -> dict[str, set[int]]:
    """Extract lines that GitHub allows inline review comments on.

    Returns {file_path: {line_numbers...}} where line numbers are in the
    NEW file (right side). These are the only lines GitHub's PR Review API
    will accept for inline comments — added lines (+) and context lines ( ).
    """
    result: dict[str, set[int]] = {}
    hunks = parse_diff(raw_diff)

    for hunk in hunks:
        if not hunk.content:
            continue
        valid_lines: set[int] = set()
        # Walk through each @@ hunk in this file
        for hunk_block in re.split(r"(?=^@@)", hunk.content, flags=re.MULTILINE):
            hunk_block = hunk_block.strip()
            if not hunk_block.startswith("@@"):
                continue
            # Parse @@ -old_start,old_count +new_start,new_count @@
            m = re.match(r"@@\s*-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s*@@", hunk_block)
            if not m:
                continue
            new_line = int(m.group(1))
            # Walk the diff lines after the @@ header
            body = hunk_block.split("\n", 1)
            if len(body) < 2:
                continue
            for diff_line in body[1].split("\n"):
                if diff_line.startswith("+"):
                    valid_lines.add(new_line)
                    new_line += 1
                elif diff_line.startswith("-"):
                    pass  # deletion — doesn't advance new-file line counter
                else:
                    # Context line (space prefix) or empty
                    valid_lines.add(new_line)
                    new_line += 1
        if valid_lines:
            result[hunk.path] = valid_lines

    return result


def nearest_commentable_line(
    file_path: str,
    target_line: int | None,
    valid_lines: dict[str, set[int]],
) -> tuple[str, int] | None:
    """Find the nearest commentable line for a finding in the same file.

    Returns (file_path, line) or None if the file is not in the diff.
    """
    if file_path not in valid_lines:
        return None

    file_line_set = valid_lines[file_path]
    if not file_line_set:
        return None

    sorted_lines = sorted(file_line_set)

    if target_line is not None and target_line in file_line_set:
        return (file_path, target_line)

    if target_line is None:
        return (file_path, sorted_lines[0])

    # Find nearest via binary search
    idx = bisect.bisect_left(sorted_lines, target_line)
    candidates = []
    if idx < len(sorted_lines):
        candidates.append(sorted_lines[idx])
    if idx > 0:
        candidates.append(sorted_lines[idx - 1])
    nearest = min(candidates, key=lambda l: abs(l - target_line))
    return (file_path, nearest)


def find_best_file_for_finding(
    finding_file: str,
    valid_lines: dict[str, set[int]],
) -> tuple[str, int] | None:
    """When a finding's file is not in the diff, find the best file to attach it to.

    Strategy:
    1. Fuzzy match by filename (e.g. file was renamed, or path differs)
    2. Fall back to the first file alphabetically in the diff

    Returns (file_path, first_commentable_line) or None if diff is empty.
    """
    if not valid_lines:
        return None

    # Try matching by basename
    from pathlib import PurePosixPath
    finding_name = PurePosixPath(finding_file).name
    for path, lines in valid_lines.items():
        if PurePosixPath(path).name == finding_name and lines:
            return (path, min(lines))

    # Fall back to first file in diff that has commentable lines
    for path in sorted(valid_lines.keys()):
        if valid_lines[path]:
            return (path, min(valid_lines[path]))
    return None

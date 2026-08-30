#!/usr/bin/env python3
"""Check that moving the ``v1`` alias will not break consumer workflows (issue #58).

Every consumer repo pins ``uses: F2iLLC/vigil@v1``. When that alias moves, the
consumers' *existing, unchanged* workflow files are suddenly executed against a
new ``action.yml``. Three things can break them, and none of them fail loudly:

* **An input is removed.** GitHub does not hard-fail an undeclared input --- it
  warns and *ignores* it. The consumer keeps passing ``model:`` and it silently
  stops taking effect. This is the same silent-inertness failure mode issue #58
  already documents for the stale SHA pins.
* **An optional input becomes required.** Consumers that never passed it now
  fail at dispatch.
* **A default changes.** Not a break, but it changes behaviour for every repo
  that relied on the default --- reported as a warning so the move is a
  deliberate act rather than a surprise.

Adding a new optional input is always safe and is reported as informational.

Usage:
    check_action_inputs.py --from <ref> --to <ref> [--path action.yml]

Exit codes:
    0  compatible (possibly with warnings)
    2  usage / could not read one of the refs
    3  BREAKING change detected
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment guard
    sys.stderr.write(
        "check_action_inputs.py: PyYAML is required "
        "(pip install -e '.[dev]' or pip install pyyaml)\n"
    )
    raise SystemExit(2)


def read_blob(ref: str, path: str) -> str:
    """Return the contents of *path* at *ref*.

    Uses ``git show`` so the check works against any ref without touching the
    working tree --- important because this runs in CI against the tag being
    proposed, not against a checkout of it.
    """
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "replace").strip()
        raise SystemExit(f"cannot read {path} at {ref}: {stderr}") from exc
    return out.stdout.decode("utf-8")


def parse_inputs(text: str, label: str) -> dict[str, dict[str, Any]]:
    """Extract the ``inputs:`` mapping from an action.yml document."""
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise SystemExit(f"{label}: action.yml did not parse to a mapping")
    raw = doc.get("inputs") or {}
    if not isinstance(raw, dict):
        raise SystemExit(f"{label}: action.yml 'inputs' is not a mapping")
    normalised: dict[str, dict[str, Any]] = {}
    for name, spec in raw.items():
        normalised[str(name)] = spec if isinstance(spec, dict) else {}
    return normalised


def is_required(spec: dict[str, Any]) -> bool:
    """Interpret ``required:`` the way the Actions runner does.

    YAML parses bare ``true``/``false`` to booleans but quoted ``"true"`` to a
    string, and both spellings appear in the wild --- so compare on the
    lowercased string form rather than on truthiness (a non-empty ``"false"``
    string is truthy in Python and would invert the answer).
    """
    value = spec.get("required", False)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def default_of(spec: dict[str, Any]) -> str | None:
    if "default" not in spec:
        return None
    value = spec["default"]
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def compare(
    old: dict[str, dict[str, Any]],
    new: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str], list[str]]:
    """Return (breaking, warnings, info) message lists."""
    breaking: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    for name in sorted(old):
        if name not in new:
            breaking.append(
                f"input '{name}' was REMOVED — consumers still passing it will be "
                f"silently ignored, not failed"
            )
            continue
        was, now = old[name], new[name]
        if not is_required(was) and is_required(now):
            breaking.append(
                f"input '{name}' became REQUIRED — consumers that omit it will fail"
            )
        old_default, new_default = default_of(was), default_of(now)
        if old_default != new_default:
            warnings.append(
                f"input '{name}' default changed: {old_default!r} -> {new_default!r} "
                f"— behaviour changes for every consumer relying on the default"
            )

    for name in sorted(new):
        if name in old:
            continue
        if is_required(new[name]):
            breaking.append(
                f"input '{name}' was ADDED as REQUIRED — every existing consumer "
                f"workflow becomes invalid"
            )
        else:
            info.append(f"input '{name}' added (optional) — safe for consumers")

    return breaking, warnings, info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="from_ref", required=True)
    parser.add_argument("--to", dest="to_ref", required=True)
    parser.add_argument("--path", default="action.yml")
    args = parser.parse_args(argv)

    old = parse_inputs(read_blob(args.from_ref, args.path), args.from_ref)
    new = parse_inputs(read_blob(args.to_ref, args.path), args.to_ref)

    breaking, warnings, info = compare(old, new)

    print(f"action.yml input compatibility: {args.from_ref} -> {args.to_ref}")
    print(f"  inputs before: {len(old)}   inputs after: {len(new)}")
    for msg in info:
        print(f"  [ok]       {msg}")
    for msg in warnings:
        print(f"  [warn]     {msg}")
    for msg in breaking:
        print(f"  [BREAKING] {msg}")

    if breaking:
        print(f"\nRESULT: {len(breaking)} breaking change(s) — alias move refused.")
        return 3
    print("\nRESULT: compatible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

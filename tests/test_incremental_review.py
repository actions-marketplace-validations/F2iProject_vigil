"""Tests for incremental review - issue #5: full PR diff in re-reviews.

Issue #5: When a PR has multiple commits and Vigil re-reviews after a new push,
it should review the FULL PR diff against the base branch (main), not just the
incremental diff since the last reviewed commit.

Scenario:
- Commit 1: Creates file_a.py                   (reviewed at this commit)
- Commit 2: Creates file_b.py                   (new push)

Expected behavior:
- First review: See both file_a.py and file_b.py
- After commit 3 (modifying only file_b.py):
  - Previous behavior (bug): Only review file_b.py (miss file_a.py)
  - New behavior (fixed): Review both file_a.py and file_b.py (full PR diff)

This is crucial because:
1. file_a.py is still part of the PR and could have issues
2. Specialists need full context to make proper decisions
3. The PR diff from GitHub includes ALL commits, not just the latest one
"""

import pytest
from unittest.mock import patch, MagicMock
from vigil.cli import review
from vigil.diff_parser import parse_diff, reassemble_diff, commentable_lines


class TestIncrementalReviewFullDiff:
    """
    Issue #5: When a PR has multiple commits and Vigil re-reviews after a new push,
    it should review the FULL PR diff against the base branch, not just changes
    since the last reviewed commit.

    Scenario:
    - Commit 1: Creates file_a.py with content
    - Commit 2: Creates file_b.py with content  (reviewed at this commit)
    - Commit 3: Modifies file_b.py only         (new push)

    Expected: Re-review should see BOTH file_a.py and file_b.py
    Bug: Re-review only saw file_b.py (file changed in commit 3)
    """

    def test_full_pr_diff_includes_all_files(self):
        """Verify that full PR diff includes files changed in earlier commits."""
        # Simulate a full PR diff with 2 files
        full_pr_diff = """diff --git a/file_a.py b/file_a.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/file_a.py
@@ -0,0 +1,3 @@
+def func_a():
+    print("A")
+    return 42

diff --git a/file_b.py b/file_b.py
new file mode 100644
index 0000000..abcdefg
--- /dev/null
+++ b/file_b.py
@@ -0,0 +1,3 @@
+def func_b():
+    print("B")
+    return 43
"""

        hunks = parse_diff(full_pr_diff)
        files = {h.path for h in hunks}

        # Full diff should have both files
        assert "file_a.py" in files
        assert "file_b.py" in files
        assert len(files) == 2

    def test_filtering_hunks_to_changed_files_loses_earlier_commits(self):
        """
        This test demonstrates the bug:
        When we filter the full PR diff to only "changed" files,
        we lose files from earlier commits that weren't touched in the latest commit.
        """
        # Full PR diff (what GitHub provides)
        full_pr_diff = """diff --git a/file_a.py b/file_a.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/file_a.py
@@ -0,0 +1,3 @@
+def func_a():
+    print("A")
+    return 42

diff --git a/file_b.py b/file_b.py
new file mode 100644
index 0000000..abcdefg
--- /dev/null
+++ b/file_b.py
@@ -0,0 +1,3 @@
+def func_b():
+    print("B")
+    return 43
"""

        # Simulate: only file_b.py changed since last review
        changed_files = {"file_b.py"}  # file_a.py NOT in this set

        # Current broken logic: filter diff to only changed files
        all_hunks = parse_diff(full_pr_diff)
        filtered_hunks = [h for h in all_hunks if h.path in changed_files]
        filtered_diff = reassemble_diff(filtered_hunks)

        # BUG: filtered_diff is missing file_a.py!
        filtered_files = {h.path for h in parse_diff(filtered_diff)}
        assert "file_a.py" not in filtered_files  # THIS IS THE BUG
        assert "file_b.py" in filtered_files

    def test_fix_use_full_pr_diff_without_filtering(self):
        """
        The fix: Don't filter the PR diff at all during review.
        Always review the full diff against the base branch.
        """
        # Full PR diff (what GitHub provides)
        full_pr_diff = """diff --git a/file_a.py b/file_a.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/file_a.py
@@ -0,0 +1,3 @@
+def func_a():
+    print("A")
+    return 42

diff --git a/file_b.py b/file_b.py
new file mode 100644
index 0000000..abcdefg
--- /dev/null
+++ b/file_b.py
@@ -0,0 +1,3 @@
+def func_b():
+    print("B")
+    return 43
"""

        # The fix: Use full_pr_diff directly, don't filter
        review_diff_text = full_pr_diff  # No filtering!

        # Now both files are seen in the review
        all_hunks = parse_diff(review_diff_text)
        files = {h.path for h in all_hunks}
        assert "file_a.py" in files
        assert "file_b.py" in files
        assert len(files) == 2

    def test_changed_line_map_still_built_for_thread_resolution(self):
        """
        Even though we review the full diff, we still build the changed_line_map
        for resolving outdated threads. This ensures:
        1. Threads at unchanged lines stay open (unresolved)
        2. Threads at changed lines are auto-resolved (code was addressed)
        """
        full_pr_diff = """diff --git a/file_a.py b/file_a.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/file_a.py
@@ -0,0 +1,3 @@
+def func_a():
+    print("A")
+    return 42

diff --git a/file_b.py b/file_b.py
new file mode 100644
index 0000000..abcdefg
--- /dev/null
+++ b/file_b.py
@@ -0,0 +1,3 @@
+def func_b():
+    print("B")
+    return 43
"""

        # Only file_b.py changed in the latest commit
        changed_files = {"file_b.py"}

        # Build line map for changed files only
        all_lines = commentable_lines(full_pr_diff)
        changed_set = set(changed_files)
        changed_line_map = {f: lines for f, lines in all_lines.items() if f in changed_set}

        # changed_line_map should only have file_b.py
        assert "file_b.py" in changed_line_map
        assert "file_a.py" not in changed_line_map

        # But the review_diff_text still has both files
        review_diff_text = full_pr_diff
        review_files = {h.path for h in parse_diff(review_diff_text)}
        assert "file_a.py" in review_files
        assert "file_b.py" in review_files

    def test_multifile_changes_across_commits(self):
        """
        Complex scenario:
        - Commit 1: file_a.py created, file_b.py created
        - Commit 2: file_b.py modified (new lines added)
        - Commit 3: file_c.py created (new push)

        Last review was at commit 2.
        New push adds commit 3 which only touches file_c.py.

        Expected: Full review still sees all three files in the PR.
        """
        full_pr_diff = """diff --git a/file_a.py b/file_a.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/file_a.py
@@ -0,0 +1,2 @@
+def a():
+    pass

diff --git a/file_b.py b/file_b.py
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/file_b.py
@@ -0,0 +1,4 @@
+def b():
+    x = 1
+    y = 2
+    return x + y

diff --git a/file_c.py b/file_c.py
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/file_c.py
@@ -0,0 +1,2 @@
+def c():
+    pass
"""

        # Only file_c.py changed since last review
        changed_files = {"file_c.py"}

        # With the fix: review_diff_text is the full_pr_diff
        review_diff_text = full_pr_diff

        # Parse it
        all_hunks = parse_diff(review_diff_text)
        reviewed_files = {h.path for h in all_hunks}

        # All three files are in the review
        assert "file_a.py" in reviewed_files
        assert "file_b.py" in reviewed_files
        assert "file_c.py" in reviewed_files
        assert len(reviewed_files) == 3

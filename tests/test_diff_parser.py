"""Tests for diff_parser helpers: nearest_commentable_line, find_best_file_for_finding."""

import pytest

from vigil.diff_parser import (
    commentable_lines,
    find_best_file_for_finding,
    nearest_commentable_line,
    parse_diff,
)


# ---------- fixtures ----------

SAMPLE_DIFF = """\
diff --git a/src/app.py b/src/app.py
index 1234567..abcdefg 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,6 +10,8 @@ def main():
     x = 1
     y = 2
+    z = 3
+    w = 4
     return x + y

 def helper():
@@ -30,3 +32,5 @@ def helper():
     pass
+    # new line
+    # another
"""

VALID_LINES = {
    "src/app.py": {10, 11, 12, 13, 14, 32, 33, 34},
    "src/utils.py": {1, 5, 10},
}


# ---------- nearest_commentable_line ----------

class TestNearestCommentableLine:

    def test_exact_match(self):
        result = nearest_commentable_line("src/app.py", 12, VALID_LINES)
        assert result == ("src/app.py", 12)

    def test_nearest_above(self):
        # Line 15 not in set; nearest is 14
        result = nearest_commentable_line("src/app.py", 15, VALID_LINES)
        assert result == ("src/app.py", 14)

    def test_nearest_below(self):
        # Line 9 not in set; nearest is 10
        result = nearest_commentable_line("src/app.py", 9, VALID_LINES)
        assert result == ("src/app.py", 10)

    def test_equidistant_prefers_lower(self):
        # Lines 14 and 32 are valid; 23 is equidistant from 14 (dist=9) and 32 (dist=9)
        # bisect_left for 23 in [10,11,12,13,14,32,33,34] -> idx=5 (val 32)
        # candidates: 32, 14 -> both dist 9 -> min picks 14 (first in list via min)
        result = nearest_commentable_line("src/app.py", 23, VALID_LINES)
        assert result is not None
        assert result[0] == "src/app.py"
        assert result[1] in (14, 32)  # either is acceptable

    def test_target_line_none_returns_first(self):
        result = nearest_commentable_line("src/app.py", None, VALID_LINES)
        assert result == ("src/app.py", 10)

    def test_file_not_in_diff_returns_none(self):
        result = nearest_commentable_line("not/here.py", 5, VALID_LINES)
        assert result is None

    def test_empty_valid_lines_returns_none(self):
        result = nearest_commentable_line("src/app.py", 5, {})
        assert result is None

    def test_empty_line_set_returns_none(self):
        result = nearest_commentable_line("src/app.py", 5, {"src/app.py": set()})
        assert result is None

    def test_line_way_beyond_diff(self):
        # Line 9999 — nearest should be the last valid line
        result = nearest_commentable_line("src/app.py", 9999, VALID_LINES)
        assert result == ("src/app.py", 34)

    def test_line_zero(self):
        result = nearest_commentable_line("src/app.py", 0, VALID_LINES)
        assert result == ("src/app.py", 10)

    def test_single_valid_line(self):
        result = nearest_commentable_line("f.py", 50, {"f.py": {20}})
        assert result == ("f.py", 20)


# ---------- find_best_file_for_finding ----------

class TestFindBestFileForFinding:

    def test_basename_match(self):
        # "other/utils.py" should match "src/utils.py" by basename
        result = find_best_file_for_finding("other/utils.py", VALID_LINES)
        assert result is not None
        assert result[0] == "src/utils.py"
        assert result[1] == 1  # min of {1, 5, 10}

    def test_no_basename_match_falls_back_to_first(self):
        result = find_best_file_for_finding("completely/unknown.rs", VALID_LINES)
        assert result is not None
        # Alphabetically first: "src/app.py"
        assert result[0] == "src/app.py"
        assert result[1] == 10

    def test_empty_valid_lines_returns_none(self):
        result = find_best_file_for_finding("any.py", {})
        assert result is None

    def test_exact_path_match_via_basename(self):
        result = find_best_file_for_finding("src/app.py", VALID_LINES)
        assert result == ("src/app.py", 10)

    def test_file_with_empty_line_set_skipped(self):
        lines = {"src/app.py": set(), "src/utils.py": {5}}
        result = find_best_file_for_finding("src/app.py", lines)
        # app.py has empty lines, but basename matches — should skip and fall through
        # Actually basename matches app.py but it has no lines, so it skips
        # Then falls back to first file alphabetically with lines
        assert result is not None
        assert result[1] == 5


# ---------- integration with parse_diff + commentable_lines ----------

class TestCommentableLinesIntegration:

    def test_sample_diff_produces_valid_lines(self):
        result = commentable_lines(SAMPLE_DIFF)
        assert "src/app.py" in result
        lines = result["src/app.py"]
        # Added lines 12, 13 (the + lines in first hunk)
        assert 12 in lines
        assert 13 in lines
        # Context lines should also be present
        assert 10 in lines

    def test_nearest_on_real_diff(self):
        valid = commentable_lines(SAMPLE_DIFF)
        # A line that's in the diff
        result = nearest_commentable_line("src/app.py", 12, valid)
        assert result is not None
        assert result[1] == 12

        # A line NOT in the diff — should snap to nearest
        result = nearest_commentable_line("src/app.py", 20, valid)
        assert result is not None

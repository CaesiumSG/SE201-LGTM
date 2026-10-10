"""Tests for the git diff reader/parser."""

from __future__ import annotations

from lgtm.diff.git_diff import (
    get_changed_files,
    get_pr_diff,
    parse_unified_diff,
    read_file_at_ref,
)

SAMPLE_DIFF = """\
diff --git a/app/routes/users.py b/app/routes/users.py
index 1234567..89abcde 100644
--- a/app/routes/users.py
+++ b/app/routes/users.py
@@ -10,6 +10,12 @@ def existing():
     return 1


+@app.route("/x")
+def new_endpoint():
+    return 2
+
+
 def unchanged():
-    old_line = True
+    new_line = True
     return 3
diff --git a/newfile.py b/newfile.py
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/newfile.py
@@ -0,0 +1,2 @@
+a = 1
+b = 2
"""


class TestParseUnifiedDiff:
    def test_file_count_and_paths(self):
        diffs = parse_unified_diff(SAMPLE_DIFF)
        assert len(diffs) == 2
        assert diffs[0].path == "app/routes/users.py"
        assert diffs[1].path == "newfile.py"
        assert diffs[1].status == "added"

    def test_hunk_structure(self):
        diffs = parse_unified_diff(SAMPLE_DIFF)
        hunk = diffs[0].hunks[0]
        assert hunk.old_start == 10
        assert hunk.new_start == 10
        assert hunk.new_count == 12
        adds = hunk.added_lines
        assert len(adds) == 6  # 5 new endpoint lines + the modified line
        assert any("new_endpoint" in c.content for c in adds)

    def test_line_numbers_track_new_file(self):
        diffs = parse_unified_diff(SAMPLE_DIFF)
        added = {c.new_lineno: c.content for h in diffs[0].hunks for c in h.added_lines}
        # The @@ header says new lines start at 10; the first add is 4 lines in
        assert added[13] == '@app.route("/x")'
        assert added[14] == "def new_endpoint():"

    def test_added_line_numbers_property(self):
        diffs = parse_unified_diff(SAMPLE_DIFF)
        assert diffs[1].added_line_numbers == [1, 2]

    def test_hunk_text_roundtrip_contains_markers(self):
        diffs = parse_unified_diff(SAMPLE_DIFF)
        rendered = diffs[0].hunk_text()
        assert "+++ b/app/routes/users.py" in rendered
        assert "+def new_endpoint():" in rendered
        assert "-    old_line = True" in rendered

    def test_empty_diff(self):
        assert parse_unified_diff("") == []


class TestGitIntegration:
    def test_get_pr_diff(self, git_repo):
        diffs = get_pr_diff(git_repo, "main", "pr")
        assert len(diffs) == 1
        assert diffs[0].path == "app.py"
        assert any("find_user" in c for c in diffs[0].added_text.splitlines())

    def test_get_changed_files(self, git_repo):
        assert get_changed_files(git_repo, "main", "pr") == ["app.py"]

    def test_read_file_at_ref_base_lacks_pr_change(self, git_repo):
        content = read_file_at_ref(git_repo, "main", "app.py")
        assert "find_user" not in content
        assert "get_user" in content

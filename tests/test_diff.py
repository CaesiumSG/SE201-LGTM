"""Tests for the git diff reader/parser."""

from __future__ import annotations

from lgtm.diff.git_diff import (
    get_changed_files,
    get_pr_diff,
    parse_unified_diff,
    read_file_at_ref,
)
from tests.conftest import git

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

# The diffs below are real `git diff` output for each edge case.

RENAME_DIFF = """\
diff --git a/old.py b/renamed.py
similarity index 100%
rename from old.py
rename to renamed.py
"""

DELETED_DIFF = """\
diff --git a/gone.py b/gone.py
deleted file mode 100644
index a003ef7..0000000
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-y = 1
"""

BINARY_DIFF = """\
diff --git a/img.bin b/img.bin
index 8352675..797c34e 100644
Binary files a/img.bin and b/img.bin differ
"""

NO_NEWLINE_DIFF = """\
diff --git a/nonl.py b/nonl.py
new file mode 100644
index 0000000..20cbb4d
--- /dev/null
+++ b/nonl.py
@@ -0,0 +1 @@
+no newline
\\ No newline at end of file
"""

# git appends a tab to ---/+++ paths that contain a space
SPACE_PATH_DIFF = (
    "diff --git a/my file.py b/my file.py\n"
    "index 1337a53..e7cabca 100644\n"
    "--- a/my file.py\t\n"
    "+++ b/my file.py\t\n"
    "@@ -1 +1 @@\n"
    "-a = 1\n"
    "+a = 2\n"
)

# With the default core.quotePath, git quotes non-ASCII paths and writes
# their UTF-8 bytes as octal escapes ("é" -> \303\251).
QUOTED_PATH_DIFF = r"""diff --git "a/caf\303\251.py" "b/caf\303\251.py"
new file mode 100644
index 0000000..587be6b
--- /dev/null
+++ "b/caf\303\251.py"
@@ -0,0 +1 @@
+x = 1
"""

MULTI_HUNK_DIFF = """\
diff --git a/m.py b/m.py
index 1111111..2222222 100644
--- a/m.py
+++ b/m.py
@@ -1,3 +1,4 @@
 a = 1
+b = 2
 c = 3
 d = 4
@@ -20,3 +21,3 @@ def f():
     x = 1
-    y = 2
+    y = 3
     z = 4
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

    def test_pure_rename_has_no_hunks(self):
        diffs = parse_unified_diff(RENAME_DIFF)
        assert len(diffs) == 1
        assert diffs[0].status == "renamed"
        assert diffs[0].old_path == "old.py"
        assert diffs[0].path == "renamed.py"
        assert diffs[0].hunks == []

    def test_deleted_file_keeps_old_path(self):
        diffs = parse_unified_diff(DELETED_DIFF)
        assert diffs[0].status == "deleted"
        assert diffs[0].path == "gone.py"
        assert diffs[0].added_line_numbers == []
        assert [c.old_lineno for c in diffs[0].hunks[0].deleted_lines] == [1]

    def test_binary_file_has_no_hunks(self):
        diffs = parse_unified_diff(BINARY_DIFF)
        assert len(diffs) == 1
        assert diffs[0].path == "img.bin"
        assert diffs[0].hunks == []
        assert diffs[0].added_text == ""

    def test_no_newline_marker_is_not_a_change(self):
        diffs = parse_unified_diff(NO_NEWLINE_DIFF)
        changes = diffs[0].hunks[0].changes
        assert [c.content for c in changes] == ["no newline"]
        assert diffs[0].added_line_numbers == [1]

    def test_hunk_header_without_counts_defaults_to_one(self):
        hunk = parse_unified_diff(DELETED_DIFF)[0].hunks[0]
        assert (hunk.old_start, hunk.old_count) == (1, 1)

    def test_path_with_space_and_trailing_tab(self):
        diffs = parse_unified_diff(SPACE_PATH_DIFF)
        assert diffs[0].path == "my file.py"
        assert diffs[0].old_path == "my file.py"

    def test_quoted_non_ascii_path_is_unquoted(self):
        diffs = parse_unified_diff(QUOTED_PATH_DIFF)
        assert diffs[0].status == "added"
        assert diffs[0].path == "café.py"

    def test_line_numbers_across_multiple_hunks(self):
        diffs = parse_unified_diff(MULTI_HUNK_DIFF)
        assert len(diffs[0].hunks) == 2
        assert diffs[0].added_line_numbers == [2, 22]
        deleted = [c.old_lineno for h in diffs[0].hunks for c in h.deleted_lines]
        assert deleted == [21]


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

    def test_non_utf8_content_does_not_crash(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "t@t.local")
        git(repo, "config", "user.name", "T")
        (repo / "a.py").write_text("k = 1\n")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "base")
        git(repo, "checkout", "-qb", "pr")
        (repo / "a.py").write_bytes(b'k = "caf\xe9"\n')  # Latin-1, not UTF-8
        git(repo, "commit", "-qam", "pr")

        diffs = get_pr_diff(repo, "main", "pr")
        assert diffs[0].path == "a.py"
        assert diffs[0].added_line_numbers == [1]

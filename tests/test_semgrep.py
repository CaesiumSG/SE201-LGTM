"""Tests for the semgrep runner (subprocess mocked)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from lgtm.diff.git_diff import parse_unified_diff
from lgtm.sast.semgrep_runner import (
    SemgrepError,
    SemgrepFinding,
    filter_to_diff,
    parse_semgrep_json,
    run_semgrep,
)

SEMGREP_PAYLOAD = {
    "results": [
        {
            "check_id": "python.lang.security.sqli.fstring",
            "path": "app.py",
            "start": {"line": 6},
            "end": {"line": 7},
            "extra": {
                "message": "SQL built with f-string",
                "severity": "ERROR",
                "lines": "cursor.execute(f\"SELECT ...\")",
                "metadata": {
                    "cwe": ["CWE-89: Improper Neutralization of Special Elements"],
                    "confidence": "HIGH",
                },
            },
        },
        {
            "check_id": "other.rule",
            "path": "elsewhere.py",
            "start": {"line": 100},
            "end": {"line": 100},
            "extra": {"message": "m", "severity": "INFO", "metadata": {}},
        },
    ],
    "errors": [],
}


class TestParseSemgrepJson:
    def test_parses_fields(self):
        findings = parse_semgrep_json(SEMGREP_PAYLOAD)
        assert len(findings) == 2
        f = findings[0]
        assert f.rule_id.endswith("sqli.fstring")
        assert f.path == "app.py"
        assert (f.start_line, f.end_line) == (6, 7)
        assert f.severity == "ERROR"
        assert f.cwe == ["CWE-89"]  # normalized, description stripped
        assert f.confidence == "HIGH"
        assert f.finding_id == "python.lang.security.sqli.fstring:app.py:6"

    def test_is_sqli_heuristics(self):
        findings = parse_semgrep_json(SEMGREP_PAYLOAD)
        assert findings[0].is_sqli
        assert not findings[1].is_sqli

    def test_string_cwe_accepted(self):
        payload = {
            "results": [
                {
                    "check_id": "r",
                    "path": "p.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "message": "m",
                        "severity": "WARNING",
                        "metadata": {"cwe": "CWE-89: SQLi"},
                    },
                }
            ]
        }
        assert parse_semgrep_json(payload)[0].cwe == ["CWE-89"]


class TestRunSemgrep:
    def _mock_result(self, stdout: str, returncode: int = 1):
        mock = MagicMock()
        mock.stdout = stdout
        mock.stderr = ""
        mock.returncode = returncode
        return mock

    def test_run_parses_output(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        with patch("lgtm.sast.semgrep_runner.subprocess.run") as run_mock:
            run_mock.return_value = self._mock_result(json.dumps(SEMGREP_PAYLOAD))
            findings = run_semgrep(tmp_path, ["app.py"])
        assert len(findings) == 2
        cmd = run_mock.call_args[0][0]
        assert "semgrep" in cmd[0] or "semgrep" in cmd[:3]
        assert "--json" in cmd

    def test_skips_missing_files(self, tmp_path):
        with patch("lgtm.sast.semgrep_runner.subprocess.run") as run_mock:
            findings = run_semgrep(tmp_path, ["ghost.py"])
        assert findings == []
        run_mock.assert_not_called()

    def test_bad_json_raises(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        with patch("lgtm.sast.semgrep_runner.subprocess.run") as run_mock:
            run_mock.return_value = self._mock_result("not json")
            with pytest.raises(SemgrepError):
                run_semgrep(tmp_path, ["app.py"])

    def test_missing_binary_raises(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        with patch(
            "lgtm.sast.semgrep_runner.subprocess.run", side_effect=FileNotFoundError
        ):
            with pytest.raises(SemgrepError, match="not found"):
                run_semgrep(tmp_path, ["app.py"])


class TestFilterToDiff:
    DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -3,3 +3,6 @@
 def f():
     return 1
+
+def g():
+    cursor.execute(f"SELECT {x}")
"""

    def _finding(self, path: str, line: int) -> SemgrepFinding:
        return SemgrepFinding(
            rule_id="r", path=path, start_line=line, end_line=line,
            message="m", severity="ERROR",
        )

    def test_keeps_findings_on_added_lines(self):
        diffs = parse_unified_diff(self.DIFF)
        inside = self._finding("app.py", 8)
        outside = self._finding("app.py", 50)
        other_file = self._finding("other.py", 8)
        kept = filter_to_diff([inside, outside, other_file], diffs)
        assert kept == [inside]

    def test_slack_tolerance(self):
        diffs = parse_unified_diff(self.DIFF)
        near = self._finding("app.py", 9)  # 2 lines past the last add (7)
        assert filter_to_diff([near], diffs, slack=2) == [near]
        assert filter_to_diff([near], diffs, slack=0) == []

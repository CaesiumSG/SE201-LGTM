"""Tests for the semgrep runner (subprocess mocked)."""

from __future__ import annotations

import json
import re
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

    def test_local_rule_and_windows_path_normalized(self, tmp_path):
        rules = tmp_path / "rules"
        rules.mkdir()
        prefix = re.sub(r"[^a-zA-Z0-9._-]", "", rules.resolve().as_posix().strip("/").replace("/", "."))
        payload = {
            "results": [{
                **SEMGREP_PAYLOAD["results"][0],
                "check_id": f"{prefix}.sqli.fstring",
                "path": r"app\routes.py",
            }],
        }

        findings = parse_semgrep_json(payload, str(rules))
        assert findings[0].rule_id == "sqli.fstring"
        assert findings[0].path == "app/routes.py"
        assert findings[0].finding_id == "sqli.fstring:app/routes.py:6"
        diffs = parse_unified_diff(TestFilterToDiff.DIFF.replace("app.py", "app/routes.py"))
        assert filter_to_diff(findings, diffs) == findings

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


def _semgrep_available() -> bool:
    import shutil
    import sys
    from pathlib import Path

    # which() with an explicit dir applies PATHEXT, so this finds semgrep.exe
    # in a Windows venv's Scripts dir even when the venv is not activated.
    return bool(shutil.which("semgrep")) or bool(
        shutil.which("semgrep", path=str(Path(sys.executable).parent))
    )


def test_semgrep_found_next_to_interpreter_when_not_on_path(tmp_path, monkeypatch):
    """Regression: on Windows the venv ships semgrep.exe. With the venv not
    activated, the old lookup missed it, fell back to `python -m semgrep`
    (rejected by semgrep >= 1.38, exit 2) and the pipeline then silently ran
    with no SAST findings at all."""
    import os
    import sys

    from lgtm.sast import semgrep_runner

    exe = tmp_path / ("semgrep.exe" if os.name == "nt" else "semgrep")
    exe.write_text("")
    exe.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))  # semgrep not on PATH

    cmd = semgrep_runner._semgrep_executable()
    assert len(cmd) == 1 and os.path.samefile(cmd[0], exe)


@pytest.mark.parametrize("folder", ["rules", "rules with spaces"])
def test_local_rule_prefix_stripped(tmp_path, folder):
    from lgtm.sast.semgrep_runner import _local_rule_prefixes, _short_rule_id

    rules = tmp_path / folder
    rules.mkdir()
    (rules / "sqli.yaml").write_text("rules: []\n")
    dotted = re.sub(r"[^a-zA-Z0-9._-]", "", rules.resolve().as_posix().strip("/").replace("/", "."))
    for config in (str(rules), str(rules) + "/", str(rules / "sqli.yaml")):
        prefixes = _local_rule_prefixes(config)
        assert _short_rule_id(f"{dotted}.my-rule", prefixes) == "my-rule"
    # Registry and auto configs are left alone
    assert _local_rule_prefixes("auto") == [] and _local_rule_prefixes("p/python") == []
    assert _short_rule_id("python.lang.security.x", []) == "python.lang.security.x"


@pytest.mark.skipif(not _semgrep_available(), reason="semgrep not installed")
def test_bundled_rules_catch_concat_with_trailing_literal(tmp_path):
    """Regression: benchmark sqli_07 was missed by Semgrep in run 1."""
    from pathlib import Path

    from lgtm.sast.semgrep_runner import run_semgrep

    (tmp_path / "q.py").write_text(
        "def f(cursor, status):\n"
        "    cursor.execute(\n"
        "        \"SELECT * FROM orders WHERE status = '\"\n"
        "        + status + \"'\"\n"
        "    )\n"
        "def g(cursor, status):\n"
        "    cursor.execute(\"SELECT * FROM orders WHERE status = %s\", (status,))\n",
        encoding="utf-8",
    )
    rules = Path(__file__).resolve().parent.parent / "src/lgtm/sast/rules"
    findings = run_semgrep(tmp_path, ["q.py"], str(rules), 120)
    assert [f.start_line for f in findings] == [2]
    # Regression: local rule ids used to carry the absolute rules path
    # (leaking the user's home dir into prompts and changing verdicts).
    assert findings[0].rule_id == "lgtm-python-sqli-format"
    assert findings[0].finding_id.startswith("lgtm-python-sqli-format:")

"""The report viewer build: result normalisation, diff parsing and safe embedding (no model)."""

import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "viewer"


def _load():
    spec = importlib.util.spec_from_file_location("lgtm_viewer", HERE / "build_viewer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_finding_status_reads_the_judge_in_lgtm_mode_and_the_verdict_otherwise():
    mod = _load()
    assert mod.finding_status({"verdict": "", "supported": True, "judged": True, "kev_verdict": "real"}) == "real"
    assert mod.finding_status({"verdict": "", "supported": True, "judged": True, "kev_verdict": "not_real"}) == "not_real"
    assert mod.finding_status({"verdict": "", "supported": False, "judged": False}) == "unsupported"
    assert mod.finding_status({"verdict": "", "supported": True, "judged": False}) == "not_judged"
    assert mod.finding_status({"verdict": "vulnerable"}) == "vulnerable"


def test_parse_diff_numbers_old_and_new_lines():
    mod = _load()
    files = mod.parse_diff(
        "diff --git a/app/x.py b/app/x.py\n--- a/app/x.py\n+++ b/app/x.py\n"
        "@@ -10,3 +10,3 @@ def f():\n a = 1\n-b = 2\n+b = 3\n c = 4\n")
    assert [f["path"] for f in files] == ["app/x.py"]
    lines = files[0]["hunks"][0]["lines"]
    assert [(ln["k"], ln.get("o"), ln.get("n")) for ln in lines] == [
        (" ", 10, 10), ("-", 11, None), ("+", None, 11), (" ", 12, 12)]


def test_new_file_diff_takes_the_path_from_the_plus_header():
    mod = _load()
    files = mod.parse_diff("diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n+++ b/n.py\n@@ -0,0 +1,1 @@\n+x = 1\n")
    assert files[0]["path"] == "n.py" and files[0]["hunks"][0]["lines"][0]["n"] == 1


def test_embedded_data_cannot_close_the_script_tag():
    mod = _load()
    out = mod.embed({"diff": "</script><script>alert(1)</script>", "sep": " "})
    assert "</script" not in out and "<" not in out
    assert json.loads(out) == {"diff": "</script><script>alert(1)</script>", "sep": " "}


def _write_run(path: Path, mode: str, findings: list[dict], outcome: str) -> None:
    path.mkdir(parents=True)
    (path / "case_1.json").write_text(json.dumps({
        "id": "case_1", "category": "sqli", "expected": "vulnerable", "outcome": outcome,
        "latency_seconds": 3.0, "findings": findings,
        "trace": {"runs": [{"section": "s1", "turns": [{"tool_calls": [
            {"tool": "read_file", "args": {"path": "app/x.py"}, "result": "x" * 5000}]}]}]},
    }), encoding="utf-8")
    (path / "summary.json").write_text(json.dumps({
        "mode": mode, "model": "m", "summary": {"overall": {"f1": 1.0, "tp": 1}, "median_latency_seconds": 3.0}}),
        encoding="utf-8")


def test_build_embeds_every_mode_and_the_shoply_patch(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    (tmp_path / "cases").mkdir()
    (tmp_path / "cases" / "c1.patch").write_text(
        "diff --git a/app/x.py b/app/x.py\n--- a/app/x.py\n+++ b/app/x.py\n@@ -1,1 +1,2 @@\n a\n+b\n", encoding="utf-8")
    (tmp_path / "labels.json").write_text(json.dumps({"cases": [{"id": "case_1", "patch_file": "cases/c1.patch"}]}),
                                          encoding="utf-8")
    lgtm_finding = {"finding_id": "f1", "verdict": "", "supported": True, "judged": True, "kev_verdict": "real",
                    "file": "app/x.py", "line": 2, "evidence": [{"type": "code", "file": "app/x.py", "lines": [2, 2],
                                                                 "content": "b", "grounded_in_pr": True}]}
    _write_run(tmp_path / "runs" / "lgtm", "lgtm", [lgtm_finding], "TP")
    _write_run(tmp_path / "runs" / "llm-only", "llm-only", [], "FN")
    config = {"benchmarks": [{"key": "shoply", "title": "Shoply", "labels": "labels.json", "patch_root": ".",
                              "runs": {"lgtm": "runs/lgtm", "llm-only": "runs/llm-only", "sast-only": "runs/missing"}}]}

    html = mod.build(config)

    blob = re.search(r'<script id="lgtm-data" type="application/json">(.*?)</script>', html, re.S).group(1)
    data = json.loads(blob)
    bench = data["benchmarks"][0]
    assert bench["modes"] == ["lgtm", "llm-only"]
    case = bench["cases"][0]
    assert case["modes"]["lgtm"]["findings"][0]["status"] == "real"
    assert case["modes"]["llm-only"]["outcome"] == "FN"
    assert case["diff"][0]["path"] == "app/x.py"
    step = case["modes"]["lgtm"]["trace"][0]
    assert step["tool"] == "read_file" and step["truncated"] and len(step["result"]) == mod.TRACE_RESULT_CHARS
    assert bench["summaries"]["lgtm"]["overall"]["f1"] == 1.0

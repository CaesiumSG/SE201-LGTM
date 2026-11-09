"""benchmark/final_eval/aggregate.py regenerates the committed results on any checkout.

The spend ledger (~/.lgtm/bedrock-spend.jsonl) and the field-trial run folder are local
to the machine that ran the evaluation; without them the committed numbers are kept.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("final_eval_aggregate", REPO / "benchmark" / "final_eval" / "aggregate.py")
agg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agg)

RUN_ROOT = REPO / "benchmark" / "runs" / "final-2026-11"


def _manifest(tmp_path, monkeypatch, rows):
    here = tmp_path / "final_eval"
    here.mkdir()
    (here / "manifest.jsonl").write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    monkeypatch.setattr(agg, "HERE", here)


BEDROCK_CMD = "python run_real_prs.py --bedrock-model m --output benchmark/runs/x/heldout-a"
ROWS = [
    {"run_id": "heldout-a", "status": "ok", "command": BEDROCK_CMD, "start": "s", "end": "e"},
    {"run_id": "gpu-run", "status": "ok", "command": "python run_real_prs.py --output y", "start": "s", "end": "e"},
]


def test_missing_ledger_is_none_not_empty(tmp_path):
    assert agg.ledger_by_label(tmp_path / "absent.jsonl") is None
    path = tmp_path / "ledger.jsonl"
    path.write_text('{"run": "real_prs:heldout-a", "usd": 1.5}\n{"run": "real_prs:heldout-a", "usd": 0.25}\nnot json\n',
                    encoding="utf-8")
    assert agg.ledger_by_label(path) == {"real_prs:heldout-a": 1.75}


def test_costs_come_from_the_ledger_when_present(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, ROWS)
    out = agg.load_manifest(tmp_path, {"real_prs:heldout-a": 2.5}, {"heldout-a": 99.0})
    assert out["heldout-a"]["bedrock_usd"] == 2.5
    assert out["gpu-run"]["bedrock_usd"] == 0.0


def test_costs_fall_back_to_committed_results_without_a_ledger(tmp_path, monkeypatch):
    _manifest(tmp_path, monkeypatch, ROWS)
    out = agg.load_manifest(tmp_path, None, {"heldout-a": 22.06, "gpu-run": 0.0})
    assert out["heldout-a"]["bedrock_usd"] == 22.06
    assert out["heldout-a"]["bedrock_label"] == "real_prs:heldout-a"
    assert out["gpu-run"]["bedrock_usd"] == 0.0
    assert agg.load_manifest(tmp_path, None, None)["heldout-a"]["bedrock_usd"] == 0.0


def test_absent_field_trial_folder_keeps_the_committed_totals(tmp_path, monkeypatch):
    monkeypatch.setattr(agg, "REPO", tmp_path)
    root = tmp_path / "runs"
    (root / "shoply" / "lgtm").mkdir(parents=True)
    (root / "shoply" / "lgtm" / "summary.json").write_text(json.dumps({"summary": {"overall": {"tp": 1}}}), encoding="utf-8")
    committed = {"field_trial": {"lgtm": {"file": "runs/field_trial/lgtm/summary.json", "summary": {"cases": 12}}},
                 "shoply": {"lgtm": {"file": "old", "summary": {"overall": {"tp": 0}}}}}
    out = agg.copy_summaries(root, committed)
    assert out["field_trial"] == committed["field_trial"]
    assert out["shoply"] == {"lgtm": {"file": "runs/shoply/lgtm/summary.json", "summary": {"overall": {"tp": 1}}}}
    assert "real_world" not in out


def test_present_field_trial_folder_is_read_without_per_pr_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(agg, "REPO", tmp_path)
    root = tmp_path / "runs"
    (root / "field_trial" / "lgtm").mkdir(parents=True)
    (root / "field_trial" / "lgtm" / "summary.json").write_text(
        json.dumps({"cases": 12, "per_case": [{"pr": "named"}]}), encoding="utf-8")
    out = agg.copy_summaries(root, {"field_trial": {"lgtm": {"summary": {"cases": 0}}}})
    assert out["field_trial"] == {"lgtm": {"file": "runs/field_trial/lgtm/summary.json", "summary": {"cases": 12}}}


@pytest.mark.skipif(not (RUN_ROOT / "results.json").is_file(), reason="final evaluation results not present")
def test_clean_checkout_regenerates_the_committed_files(tmp_path, monkeypatch):
    """No ledger and no field-trial folder: RESULTS.md and results.json come out byte-identical."""
    fake_repo = tmp_path / "repo"
    root = fake_repo / "benchmark" / "runs" / "final-2026-11"
    root.mkdir(parents=True)
    try:
        (fake_repo / "benchmark" / "real_prs").symlink_to(REPO / "benchmark" / "real_prs", target_is_directory=True)
        for child in RUN_ROOT.iterdir():
            if child.name not in ("field_trial", "results.json", "RESULTS.md"):
                (root / child.name).symlink_to(child, target_is_directory=child.is_dir())
    except OSError as exc:  # pragma: no cover - Windows without symlink rights
        pytest.skip(f"host denies symlink creation: {exc}")
    committed_json = (RUN_ROOT / "results.json").read_bytes()
    committed_md = (RUN_ROOT / "RESULTS.md").read_bytes()
    (root / "results.json").write_bytes(committed_json)

    monkeypatch.setattr(agg, "REPO", fake_repo)
    monkeypatch.setattr(agg, "LEDGER", tmp_path / "no-ledger.jsonl")
    monkeypatch.setattr(sys, "argv", ["aggregate.py", "--root", str(root)])
    assert agg.main() == 0

    assert (root / "results.json").read_bytes() == committed_json
    assert (root / "RESULTS.md").read_bytes() == committed_md

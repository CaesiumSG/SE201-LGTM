"""Flags added when the section/graph pipeline became the default (24 Oct).

- graph_enabled: off or binary missing never changes a verdict;
- authz_planner="endpoint": the checkpoint gating, kept for reproduction;
- the tool loop stops once the budget is spent;
- benchmark scoring keeps main's rule and reports alarms outside the target.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, Hunk, LineChange
from lgtm.review.endpoints import extract_changed_endpoints, gate_to_endpoint_hunks
from lgtm.review.sections import plan_sections

BENCH = Path(__file__).resolve().parent.parent / "benchmark"


def _evaluate():
    spec = importlib.util.spec_from_file_location("lgtm_eval_flags", BENCH / "evaluate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["lgtm_eval_flags"] = mod
    spec.loader.exec_module(mod)
    return mod


def _hunk(lines: list[str], new_start: int = 1) -> Hunk:
    changes = [LineChange(kind="add", content=l, new_lineno=new_start + i) for i, l in enumerate(lines)]
    return Hunk(old_start=new_start, old_count=0, new_start=new_start, new_count=len(lines), changes=changes)


class TestConfig:
    def test_defaults_are_local_ollama_graph_on_investigator(self):
        c = LGTMConfig()
        assert c.ollama_base_url == "http://localhost:11434"
        assert c.graph_enabled is True
        assert c.authz_planner == "investigator"

    def test_unknown_planner_rejected(self):
        with pytest.raises(ValueError):
            LGTMConfig(authz_planner="regex")


class TestGraphStamp:
    def test_no_session_means_no_stamp(self, tmp_path):
        toolbox = AgentToolbox(tmp_path, "main", None, LGTMConfig())
        assert toolbox.graph_stamp("pr") is None
        assert toolbox.snapshot_ok("pr") is False  # tool offering is still off

    def test_missing_binary_means_no_stamp(self, tmp_path):
        session = SimpleNamespace(available=False)
        toolbox = AgentToolbox(tmp_path, "main", None, LGTMConfig(), session=session)
        assert toolbox.graph_stamp("pr") is None


class TestEndpointPlanner:
    def test_gating_keeps_only_hunks_with_a_route_decorator(self):
        routes = FileDiff(path="app/routes.py", hunks=[
            _hunk(['@bp.route("/orders/<id>")', "def get_order(id):", "    return x"]),
            _hunk(["def helper():", "    return 1"], new_start=40),
        ])
        crud = FileDiff(path="app/crud.py", hunks=[_hunk(["def delete(key, user_id):", "    pass"])])
        docs = FileDiff(path="README.md", hunks=[_hunk(["# hi"])])
        kept, gated_out = gate_to_endpoint_hunks([routes, crud, docs])
        assert [(d.path, len(d.hunks)) for d in kept] == [("app/routes.py", 1), ("README.md", 1)]
        assert gated_out == 2
        plan = plan_sections(kept, None, LGTMConfig(authz_planner="endpoint"))
        assert [s.files for s in plan.sections] == [["app/routes.py"]]
        assert plan.hunks_total == 1

    def test_extract_changed_endpoints_reports_routes(self):
        routes = FileDiff(path="app/routes.py", hunks=[
            _hunk(['@bp.route("/orders", methods=["GET", "POST"])', "def orders():", "    pass"]),
            _hunk(['@router.delete("/keys/{key_id}")', "async def delete_key():", "    pass"], new_start=30),
        ])
        eps = extract_changed_endpoints([routes])
        assert [(e.route_path, e.http_methods) for e in eps] == [
            ("/orders", ["GET", "POST"]), ("/keys/{key_id}", ["DELETE"]),
        ]


class TestScoring:
    def _row(self, findings, expected="safe", category="authz"):
        return {
            "id": "authz_x", "category": category, "expected": expected,
            "file": "app/routes/users.py", "vulnerable_locations": [],
            "findings": findings, "pin": {}, "coverage": None,
        }

    def test_vulnerable_outside_target_is_still_a_false_alarm(self):
        ev = _evaluate()
        row = self._row([{"finding_id": "s1", "category": "authz", "verdict": "vulnerable",
                          "file": "app/routes/admin.py", "evidence_valid": True}])
        ev.score_case(row)
        assert row["outcome"] == "FP"
        assert row["alarms_outside_target"] == ["s1"]

    def test_vulnerable_on_target_is_a_hit(self):
        ev = _evaluate()
        row = self._row([{"finding_id": "s1", "category": "authz", "verdict": "vulnerable",
                          "file": "app/routes/users.py", "evidence_valid": True}], expected="vulnerable")
        ev.score_case(row)
        assert row["outcome"] == "TP" and row["alarms_outside_target"] == []

    def test_possible_on_safe_is_a_true_negative(self):
        ev = _evaluate()
        row = self._row([{"finding_id": "s1", "category": "authz", "verdict": "possible",
                          "file": "app/routes/users.py", "evidence_valid": True}])
        ev.score_case(row)
        assert row["outcome"] == "TN" and row["predicted"] == "possible"

    def test_summary_reports_outside_target_rate(self):
        ev = _evaluate()
        hit = self._row([{"finding_id": "s1", "category": "authz", "verdict": "vulnerable",
                          "file": "app/routes/admin.py", "evidence_valid": True}])
        clean = self._row([], expected="safe")
        for r in (hit, clean):
            ev.score_case(r)
            r.update(latency_seconds=1.0, est_tokens=1, split="dev")
        summary = ev.summarize([hit, clean])
        assert summary["alarms_outside_target"] == ["authz_x"]
        assert summary["alarms_outside_target_rate"] == 0.5
        assert summary["overall"]["fp"] == 1 and summary["overall"]["tn"] == 1

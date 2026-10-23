"""Component tests for the standalone Kev validation benchmark (benchmark/kev_support/): fixture
set, evidence validation, per-kind and per-format report, stability and option-order checks, and
the command-line entry. The Kev judge is a fake; nothing reaches a network or a cluster."""

from __future__ import annotations

import ast
import copy
import importlib
import io
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

import pytest

from lgtm.validation.cwe_criteria import CWE_CRITERIA
from lgtm.validation.judge import REQUEST_FORMATS

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

KINDS = ("safe_twin", "unrelated_code", "missing_check", "sqli_no_sql", "wrong_cwe")
CONTROL = "control"
ANSWER = {
    True: {"supported": "yes", "provenance_confidence": 0.9},
    False: {"supported": "no", "provenance_confidence": 0.9},
}


@pytest.fixture(scope="module")
def fixtures_mod():
    return importlib.import_module("kev_support.fixtures")


@pytest.fixture(scope="module")
def runner():
    return importlib.import_module("kev_support.runner")


@pytest.fixture(scope="module")
def all_fixtures(fixtures_mod):
    return fixtures_mod.load_fixtures()


def _is_correct(fixture) -> bool:
    return fixture.kind == CONTROL


def ideal_judge(truth):
    """Accepts exactly the controls."""

    def judge(case_id, request_format, request):
        return ANSWER[truth[case_id]]

    return judge


def run_bench(runner, tmp_path, judge, permute=None, fixtures=None):
    return runner.run(
        tmp_path / "out",
        work_dir=tmp_path / "work",
        judge=judge,
        permute=permute or judge,
        fixtures=fixtures,
    )


@pytest.fixture
def truth(all_fixtures):
    return {f.case_id: _is_correct(f) for f in all_fixtures}


class TestFixtureSet:
    def test_holds_six_incorrect_findings_per_kind_and_fifteen_controls(self, all_fixtures):
        counts = Counter(f.kind for f in all_fixtures)

        assert counts == Counter({**{kind: 6 for kind in KINDS}, CONTROL: 15})

    def test_case_ids_are_unique(self, all_fixtures):
        ids = [f.case_id for f in all_fixtures]

        assert len(set(ids)) == len(ids) == 45

    def test_every_fixture_passes_evidence_validation_against_its_case_repository(
        self, fixtures_mod, runner, all_fixtures, tmp_path
    ):
        repos = fixtures_mod.build_repos(tmp_path / "repos")

        for f in all_fixtures:
            repo = Path(repos[f.repo])
            assert runner.evidence_issues(f, repo) == [], f.case_id
            for item in f.finding.evidence:
                if item.type == "policy":
                    text = (repo / item.source).read_text(encoding="utf-8")
                else:
                    lines = (repo / item.file).read_text(encoding="utf-8").splitlines()
                    text = "\n".join(lines[item.lines[0] - 1 : item.lines[1]])
                assert _squash(item.content) in _squash(text), (f.case_id, item.file or item.source)

    def test_every_claimed_cwe_has_authored_criteria(self, all_fixtures):
        missing = {
            f.finding.cwe_id
            for f in all_fixtures
            if str(f.finding.cwe_id).strip().upper() not in CWE_CRITERIA
        }

        assert missing == set()


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


class TestRejectionReport:
    def test_judge_that_rejects_wrong_findings_and_accepts_controls_scores_all_of_them(
        self, runner, tmp_path, truth
    ):
        report = run_bench(runner, tmp_path, ideal_judge(truth))

        assert set(report["formats"]) == set(REQUEST_FORMATS)
        for fmt in REQUEST_FORMATS:
            entry = report["formats"][fmt]
            for kind in KINDS:
                assert (entry["kinds"][kind]["rejected"], entry["kinds"][kind]["evaluated"]) == (6, 6)
            assert (entry["controls"]["kept"], entry["controls"]["evaluated"]) == (15, 15)

    def test_judge_that_accepts_everything_rejects_nothing(self, runner, tmp_path):
        report = run_bench(runner, tmp_path, lambda cid, fmt, req: ANSWER[True])

        for fmt in REQUEST_FORMATS:
            for kind in KINDS:
                assert report["formats"][fmt]["kinds"][kind]["rejected"] == 0
                assert report["formats"][fmt]["kinds"][kind]["evaluated"] == 6

    def test_finding_failing_evidence_validation_is_reported_apart_and_never_judged(
        self, runner, tmp_path, truth, all_fixtures
    ):
        broken = copy.deepcopy(next(f for f in all_fixtures if f.kind == "safe_twin"))
        next(e for e in broken.finding.evidence if e.type == "code").lines = [9000, 9001]
        fixtures = [broken if f.case_id == broken.case_id else f for f in all_fixtures]
        seen = set()
        inner = ideal_judge(truth)

        def judge(case_id, request_format, request):
            seen.add(case_id)
            return inner(case_id, request_format, request)

        report = run_bench(runner, tmp_path, judge, fixtures=fixtures)

        assert broken.case_id not in seen
        assert report["evidence_failures"] == [broken.case_id]
        for fmt in REQUEST_FORMATS:
            cell = report["formats"][fmt]["kinds"]["safe_twin"]
            assert (cell["evidence_invalid"], cell["rejected"], cell["evaluated"]) == (1, 5, 5)

    @pytest.mark.parametrize("kind", [*KINDS, CONTROL])
    def test_judge_error_is_counted_for_that_finding_and_format_only_and_run_continues(
        self, runner, tmp_path, truth, all_fixtures, kind
    ):
        target = next(f for f in all_fixtures if f.kind == kind).case_id
        inner = ideal_judge(truth)

        def judge(case_id, request_format, request):
            if (case_id, request_format) == (target, "code_first"):
                raise RuntimeError("kev unreachable")
            return inner(case_id, request_format, request)

        report = run_bench(runner, tmp_path, judge)

        def cell(fmt):
            entry = report["formats"][fmt]
            return entry["controls"] if kind == CONTROL else entry["kinds"][kind]

        hit, other = cell("code_first"), cell("current")
        hits = hit["kept"] if kind == CONTROL else hit["rejected"]
        total = 15 if kind == CONTROL else 6
        assert (hit["errors"], hits, hit["evaluated"]) == (1, total - 1, total - 1)
        assert (other["errors"], other["evaluated"]) == (0, total)


class TestStabilityCallFailure:
    @pytest.mark.parametrize("route", ["repeat", "permute"])
    @pytest.mark.parametrize("kind", ["safe_twin", CONTROL])
    def test_failed_stability_call_keeps_the_valid_first_verdict_and_counts_one_error(
        self, runner, tmp_path, truth, all_fixtures, route, kind
    ):
        target = next(f for f in all_fixtures if f.kind == kind)
        inner = ideal_judge(truth)
        calls = Counter()

        def judge(case_id, request_format, request):
            calls[(case_id, request_format)] += 1
            if route == "repeat" and (case_id, request_format) == (target.case_id, "code_first") and calls[(case_id, request_format)] > 1:
                raise TimeoutError("repeat timed out")
            if route == "permute" and (case_id, request_format) == (target.case_id, "code_first") and calls[(case_id, request_format)] > 1:
                return ANSWER[not truth[case_id]]
            return inner(case_id, request_format, request)

        def permute(case_id, request_format, request):
            if (case_id, request_format) == (target.case_id, "code_first"):
                if route == "permute":
                    raise TimeoutError("permute timed out")
                return ANSWER[not truth[case_id]]
            return inner(case_id, request_format, request)

        report = run_bench(runner, tmp_path, judge, permute=permute)

        total = 15 if kind == CONTROL else 6
        hit, other = _cell(report, target, "code_first"), _cell(report, target, "current")
        assert (hit["errors"], _hits(hit), hit["evaluated"]) == (1, total, total)
        assert (other["errors"], _hits(other), other["evaluated"]) == (0, total, total)
        entry = report["formats"]["code_first"]
        failed, surviving = ("unstable", "order_sensitive") if route == "repeat" else ("order_sensitive", "unstable")
        assert target.case_id not in entry[failed]["cases"]
        assert target.case_id in entry[surviving]["cases"]

    def test_run_with_failed_calls_exits_non_zero_and_still_writes_the_report(
        self, runner, tmp_path, truth, all_fixtures
    ):
        target = all_fixtures[0].case_id
        inner = ideal_judge(truth)

        def permute(case_id, request_format, request):
            if case_id == target:
                raise TimeoutError("permute timed out")
            return inner(case_id, request_format, request)

        out = tmp_path / "out"
        code = runner.main(["--out", str(out), "--work-dir", str(tmp_path / "work")], judge=inner, permute=permute)

        assert code != 0
        assert (out / "report.json").is_file()

    def test_run_where_the_permute_route_is_missing_exits_non_zero_with_every_verdict_scored(
        self, runner, tmp_path, truth
    ):
        inner = ideal_judge(truth)

        def permute(case_id, request_format, request):
            raise OSError("HTTP Error 404: Not Found")

        out = tmp_path / "out"
        code = runner.main(["--out", str(out), "--work-dir", str(tmp_path / "work")], judge=inner, permute=permute)

        assert code != 0
        report = json.loads((out / "report.json").read_text())
        for fmt in REQUEST_FORMATS:
            entry = report["formats"][fmt]
            for kind in KINDS:
                assert (entry["kinds"][kind]["rejected"], entry["kinds"][kind]["evaluated"]) == (6, 6)
            assert (entry["controls"]["kept"], entry["controls"]["evaluated"]) == (15, 15)

    def test_run_where_the_judge_is_unreachable_exits_non_zero(self, runner, tmp_path, truth):
        def judge(case_id, request_format, request):
            raise ConnectionRefusedError("kev unreachable")

        code = runner.main(
            ["--out", str(tmp_path / "out"), "--work-dir", str(tmp_path / "work")], judge=judge, permute=judge
        )

        assert code != 0


def _cell(report, fixture, fmt):
    entry = report["formats"][fmt]
    return entry["controls"] if fixture.kind == CONTROL else entry["kinds"][fixture.kind]


def _hits(cell):
    return cell["kept"] if "kept" in cell else cell["rejected"]


class TestRequestFormats:
    def test_each_call_carries_the_request_built_for_its_requested_format(
        self, fixtures_mod, runner, all_fixtures, truth, tmp_path
    ):
        from lgtm.config import LGTMConfig
        from lgtm.validation.evidence import EvidenceValidator
        from lgtm.validation.judge import JUDGE_STATE_MAX_CHARS, build_judge_request

        repos = fixtures_mod.build_repos(tmp_path / "repos")
        model = LGTMConfig().judge_model
        inner = ideal_judge(truth)
        seen = {"judge": [], "permute": []}

        def recording(route):
            def call(case_id, request_format, request):
                seen[route].append((case_id, request_format, request))
                return inner(case_id, request_format, request)

            return call

        run_bench(runner, tmp_path, recording("judge"), permute=recording("permute"))

        by_id = {f.case_id: f for f in all_fixtures}
        assert {(c, fmt) for c, fmt, _ in seen["judge"]} == {
            (f.case_id, fmt) for f in all_fixtures for fmt in REQUEST_FORMATS
        }
        for case_id, fmt, request in [*seen["judge"], *seen["permute"]]:
            f = by_id[case_id]
            expected = build_judge_request(
                f.finding,
                EvidenceValidator(Path(repos[f.repo]), "HEAD").read_cited_code,
                model=model,
                max_chars=JUDGE_STATE_MAX_CHARS,
                request_format=fmt,
            )
            assert request == expected, (case_id, fmt)
        distinct = {
            json.dumps(r, sort_keys=True, default=str)
            for c, _, r in seen["judge"]
            if c == all_fixtures[0].case_id
        }
        assert len(distinct) > 1


class TestStability:
    def test_verdict_that_changes_on_repeat_is_listed_as_unstable_in_its_format(
        self, runner, tmp_path, truth, all_fixtures
    ):
        target = all_fixtures[7].case_id
        inner = ideal_judge(truth)
        calls = Counter()

        def judge(case_id, request_format, request):
            calls[(case_id, request_format)] += 1
            flip = (case_id, request_format) == (target, "short_claim") and calls[(case_id, request_format)] > 1
            return ANSWER[truth[case_id] != flip]

        report = run_bench(runner, tmp_path, judge, permute=inner)

        flipped = all_fixtures[7]
        total = 15 if flipped.kind == CONTROL else 6
        assert _hits(_cell(report, flipped, "short_claim")) == total
        assert report["formats"]["short_claim"]["unstable"] == {"count": 1, "cases": [target]}
        for fmt in set(REQUEST_FORMATS) - {"short_claim"}:
            assert report["formats"][fmt]["unstable"] == {"count": 0, "cases": []}
            assert report["formats"][fmt]["order_sensitive"] == {"count": 0, "cases": []}

    def test_rate_counts_the_first_plain_verdict_not_the_repeat_or_permute_verdict(
        self, runner, tmp_path, truth, all_fixtures
    ):
        wrong_first = all_fixtures[7]
        wrong_permute = all_fixtures[20]
        calls = Counter()

        def judge(case_id, request_format, request):
            calls[(case_id, request_format)] += 1
            if case_id == wrong_first.case_id and request_format == "short_claim":
                return ANSWER[truth[case_id] != (calls[(case_id, request_format)] == 1)]
            return ANSWER[truth[case_id]]

        def permute(case_id, request_format, request):
            wrong = (case_id, request_format) == (wrong_permute.case_id, "code_only")
            return ANSWER[truth[case_id] != wrong]

        report = run_bench(runner, tmp_path, judge, permute=permute)

        def total(f):
            return 15 if f.kind == CONTROL else 6

        assert _hits(_cell(report, wrong_first, "short_claim")) == total(wrong_first) - 1
        assert _hits(_cell(report, wrong_permute, "code_only")) == total(wrong_permute)
        assert report["formats"]["short_claim"]["unstable"]["cases"] == [wrong_first.case_id]
        assert report["formats"]["code_only"]["order_sensitive"]["cases"] == [wrong_permute.case_id]

    def test_deterministic_judge_has_no_unstable_or_order_sensitive_requests(
        self, runner, tmp_path, truth
    ):
        report = run_bench(runner, tmp_path, ideal_judge(truth))

        for fmt in REQUEST_FORMATS:
            assert report["formats"][fmt]["unstable"] == {"count": 0, "cases": []}
            assert report["formats"][fmt]["order_sensitive"] == {"count": 0, "cases": []}

    def test_verdict_that_changes_on_the_permute_route_is_listed_as_order_sensitive(
        self, runner, tmp_path, truth, all_fixtures
    ):
        target = all_fixtures[20].case_id
        inner = ideal_judge(truth)
        permuted = set()

        def permute(case_id, request_format, request):
            permuted.add((case_id, request_format))
            return ANSWER[truth[case_id] != ((case_id, request_format) == (target, "code_only"))]

        report = run_bench(runner, tmp_path, inner, permute=permute)

        assert permuted == {(f.case_id, fmt) for f in all_fixtures for fmt in REQUEST_FORMATS}
        assert report["formats"]["code_only"]["order_sensitive"] == {"count": 1, "cases": [target]}
        for fmt in set(REQUEST_FORMATS) - {"code_only"}:
            assert report["formats"][fmt]["order_sensitive"] == {"count": 0, "cases": []}
        for fmt in REQUEST_FORMATS:
            assert report["formats"][fmt]["unstable"] == {"count": 0, "cases": []}


class _Response(io.BytesIO):
    pass


class _FakeOpener:
    def __init__(self, log):
        self.log = log

    def open(self, request, timeout=None):
        body = json.loads(request.data)
        self.log.append((request.full_url, body))
        if request.full_url.endswith("/permute"):
            reply = {
                "runs": [{"order": ["yes", "no"], "probabilities": {"yes": 0.1, "no": 0.9}, "choice": "no"}],
                "argmax_stable": True,
                "spread": {"yes": 0.0, "no": 0.0},
            }
        else:
            reply = {
                "answers": {
                    "supported": {"type": "choice", "choice": "no"},
                    "provenance_confidence": {"type": "noul", "noul": 0.1},
                }
            }
        return _Response(json.dumps(reply).encode())


class TestEntryPoint:
    def test_writes_report_to_a_new_output_directory_and_leaves_existing_results_alone(
        self, runner, tmp_path, truth
    ):
        old = tmp_path / "results" / "old.json"
        old.parent.mkdir()
        old.write_text('{"keep": true}')
        out = tmp_path / "runs" / "kev-support"
        judge = ideal_judge(truth)

        code = runner.main(
            ["--out", str(out), "--work-dir", str(tmp_path / "work")], judge=judge, permute=judge
        )

        assert code == 0
        report = json.loads((out / "report.json").read_text())
        assert set(report["formats"]) == set(REQUEST_FORMATS)
        assert old.read_text() == '{"keep": true}'
        assert [p for p in tmp_path.iterdir() if p.name not in {"results", "runs", "work"}] == []

    def test_sends_requests_to_the_kev_endpoint_from_the_judge_settings(
        self, runner, tmp_path, monkeypatch
    ):
        from lgtm.config import LGTMConfig

        endpoint = LGTMConfig().judge_endpoint.rstrip("/")
        log = []
        monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener(log))

        code = runner.main(["--out", str(tmp_path / "out"), "--work-dir", str(tmp_path / "work")])

        assert code == 0
        assert {url for url, _ in log} == {
            f"{endpoint}/v1/systemone",
            f"{endpoint}/v1/systemone/permute",
        }
        assert all("request" in body for url, body in log if url.endswith("/permute"))
        assert (tmp_path / "out" / "report.json").is_file()


AGENT_MODULE_ROOTS = ("lgtm.agents", "lgtm.pipeline", "lgtm.review", "evaluate")
ALLOWED_AGENT_IMPORTS = ("lgtm.agents.base",)


def _imported_modules(source: str) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _agent_imports(source: str) -> set[str]:
    return {
        name
        for name in _imported_modules(source)
        if any(name == root or name.startswith(root + ".") for root in AGENT_MODULE_ROOTS)
        and not any(name == ok or name.startswith(ok + ".") for ok in ALLOWED_AGENT_IMPORTS)
    }


class TestNoAgentImports:
    def test_checker_flags_agent_pipeline_review_and_evaluate_imports(self):
        source = "\n".join(
            [
                "import lgtm.agents.investigator",
                "from lgtm.agents import registry",
                "from lgtm.pipeline import run",
                "from lgtm.review.dedup import dedup",
                "import evaluate",
                "from lgtm.agents.base import AgentFinding",
            ]
        )
        assert _agent_imports(source) == {
            "lgtm.agents",
            "lgtm.agents.investigator",
            "lgtm.agents.registry",
            "lgtm.pipeline",
            "lgtm.pipeline.run",
            "lgtm.review.dedup",
            "lgtm.review.dedup.dedup",
            "evaluate",
        }

    def test_no_benchmark_module_imports_an_lgtm_agent_module(self):
        modules = sorted((BENCH / "kev_support").rglob("*.py"))
        assert modules, "benchmark/kev_support/ holds no modules"
        offenders = {
            str(path.relative_to(BENCH)): sorted(_agent_imports(path.read_text(encoding="utf-8")))
            for path in modules
        }
        assert {k: v for k, v in offenders.items() if v} == {}

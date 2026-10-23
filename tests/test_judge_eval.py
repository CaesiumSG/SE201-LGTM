"""Unit tests for judge evaluation: citation support, judge-quality measures, support
perturbations, fallback and latency, and not-judged case exclusion in the three harnesses."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig

BENCH = Path(__file__).resolve().parent.parent / "benchmark"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def je():
    return _load("jt_judge_eval", BENCH / "judge_eval.py")


@pytest.fixture(scope="module")
def ev():
    return _load("jt_evaluate", BENCH / "evaluate.py")


@pytest.fixture(scope="module")
def er():
    return _load("jt_evaluate_real", BENCH / "real_world" / "evaluate_real.py")


@pytest.fixture(scope="module")
def inj():
    return _load("jt_injection", BENCH / "injection" / "run_injection_bench.py")


def _outcome(unit_id, judged=True, supported=True, confidence=0.5):
    return {
        "unit_id": unit_id, "judged": judged,
        "supported": supported if judged else None,
        "provenance_confidence": confidence if judged else None,
    }


def _labels(**units):
    """_labels(u1="yes", u2="no") -> labels file content."""
    return {"units": {unit_id: {"supports": label} for unit_id, label in units.items()}}


class TestCitationSupport:
    UNITS = ["u1", "u2", "u3", "u4", "u5"]

    def _report(self, je, labels, outcomes):
        return je.citation_support(self.UNITS, labels, outcomes)

    def test_percent_yes_with_n_and_unlabelled_for_both_populations(self, je):
        labels = _labels(u1="yes", u2="yes", u3="no", u4="no")
        outcomes = [
            _outcome("u1"),
            _outcome("u2"),
            _outcome("u3", supported=False),
            _outcome("u4", judged=False),
            _outcome("u5"),
        ]

        report = self._report(je, labels, outcomes)

        before = report["before_judging"]
        assert (before["n"], before["unlabelled"]) == (4, 1)
        assert before["percent_yes"] == pytest.approx(50.0)
        judged = report["judged"]
        assert (judged["n"], judged["unlabelled"]) == (2, 1)
        assert judged["percent_yes"] == pytest.approx(100.0)

    def test_judged_population_counts_only_units_the_judge_found_supported(self, je):
        labels = _labels(u1="yes", u2="no", u3="yes", u4="yes", u5="no")
        outcomes = [
            _outcome("u1"),
            _outcome("u2"),
            _outcome("u3", supported=False),
            _outcome("u4", supported=False),
            {**_outcome("u5", judged=False), "supported": True},
        ]

        report = self._report(je, labels, outcomes)

        assert report["judged"]["n"] == 2
        assert report["judged"]["percent_yes"] == pytest.approx(50.0)
        assert report["before_judging"]["n"] == 5

    def test_unlabelled_units_are_counted_and_do_not_fail_the_report(self, je):
        report = self._report(je, _labels(u1="yes"), [_outcome(u) for u in self.UNITS])

        assert report["before_judging"]["n"] == 1
        assert report["before_judging"]["unlabelled"] == 4
        assert report["before_judging"]["percent_yes"] == pytest.approx(100.0)

    def test_population_without_labelled_units_reports_no_percentage(self, je):
        report = self._report(je, _labels(), [_outcome(u) for u in self.UNITS])

        assert report["judged"]["n"] == 0
        assert report["judged"]["unlabelled"] == 5
        assert report["judged"]["percent_yes"] is None

    @pytest.mark.parametrize(
        "labels,offender",
        [
            (_labels(u1="yes", ghost="yes"), "ghost"),
            ({"units": {"u1": {"supports": "maybe"}}}, "u1"),
            ({"units": {"u1": {"supports": "Yes"}}}, "u1"),
            ({"units": {"u1": {"supports": "correct"}}}, "u1"),
            ({"units": {"u1": {"supports": True}}}, "u1"),
            ({"units": {"u1": {"supports": None}}}, "u1"),
            ({"units": {"u1": {}}}, "u1"),
        ],
    )
    def test_labels_file_with_unknown_id_or_bad_label_stops_naming_the_entry(
        self, je, labels, offender
    ):
        with pytest.raises(ValueError) as exc:
            self._report(je, labels, [_outcome("u1")])

        assert offender in str(exc.value)

    def test_both_populations_come_from_one_export_and_one_labels_file(self, je):
        labels = _labels(u1="yes", u2="no", u3="yes")
        outcomes = [_outcome("u1"), _outcome("u2", supported=False), _outcome("u3", judged=False)]

        report = self._report(je, labels, outcomes)

        assert report["judged"]["n"] + report["judged"]["unlabelled"] <= (
            report["before_judging"]["n"] + report["before_judging"]["unlabelled"]
        )
        assert report["before_judging"]["n"] + report["before_judging"]["unlabelled"] == len(self.UNITS)


class TestConfidenceAgreement:
    def test_mean_confidence_for_yes_and_no_units_with_n(self, je):
        labels = _labels(
            u1="yes", u2="yes", u3="no", u4="no", u5="no",
            u6="yes", u7="no",
        )
        outcomes = [
            _outcome("u1", confidence=0.9),
            _outcome("u2", confidence=0.7),
            _outcome("u3", confidence=0.2),
            _outcome("u4", confidence=0.4),
            _outcome("u5", judged=False),
            _outcome("u6", supported=False, confidence=0.8),
            _outcome("u7", supported=False, confidence=0.6),
        ]

        result = je.confidence_agreement(labels, outcomes)

        assert result["yes"]["n"] == 3
        assert result["yes"]["mean"] == pytest.approx(0.8)
        assert result["no"]["n"] == 3
        assert result["no"]["mean"] == pytest.approx(0.4)

    def test_unlabelled_units_do_not_enter_either_mean(self, je):
        outcomes = [_outcome("u1", confidence=0.9), _outcome("u2", confidence=0.1)]

        result = je.confidence_agreement(_labels(u1="yes"), outcomes)

        assert result["yes"] == {"mean": pytest.approx(0.9), "n": 1}
        assert result["no"]["n"] == 0
        assert result["no"]["mean"] is None


def _case(cid, expected, findings, category="authz"):
    return {"id": cid, "category": category, "expected": expected, "findings": findings}


def _jf(supported, category="authz"):
    return {"category": category, "judged": True, "supported": supported}


class TestVerdictAccuracy:
    def test_accuracy_scores_a_case_by_whether_a_candidate_is_supported(self, je):
        cases = [
            _case("a", "vulnerable", [_jf(True)]),
            _case("b", "safe", [_jf(False)]),
            _case("c", "vulnerable", [_jf(False)]),
            _case("d", "safe", [_jf(True)]),
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["correct"]) == (4, 2)
        assert result["accuracy"] == pytest.approx(0.5)

    def test_case_without_expected_verdict_is_unlabelled_and_excluded_from_this_measure_only(self, je):
        cases = [
            _case("a", "vulnerable", [_jf(True)]),
            _case("b", None, [_jf(True)]),
            _case("c", "", [_jf(False)]),
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["unlabelled"]) == (1, 2)
        assert result["accuracy"] == pytest.approx(1.0)

    @staticmethod
    def _not_judged_finding():
        return {
            "category": "authz", "judged": False, "supported": None,
            "not_judged_reason": "judge-failed", "verdict": "",
        }

    def test_error_and_not_judged_cases_in_a_judged_mode_are_excluded_not_scored(self, je):
        cases = [
            {**_case("c_ok", "vulnerable", [_jf(True)]), "mode": "lgtm"},
            {
                **_case("c_nj", "vulnerable", [_jf(True), self._not_judged_finding()]),
                "mode": "lgtm",
            },
            {**_case("c_err", "vulnerable", [_jf(True)]), "mode": "lgtm", "error": "boom"},
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["excluded"]) == (1, 2)
        assert result["correct"] == 1

    @pytest.mark.parametrize("mode", ["llm-only", "sast-only"])
    def test_not_judged_case_outside_judged_modes_is_still_scored(self, je, mode):
        baseline = {"category": "authz", "judged": False, "supported": None, "verdict": "vulnerable"}
        cases = [
            {**_case("c_nj", "vulnerable", [baseline, self._not_judged_finding()]), "mode": mode}
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["excluded"]) == (1, 0)


class TestSupportedAgreement:
    def test_share_of_judged_units_whose_supported_answer_matches_the_label_with_n(self, je):
        labels = _labels(u1="yes", u2="no", u3="yes", u4="no")
        outcomes = [
            _outcome("u1"),
            _outcome("u2", supported=False),
            _outcome("u3", supported=False),
            _outcome("u4"),
        ]

        result = je.supported_agreement(labels, outcomes)

        assert (result["n"], result["agree"]) == (4, 2)
        assert result["agreement"] == pytest.approx(0.5)

    def test_unlabelled_and_not_judged_units_are_excluded_and_counted(self, je):
        labels = _labels(u1="yes", u2="no", u4="yes")
        outcomes = [
            _outcome("u1"),
            _outcome("u2", judged=False),
            _outcome("u3"),
            _outcome("u4", judged=False),
            _outcome("u5", judged=False),
        ]

        result = je.supported_agreement(labels, outcomes)

        assert (result["n"], result["agree"]) == (1, 1)
        assert result["unlabelled"] == 1
        assert result["not_judged"] == 3
        assert result["agreement"] == pytest.approx(1.0)

    def test_no_judged_labelled_unit_reports_no_agreement(self, je):
        result = je.supported_agreement(_labels(u1="yes"), [_outcome("u1", judged=False)])

        assert result["n"] == 0
        assert result["agreement"] is None


def _not_judged_with(reason):
    return {**_finding(judged=False), "not_judged_reason": reason}


class TestNotJudgedByReason:
    def test_counts_per_reason_with_request_too_large_distinct_from_judge_failures(self, je):
        findings = [
            _not_judged_with("request-too-large"),
            _not_judged_with("judge-failed"),
            _not_judged_with("judge-failed"),
            _finding(),
            _finding(supported=False),
        ]

        counts = je.not_judged_by_reason(findings)

        assert counts == {"request-too-large": 1, "judge-failed": 2}

    def test_run_with_every_candidate_judged_has_no_reasons(self, je):
        assert je.not_judged_by_reason([_finding(), _finding(supported=False)]) == {}


class TestSupportPerturbations:
    CLAIMS = {"claim a": "a.py", "claim b": "b.py", "claim c": "elsewhere.py"}

    @staticmethod
    def _candidate(fid, claim, file, with_citation=True):
        evidence = [EvidenceItem(type="code", file=file, lines=[1, 2], snapshot="pr",
                                 content="agent snippet", grounded_in_pr=True)]
        return AgentFinding(
            finding_id=fid, cwe_id="CWE-639", explanation=claim, category="authz", agent="authz",
            file=file, line=1, pr_graph_ok=True, evidence=evidence if with_citation else [],
        )

    def _candidates(self):
        return [
            self._candidate("a", "claim a", "a.py"),
            self._candidate("b", "claim b", "b.py"),
            self._candidate("c", "claim c", "c.py"),
        ]

    @staticmethod
    def _read_code(item):
        if item.file == "gone.py":
            raise FileNotFoundError(item.file)
        return f"CODE_OF_{item.file}"

    def _judge(self, request):
        claim = request["state"].splitlines()[0].removeprefix("Claim: ")
        expected = self.CLAIMS.get(claim)
        supported = expected is not None and f"CODE_OF_{expected}" in request["state"]
        return {"supported": "yes" if supported else "no",
                "provenance_confidence": 0.9 if supported else 0.2}

    @staticmethod
    def _unrelated(finding):
        return "UNRELATED_CODE"

    @staticmethod
    def _safe_twin(finding):
        return "SAFE_TWIN_CODE"

    def _measure(self, je, candidates, judge=None, safe_twin=None):
        return je.measure_perturbations(
            candidates, self._read_code, LGTMConfig(), judge or self._judge,
            unrelated_code=self._unrelated, safe_twin_code=safe_twin or self._safe_twin,
        )

    def test_one_known_unsupported_copy_per_perturbation_for_every_judged_original(self, je):
        measured = self._measure(je, self._candidates())

        by_type = {}
        for record in measured["records"]:
            by_type.setdefault(record["perturbation"], []).append(record)
        assert set(by_type) == {"unrelated_code", "mutated_claim", "safe_twin_code"}
        assert all(len(records) == 3 for records in by_type.values())
        assert all(r["known_unsupported"] is True for r in measured["records"])

    def test_report_states_support_rate_and_confidence_drop_per_perturbation_with_n(self, je):
        report = je.perturbation_report(self._measure(je, self._candidates()))

        assert set(report) == {"unrelated_code", "mutated_claim", "safe_twin_code"}
        for name, row in report.items():
            assert row["n"] == 3, name
            assert row["support_rate_drop"] == pytest.approx(2 / 3), name
            assert row["confidence_drop"] == pytest.approx((0.9 + 0.9 + 0.2) / 3 - 0.2), name

    def test_perturbation_the_judge_still_supports_shows_no_drop(self, je):
        def credulous(request):
            return {"supported": "yes", "provenance_confidence": 0.9}

        report = je.perturbation_report(self._measure(je, self._candidates(), judge=credulous))

        for name, row in report.items():
            assert row["n"] == 3, name
            assert row["support_rate_drop"] == pytest.approx(0), name
            assert row["confidence_drop"] == pytest.approx(0), name

    def test_safe_twin_is_skipped_and_counted_for_a_candidate_without_a_fixed_variant(self, je):
        def twin_for_a_only(finding):
            return "SAFE_TWIN_CODE" if finding.finding_id == "a" else None

        report = je.perturbation_report(
            self._measure(je, self._candidates(), safe_twin=twin_for_a_only))

        assert (report["safe_twin_code"]["n"], report["safe_twin_code"]["skipped"]) == (1, 2)
        assert report["unrelated_code"]["n"] == 3
        assert report["mutated_claim"]["n"] == 3

    def test_original_the_judge_fails_on_is_left_out_and_the_run_completes(self, je):
        def fails_on_claim_a(request):
            if request["state"].startswith("Claim: claim a\n"):
                raise ConnectionError("unreachable")
            return self._judge(request)

        report = je.perturbation_report(self._measure(je, self._candidates(), judge=fails_on_claim_a))

        assert all(row["n"] == 2 for row in report.values())

    def test_perturbed_copy_the_judge_fails_on_is_left_out_of_its_perturbation_only(self, je):
        def fails_on_mutated_claim_of_b(request):
            if request["state"].startswith(f"Claim: {je.MUTATED_CLAIM}\n") and "CODE_OF_b.py" in request["state"]:
                raise ConnectionError("unreachable")
            return self._judge(request)

        report = je.perturbation_report(
            self._measure(je, self._candidates(), judge=fails_on_mutated_claim_of_b))

        assert (report["unrelated_code"]["n"], report["safe_twin_code"]["n"]) == (3, 3)
        mutated = report["mutated_claim"]
        assert mutated["n"] == 2
        assert mutated["support_rate_drop"] == pytest.approx(0.5)
        assert mutated["confidence_drop"] == pytest.approx(0.35)

    def test_candidate_without_a_readable_code_citation_is_not_perturbed(self, je):
        candidates = [
            self._candidate("a", "claim a", "a.py"),
            self._candidate("none", "claim a", "a.py", with_citation=False),
            self._candidate("gone", "claim a", "gone.py"),
        ]

        report = je.perturbation_report(self._measure(je, candidates))

        assert all(row["n"] == 1 for row in report.values())

    def test_candidates_passed_in_are_not_modified(self, je):
        candidates = self._candidates()
        before = [c.model_dump() for c in candidates]

        self._measure(je, candidates)

        assert [c.model_dump() for c in candidates] == before


class _Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def _candidate(fid):
    return AgentFinding(
        finding_id=fid, cwe_id="CWE-89", explanation="claim", category="sqli", agent="authz",
        file="app.py", line=1, pr_graph_ok=True,
        evidence=[EvidenceItem(type="code", file="app.py", lines=[1, 2], snapshot="pr",
                               content="x", grounded_in_pr=True)],
    )


GOOD = {"supported": "yes", "provenance_confidence": 0.8}


def _scripted_judge(clock, script):
    """script: one (seconds, outcome) per call; outcome is a reply dict or an exception."""
    steps = iter(script)

    def judge(request):
        seconds, outcome = next(steps)
        clock.now += seconds
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return judge


def _measure(je, candidates, judge, clock):
    return je.measure_judge_run(candidates, lambda item: "CODE", LGTMConfig(), judge, clock=clock)


class TestFallbackAndLatency:
    def test_run_completes_and_reports_fallback_rate_over_injected_judge_failures(self, je):
        clock = _Clock()
        judge = _scripted_judge(clock, [
            (1, GOOD),
            (1, ConnectionError("unreachable")),
            (1, GOOD),
            (1, TimeoutError("timed out")),
            (1, GOOD),
            (1, {"supported": "banana"}),
        ])
        candidates = [_candidate(f"c{i}") for i in range(6)]

        records = _measure(je, candidates, judge, clock)
        measures = je.run_measures(records, "lgtm")

        assert [r["judged"] for r in records] == [True, False, True, False, True, False]
        assert measures["n"] == 6
        assert measures["not_judged"] == 3
        assert measures["fallback_rate"] == pytest.approx(0.5)

    def test_every_candidate_gets_a_latency_record_on_success_and_failure(self, je):
        clock = _Clock()
        judge = _scripted_judge(clock, [(2, GOOD), (3, ConnectionError("down"))])

        records = _measure(je, [_candidate("a"), _candidate("b")], judge, clock)

        assert [r["latency_seconds"] for r in records] == [pytest.approx(2), pytest.approx(3)]

    def test_latency_median_and_95th_percentile(self, je):
        clock = _Clock()
        seconds = [1] * 18 + [5, 9]
        judge = _scripted_judge(clock, [(s, GOOD) for s in seconds])

        records = _measure(je, [_candidate(f"c{i}") for i in range(20)], judge, clock)
        measures = je.run_measures(records, "lgtm-no-sast")

        assert measures["latency_median"] == pytest.approx(1.0)
        assert measures["latency_p95"] == pytest.approx(5.0)
        assert measures["fallback_rate"] == 0

    def test_candidates_with_no_cited_source_are_excluded_from_judge_latency_and_n(self, je):
        clock = _Clock()
        judge = _scripted_judge(clock, [(5, GOOD)])
        no_source = _candidate("no-source")
        no_source.evidence = []

        records = _measure(je, [_candidate("with-code"), no_source], judge, clock)
        measures = je.run_measures(records, "lgtm")

        assert measures["n"] == 1
        assert measures["not_judged"] == 0
        assert measures["fallback_rate"] == 0
        assert measures["latency_median"] == pytest.approx(5.0)
        assert measures["latency_p95"] == pytest.approx(5.0)

    @pytest.mark.parametrize("mode", ["sast-only", "llm-only"])
    def test_fallback_rate_is_not_reported_for_modes_without_a_judge(self, je, mode):
        records = [
            {"judged": False, "latency_seconds": None},
            {"judged": False, "latency_seconds": None},
        ]

        assert je.run_measures(records, mode)["fallback_rate"] is None


def _finding(judged=True, supported=True, verdict="", category="authz"):
    return {
        "finding_id": "authz:1", "category": category, "verdict": verdict,
        "judged": judged, "supported": supported if judged else None,
        "explanation": "claim",
    }


def _not_judged(category="authz"):
    """Candidate the judge failed on: no support result."""
    return {**_finding(judged=False, category=category), "not_judged_reason": "judge-failed"}


def _row(cid, expected, findings, mode="lgtm", category="authz"):
    return {
        "id": cid, "category": category, "split": "dev", "expected": expected, "mode": mode,
        "pin": {}, "n_findings": len(findings), "verdicts": [f["verdict"] for f in findings],
        "grounded": len(findings), "grounding_rate": 1.0, "latency_seconds": 1.0,
        "est_tokens": 10, "findings": findings,
    }


def _scored_rows(ev, mode):
    return [
        ev.score_case(_row("a", "vulnerable", [_finding()], mode)),
        ev.score_case(_row(
            "b", "vulnerable",
            [_not_judged(), _not_judged(), _finding(supported=False)], mode)),
        ev.score_case(_row("c", "safe", [_finding(supported=False)], mode)),
    ]


class TestNotJudgedExclusionInSyntheticHarness:
    @pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
    def test_case_with_a_not_judged_candidate_is_excluded_and_listed_with_its_count(self, ev, mode):
        summary = ev.summarize(_scored_rows(ev, mode))

        overall = summary["overall"]
        assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (1, 0, 0, 1)
        assert overall["scored"] == 2
        assert overall["accuracy"] == 1.0
        assert summary["not_judged_cases"] == [{"id": "b", "not_judged": 2}]

    @pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
    def test_cases_whose_candidates_were_all_judged_are_scored_and_not_listed(self, ev, mode):
        rows = [
            ev.score_case(_row("a", "vulnerable", [_finding()], mode)),
            ev.score_case(_row("c", "safe", [_finding(supported=False)], mode)),
        ]

        summary = ev.summarize(rows)

        assert summary["overall"]["scored"] == 2
        assert summary.get("not_judged_cases", []) == []

    @pytest.mark.parametrize("mode", ["sast-only", "llm-only"])
    def test_runs_without_a_judge_are_scored_as_before(self, ev, mode):
        rows = [
            ev.score_case(_row("a", "vulnerable", [_finding(judged=False, verdict="vulnerable")], mode)),
            ev.score_case(_row("c", "safe", [_finding(judged=False, verdict="safe")], mode)),
        ]

        summary = ev.summarize(rows)

        overall = summary["overall"]
        assert (overall["tp"], overall["tn"], overall["scored"]) == (1, 1, 2)
        assert summary.get("not_judged_cases", []) == []


class TestNotJudgedExclusionInRealWorldHarness:
    def _summary(self, er, ev, tmp_path, mode):
        out = tmp_path / mode
        out.mkdir()
        rows = _scored_rows(ev, mode)
        for row in rows:
            (out / f"{row['id']}.json").write_text(json.dumps(row), encoding="utf-8")
        return er.write_dir_summary(out, mode, "own", {r["id"] for r in rows}, "m")["summary"]

    def test_judged_mode_excludes_and_lists_the_case_with_a_not_judged_candidate(self, er, ev, tmp_path):
        summary = self._summary(er, ev, tmp_path, "lgtm")

        assert summary["overall"]["scored"] == 2
        assert summary["overall"]["fn"] == 0
        assert summary["not_judged_cases"] == [{"id": "b", "not_judged": 2}]

    @pytest.mark.parametrize("mode", ["sast-only", "llm-only"])
    def test_modes_without_a_judge_are_scored_as_before(self, er, ev, tmp_path, mode):
        out = tmp_path / mode
        out.mkdir()
        row = ev.score_case(_row("a", "vulnerable", [_finding(judged=False, verdict="vulnerable")], mode))
        (out / "a.json").write_text(json.dumps(row), encoding="utf-8")

        summary = er.write_dir_summary(out, mode, "own", {"a"}, "m")["summary"]

        assert summary["overall"]["tp"] == 1
        assert summary.get("not_judged_cases", []) == []


INJECTION_CASE = "inj_01_sqli_comment"


def _record(cid, flagged, findings):
    return {
        "id": cid, "category": "sqli", "expected": "vulnerable",
        "predicted": "vulnerable" if flagged else "safe", "flagged": flagged,
        "latency_seconds": 1.0, "findings": findings,
        "graph_state": "ok", "graph_index_seconds": 1.0, "base_sha": "a" * 40, "pr_sha": "b" * 40,
    }


class TestNotJudgedExclusionInInjectionHarness:
    def _run(self, inj, monkeypatch, tmp_path, mode, injected_findings, injected_flagged=False):
        def fake(case, config):
            if case["id"] == INJECTION_CASE:
                return _record(case["id"], injected_flagged, injected_findings)
            return _record(case["id"], True, [_finding(category="sqli")])

        monkeypatch.setattr(inj, "evaluate_single_case", fake)
        out = tmp_path / "out"
        monkeypatch.setattr(sys, "argv", [
            "run_injection_bench.py", "--mode", mode, "--cases", INJECTION_CASE, "--output", str(out)])
        inj.main()
        return json.loads((out / "summary.json").read_text(encoding="utf-8"))

    def test_judged_mode_pair_with_a_not_judged_candidate_is_excluded_from_attack_success(
        self, inj, monkeypatch, tmp_path
    ):
        summary = self._run(
            inj, monkeypatch, tmp_path, "lgtm",
            [_not_judged("sqli"), _not_judged("sqli")],
        )

        assert summary["originally_flagged"] == 0
        assert summary["attacks_succeeded"] == 0
        assert [c["not_judged"] for c in summary["not_judged_cases"]] == [2]
        assert summary["not_judged_cases"][0]["id"] == INJECTION_CASE

    def test_judged_mode_pair_with_every_candidate_judged_is_scored(self, inj, monkeypatch, tmp_path):
        summary = self._run(
            inj, monkeypatch, tmp_path, "lgtm", [_finding(supported=False, category="sqli")])

        assert summary["originally_flagged"] == 1
        assert summary["attacks_succeeded"] == 1
        assert summary.get("not_judged_cases", []) == []

    def test_llm_only_pair_is_scored_as_before_with_the_plain_reviewers_own_verdict(
        self, inj, monkeypatch, tmp_path
    ):
        summary = self._run(
            inj, monkeypatch, tmp_path, "llm-only",
            [_finding(judged=False, verdict="safe", category="sqli")],
        )

        assert summary["originally_flagged"] == 1
        assert summary["attacks_succeeded"] == 1
        assert summary.get("not_judged_cases", []) == []

    def test_sast_only_pair_is_scored_as_before_with_its_fixed_vulnerable_verdict(
        self, inj, monkeypatch, tmp_path
    ):
        summary = self._run(
            inj, monkeypatch, tmp_path, "sast-only",
            [_finding(judged=False, verdict="vulnerable", category="sqli")],
            injected_flagged=True,
        )

        assert summary["originally_flagged"] == 1
        assert summary["attacks_succeeded"] == 0
        assert summary.get("not_judged_cases", []) == []


# ---------------------------------------------------------------------------
# Integration: unit export from a recorded run directory and real case repos
# ---------------------------------------------------------------------------

BASE_APP = "line1\nbase2\nbase3\nline4\nline5\n"
PR_APP = "line1\npr2\npr3\nline4\nline5\n"


def _git(repo: Path, *args: str) -> str:
    import subprocess

    done = subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args],
        cwd=repo, capture_output=True, text=True, check=True,
    )
    return done.stdout.strip()


def _case_repo(root: Path) -> dict:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text(BASE_APP, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "pr")
    (repo / "app.py").write_text(PR_APP, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "pr")
    pr_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    return {"repo": repo, "base_sha": base_sha, "pr_sha": pr_sha}


def _recorded_finding(finding_id, claim, evidence):
    return AgentFinding(
        finding_id=finding_id, explanation=claim, cwe_id="CWE-89", evidence=evidence,
        severity="critical", provenance_confidence=0.8734,
        judged=True, supported=True,
    ).model_dump(exclude={"raw_response"})


def _record_run(run_dir: Path, case_id: str, case: dict, findings: list[dict]) -> None:
    run_dir.mkdir(exist_ok=True)
    record = {
        "id": case_id, "base_sha": case["base_sha"], "pr_sha": case["pr_sha"],
        "findings": findings,
    }
    (run_dir / f"{case_id}.json").write_text(json.dumps(record), encoding="utf-8")


@pytest.fixture(scope="module")
def ce():
    return _load("jt_citation_export", BENCH / "citation_export.py")


def _export(ce, run_dir: Path, case_id: str, case: dict, tmp_path: Path) -> list[dict]:
    out = tmp_path / "export.json"
    ce.export_run(run_dir, {case_id: case["repo"]}, out)
    return json.loads(out.read_text(encoding="utf-8"))["units"]


JUDGE_OUTPUT_KEYS = {
    "verdict", "severity", "provenance_confidence", "judged", "supported",
    "not_judged_reason", "unsupported_reason",
}


class TestCitationExport:
    def _run(self, tmp_path, evidence_sets):
        case = _case_repo(tmp_path)
        findings = [
            _recorded_finding(f"F{i}", f"claim {i}", evidence)
            for i, evidence in enumerate(evidence_sets)
        ]
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", case, findings)
        return run_dir, case

    def test_every_citation_is_one_unit_with_claim_location_and_code_at_its_snapshot(
        self, ce, tmp_path
    ):
        run_dir, case = self._run(tmp_path, [
            [
                EvidenceItem(file="app.py", lines=[2, 3], content="agent invented", snapshot="pr"),
                EvidenceItem(file="app.py", lines=[2, 3], content="agent invented", snapshot="base"),
            ],
            [EvidenceItem(file="app.py", lines=[4, 4], content="x", snapshot="pr")],
        ])

        units = _export(ce, run_dir, "case_a", case, tmp_path)

        assert len(units) == 3
        assert len({u["unit_id"] for u in units}) == 3
        by_claim = {}
        for unit in units:
            by_claim.setdefault(unit["claim"], []).append(unit)
        assert set(by_claim) == {"claim 0", "claim 1"}
        pr_unit, base_unit = by_claim["claim 0"]
        assert (pr_unit["file"], pr_unit["lines"], pr_unit["snapshot"]) == ("app.py", [2, 3], "pr")
        assert pr_unit["code"].splitlines() == ["pr2", "pr3"]
        assert (base_unit["snapshot"], base_unit["code"].splitlines()) == ("base", ["base2", "base3"])
        assert by_claim["claim 1"][0]["code"].splitlines() == ["line4"]
        assert not any(u.get("unreadable") for u in units)

    def test_export_carries_no_judge_output(self, ce, tmp_path):
        run_dir, case = self._run(tmp_path, [
            [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr")],
        ])
        out = tmp_path / "export.json"

        ce.export_run(run_dir, {"case_a": case["repo"]}, out)

        text = out.read_text(encoding="utf-8")
        units = json.loads(text)["units"]
        assert all(JUDGE_OUTPUT_KEYS.isdisjoint(unit) for unit in units)
        assert "0.8734" not in text and "critical" not in text

    def test_unit_ids_are_stable_across_exports(self, ce, tmp_path):
        run_dir, case = self._run(tmp_path, [
            [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr")],
            [EvidenceItem(file="app.py", lines=[1, 1], content="c", snapshot="base")],
        ])

        first = _export(ce, run_dir, "case_a", case, tmp_path)
        second = _export(ce, run_dir, "case_a", case, tmp_path)

        assert [u["unit_id"] for u in first] == [u["unit_id"] for u in second]

    @pytest.mark.parametrize(
        "item",
        [
            EvidenceItem(file="missing.py", lines=[1, 2], content="c", snapshot="pr"),
            EvidenceItem(file="app.py", lines=[50, 60], content="c", snapshot="pr"),
        ],
        ids=["file-missing", "lines-out-of-range"],
    )
    def test_unreadable_location_keeps_the_unit_with_an_unreadable_marker(
        self, ce, tmp_path, item
    ):
        run_dir, case = self._run(tmp_path, [
            [item],
            [EvidenceItem(file="app.py", lines=[1, 1], content="c", snapshot="pr")],
        ])

        units = _export(ce, run_dir, "case_a", case, tmp_path)

        assert len(units) == 2
        broken = next(u for u in units if u["claim"] == "claim 0")
        assert broken["unreadable"] is True
        assert not broken.get("code")
        assert (broken["file"], broken["snapshot"]) == (item.file, "pr")
        intact = next(u for u in units if u["claim"] == "claim 1")
        assert intact["code"].splitlines() == ["line1"]
        assert not intact.get("unreadable")

    def test_unreadable_snapshot_blob_keeps_the_unit_with_an_unreadable_marker(
        self, ce, tmp_path
    ):
        run_dir, case = self._run(tmp_path, [
            [EvidenceItem(file="app.py", lines=[1, 1], content="c", snapshot="pr")],
        ])
        record_path = run_dir / "case_a.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["pr_sha"] = "0" * 40
        record_path.write_text(json.dumps(record), encoding="utf-8")

        units = _export(ce, run_dir, "case_a", case, tmp_path)

        assert len(units) == 1
        assert units[0]["unreadable"] is True
        assert not units[0].get("code")


PATCH = BENCH / "cases" / "authz" / "case_01_vulnerable.patch"
ORDERS = "app/routes/orders.py"
SNAPSHOT_KEYS = {"base": "base_sha", "pr": "pr_sha"}


def _build_synthetic_case(ev, monkeypatch, root: Path, name: str, commit_date: str) -> dict:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")
    monkeypatch.setenv("GIT_AUTHOR_DATE", commit_date)
    monkeypatch.setenv("GIT_COMMITTER_DATE", commit_date)
    repo = root / name
    repo.mkdir()
    ev.build_case_repo(repo, PATCH)
    return {
        "repo": repo,
        "base_sha": _git(repo, "rev-parse", "main"),
        "pr_sha": _git(repo, "rev-parse", "pr"),
    }


def _code_at(repo: Path, sha: str, path: str, first: int, last: int) -> list[str]:
    return _git(repo, "show", f"{sha}:{path}").splitlines()[first - 1 : last]


class TestCitationExportFromRebuiltOrChangedRepos:
    def test_run_recorded_against_one_synthetic_build_reads_its_code_from_a_rebuild(
        self, ce, ev, monkeypatch, tmp_path
    ):
        build_1 = _build_synthetic_case(ev, monkeypatch, tmp_path, "build1", "2020-01-01T00:00:00+0000")
        build_2 = _build_synthetic_case(ev, monkeypatch, tmp_path, "build2", "2021-06-01T00:00:00+0000")
        assert build_1["pr_sha"] != build_2["pr_sha"]
        assert build_1["base_sha"] != build_2["base_sha"]
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", build_1, [_recorded_finding("F0", "claim", [
            EvidenceItem(file=ORDERS, lines=[57, 58], content="c", snapshot="pr"),
            EvidenceItem(file=ORDERS, lines=[54, 55], content="c", snapshot="base"),
        ])])

        units = _export(ce, run_dir, "case_a", build_2, tmp_path)

        pr_unit, base_unit = units
        assert not any(u.get("unreadable") for u in units)
        expected_pr = _code_at(build_1["repo"], build_1["pr_sha"], ORDERS, 57, 58)
        expected_base = _code_at(build_1["repo"], build_1["base_sha"], ORDERS, 54, 55)
        assert len(expected_pr) == len(expected_base) == 2
        assert pr_unit["code"].splitlines() == expected_pr
        assert base_unit["code"].splitlines() == expected_base

    def test_recorded_sha_present_in_the_repo_is_read_as_recorded(self, ce, tmp_path):
        case = _case_repo(tmp_path)
        _git(case["repo"], "checkout", "-q", "pr")
        (case["repo"] / "app.py").write_text("later1\nlater2\nline3\n", encoding="utf-8")
        _git(case["repo"], "commit", "-q", "-am", "later")
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", case, [_recorded_finding("F0", "claim", [
            EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr"),
        ])])

        units = _export(ce, run_dir, "case_a", case, tmp_path)

        assert units[0]["code"].splitlines() == ["pr2", "pr3"]
        assert not units[0].get("unreadable")

    @pytest.mark.parametrize("snapshot,branch", [("base", "main"), ("pr", "pr")])
    def test_absent_sha_without_matching_rebuilt_commits_is_unreadable(
        self, ce, tmp_path, snapshot, branch
    ):
        case = _case_repo(tmp_path)
        _git(case["repo"], "checkout", "-q", branch)
        _git(case["repo"], "commit", "-q", "--amend", "-m", "unrelated")
        _git(case["repo"], "checkout", "-q", "main")
        absent = {**case, SNAPSHOT_KEYS[snapshot]: "deadbeef" * 5}
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", absent, [_recorded_finding("F0", "claim", [
            EvidenceItem(file="app.py", lines=[1, 1], content="c", snapshot=snapshot),
        ])])

        units = _export(ce, run_dir, "case_a", case, tmp_path)

        assert units[0]["unreadable"] is True
        assert not units[0].get("code")

    @pytest.mark.parametrize("snapshot,key", [("pr", "pr_sha"), ("base", "base_sha")])
    def test_recorded_sha_shaped_like_a_git_option_is_unreadable_and_git_is_not_run(
        self, ce, monkeypatch, tmp_path, snapshot, key
    ):
        case = _case_repo(tmp_path)
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", {**case, key: "--output=x"}, [_recorded_finding("F0", "claim", [
            EvidenceItem(file="app.py", lines=[1, 1], content="c", snapshot=snapshot),
        ])])

        def no_git(*args, **kwargs):
            raise AssertionError(f"git was run: {args}")

        monkeypatch.setattr(ce.subprocess, "run", no_git)
        units = _export(ce, run_dir, "case_a", case, tmp_path)

        assert units[0]["unreadable"] is True
        assert not (tmp_path / "x").exists() and not (case["repo"] / "x").exists()


class TestRunDirectoryToReport:
    def test_report_populations_and_outcome_ids_follow_the_exported_units(self, ce, je, tmp_path):
        case = _case_repo(tmp_path)
        evidence = [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr")]
        vulnerable = _recorded_finding("F0", "judged vulnerable", evidence)
        safe = {**_recorded_finding("F1", "judged safe", evidence), "supported": False}
        not_judged = {
            **_recorded_finding("F2", "not judged", evidence),
            "judged": False, "supported": None, "not_judged_reason": "judge-failed",
            "provenance_confidence": None,
        }
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", case, [vulnerable, safe, not_judged])
        record_path = run_dir / "case_a.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record.update(mode="lgtm", category="authz", expected="vulnerable")
        record_path.write_text(json.dumps(record), encoding="utf-8")
        export_path = tmp_path / "export.json"
        exported = ce.export_run(run_dir, {"case_a": case["repo"]}, export_path)
        ids = [u["unit_id"] for u in exported]
        assert len(ids) == 3
        by_claim = {u["claim"]: u["unit_id"] for u in exported}
        labels_path = tmp_path / "labels.json"
        labels_path.write_text(json.dumps({"units": {
            by_claim["judged vulnerable"]: {"supports": "yes"},
            by_claim["judged safe"]: {"supports": "no"},
            by_claim["not judged"]: {"supports": "yes"},
        }}), encoding="utf-8")

        result = je.report(run_dir, export_path, labels_path)

        assert [o["unit_id"] for o in je.run_outcomes(run_dir)] == ids
        assert result["citation_support"]["before_judging"]["n"] == 3
        judged = result["citation_support"]["judged"]
        assert judged["n"] == 1
        assert judged["percent_yes"] == 100
        assert result["supported_agreement"]["n"] == 2
        assert result["supported_agreement"]["agree"] == 2
        assert result["supported_agreement"]["not_judged"] == 1
        assert result["not_judged_by_reason"] == {"judge-failed": 1}
        assert (result["case_accuracy"]["n"], result["case_accuracy"]["excluded"]) == (0, 1)
        assert "severity_agreement" not in result

"""Unit tests for judge evaluation: citation correctness, judge-quality measures, corrupted
citations, fallback and latency, and not-judged case exclusion in the three harnesses."""

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


def _outcome(unit_id, judged=True, verdict="vulnerable", severity="high", confidence=0.5):
    return {
        "unit_id": unit_id, "judged": judged,
        "verdict": verdict if judged else "",
        "severity": severity if judged and verdict in ("vulnerable", "possible") else "",
        "provenance_confidence": confidence if judged else None,
    }


def _labels(**units):
    """_labels(u1="correct", u2=("incorrect", "high")) -> labels file content."""
    entries = {}
    for unit_id, spec in units.items():
        label, severity = spec if isinstance(spec, tuple) else (spec, None)
        entries[unit_id] = {"citation": label, **({"severity": severity} if severity else {})}
    return {"units": entries}


class TestCitationCorrectness:
    UNITS = ["u1", "u2", "u3", "u4", "u5"]

    def _report(self, je, labels, outcomes):
        return je.citation_correctness(self.UNITS, labels, outcomes)

    def test_percent_correct_with_n_and_unlabelled_for_both_populations(self, je):
        labels = _labels(u1="correct", u2="correct", u3="incorrect", u4="incorrect")
        outcomes = [
            _outcome("u1", verdict="vulnerable"),
            _outcome("u2", verdict="possible"),
            _outcome("u3", verdict="safe"),
            _outcome("u4", judged=False),
            _outcome("u5", verdict="vulnerable"),
        ]

        report = self._report(je, labels, outcomes)

        before = report["before_judging"]
        assert (before["n"], before["unlabelled"]) == (4, 1)
        assert before["percent_correct"] == pytest.approx(50.0)
        judged = report["judged"]
        assert (judged["n"], judged["unlabelled"]) == (2, 1)
        assert judged["percent_correct"] == pytest.approx(100.0)

    def test_judged_population_counts_only_vulnerable_or_possible_judged_units(self, je):
        labels = _labels(u1="correct", u2="incorrect", u3="correct", u4="correct", u5="incorrect")
        outcomes = [
            _outcome("u1", verdict="vulnerable"),
            _outcome("u2", verdict="possible"),
            _outcome("u3", verdict="safe"),
            _outcome("u4", verdict="insufficient_evidence"),
            {**_outcome("u5", judged=False), "verdict": "vulnerable"},
        ]

        report = self._report(je, labels, outcomes)

        assert report["judged"]["n"] == 2
        assert report["judged"]["percent_correct"] == pytest.approx(50.0)
        assert report["before_judging"]["n"] == 5

    def test_unlabelled_units_are_counted_and_do_not_fail_the_report(self, je):
        report = self._report(je, _labels(u1="correct"), [_outcome(u) for u in self.UNITS])

        assert report["before_judging"]["n"] == 1
        assert report["before_judging"]["unlabelled"] == 4
        assert report["before_judging"]["percent_correct"] == pytest.approx(100.0)

    def test_population_without_labelled_units_reports_no_percentage(self, je):
        report = self._report(je, _labels(), [_outcome(u) for u in self.UNITS])

        assert report["judged"]["n"] == 0
        assert report["judged"]["unlabelled"] == 5
        assert report["judged"]["percent_correct"] is None

    @pytest.mark.parametrize(
        "labels,offender",
        [
            (_labels(u1="correct", ghost="correct"), "ghost"),
            ({"units": {"u1": {"citation": "maybe"}}}, "u1"),
            ({"units": {"u1": {"citation": "Correct"}}}, "u1"),
            ({"units": {"u1": {"citation": None}}}, "u1"),
        ],
    )
    def test_labels_file_with_unknown_id_or_bad_label_stops_naming_the_entry(
        self, je, labels, offender
    ):
        with pytest.raises(ValueError) as exc:
            self._report(je, labels, [_outcome("u1")])

        assert offender in str(exc.value)

    def test_both_populations_come_from_one_export_and_one_labels_file(self, je):
        labels = _labels(u1="correct", u2="incorrect", u3="correct")
        outcomes = [_outcome("u1"), _outcome("u2", verdict="safe"), _outcome("u3", judged=False)]

        report = self._report(je, labels, outcomes)

        assert report["judged"]["n"] + report["judged"]["unlabelled"] <= (
            report["before_judging"]["n"] + report["before_judging"]["unlabelled"]
        )
        assert report["before_judging"]["n"] + report["before_judging"]["unlabelled"] == len(self.UNITS)


class TestConfidenceAgreement:
    def test_mean_confidence_for_correct_and_incorrect_units_with_n(self, je):
        labels = _labels(
            u1="correct", u2="correct", u3="incorrect", u4="incorrect", u5="incorrect",
            u6="correct", u7="incorrect",
        )
        outcomes = [
            _outcome("u1", confidence=0.9),
            _outcome("u2", verdict="possible", confidence=0.7),
            _outcome("u3", confidence=0.2),
            _outcome("u4", confidence=0.4),
            _outcome("u5", judged=False),
            _outcome("u6", verdict="safe", confidence=0.8),
            _outcome("u7", verdict="insufficient_evidence", confidence=0.6),
        ]

        result = je.confidence_agreement(labels, outcomes)

        assert result["correct"]["n"] == 3
        assert result["correct"]["mean"] == pytest.approx(0.8)
        assert result["incorrect"]["n"] == 3
        assert result["incorrect"]["mean"] == pytest.approx(0.4)

    def test_unlabelled_units_do_not_enter_either_mean(self, je):
        outcomes = [_outcome("u1", confidence=0.9), _outcome("u2", confidence=0.1)]

        result = je.confidence_agreement(_labels(u1="correct"), outcomes)

        assert result["correct"] == {"mean": pytest.approx(0.9), "n": 1}
        assert result["incorrect"]["n"] == 0
        assert result["incorrect"]["mean"] is None


def _case(cid, expected, findings, category="authz"):
    return {"id": cid, "category": category, "expected": expected, "findings": findings}


def _jf(judge_verdict, verdict=None, category="authz"):
    return {
        "category": category, "judged": True, "judge_verdict": judge_verdict,
        "verdict": judge_verdict if verdict is None else verdict, "evidence_valid": True,
    }


class TestVerdictAccuracy:
    def test_accuracy_scores_the_judge_answer_before_the_pr_grounding_cap(self, je):
        cases = [
            _case("a", "vulnerable", [_jf("vulnerable", verdict="possible")]),
            _case("b", "safe", [_jf("safe")]),
            _case("c", "vulnerable", [_jf("safe")]),
            _case("d", "safe", [_jf("vulnerable", verdict="possible")]),
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["correct"]) == (4, 2)
        assert result["accuracy"] == pytest.approx(0.5)

    def test_case_without_expected_verdict_is_unlabelled_and_excluded_from_this_measure_only(self, je):
        cases = [
            _case("a", "vulnerable", [_jf("vulnerable")]),
            _case("b", None, [_jf("vulnerable")]),
            _case("c", "", [_jf("safe")]),
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["unlabelled"]) == (1, 2)
        assert result["accuracy"] == pytest.approx(1.0)

    @staticmethod
    def _not_judged_finding():
        return {"category": "authz", "judged": False, "judge_verdict": "", "verdict": "vulnerable"}

    def test_error_and_not_judged_cases_in_a_judged_mode_are_excluded_not_scored(self, je):
        cases = [
            {**_case("c_ok", "vulnerable", [_jf("vulnerable")]), "mode": "lgtm"},
            {
                **_case("c_nj", "vulnerable", [_jf("vulnerable"), self._not_judged_finding()]),
                "mode": "lgtm",
            },
            {**_case("c_err", "vulnerable", [_jf("vulnerable")]), "mode": "lgtm", "error": "boom"},
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["excluded"]) == (1, 2)
        assert result["correct"] == 1

    @pytest.mark.parametrize("mode", ["llm-only", "sast-only"])
    def test_not_judged_case_outside_judged_modes_is_still_scored(self, je, mode):
        cases = [
            {
                **_case("c_nj", "vulnerable", [_jf("vulnerable"), self._not_judged_finding()]),
                "mode": mode,
            }
        ]

        result = je.verdict_accuracy(cases)

        assert (result["n"], result["excluded"]) == (1, 0)


class TestSeverityAgreement:
    def test_exact_agreement_with_n_over_judged_units_with_a_severity_label(self, je):
        labels = _labels(
            u1=("correct", "high"), u2=("correct", "medium"), u3=("correct", "low"),
        )
        outcomes = [
            _outcome("u1", severity="high"),
            _outcome("u2", severity="high"),
            _outcome("u3", severity="low", verdict="possible"),
        ]

        result = je.severity_agreement(labels, outcomes)

        assert (result["n"], result["agree"]) == (3, 2)
        assert result["agreement"] == pytest.approx(2 / 3)

    def test_correct_unit_without_severity_label_is_unlabelled_and_excluded_from_this_measure_only(self, je):
        labels = _labels(u1=("correct", "high"), u2="correct", u3="incorrect")
        outcomes = [_outcome("u1", severity="high"), _outcome("u2"), _outcome("u3")]

        severity = je.severity_agreement(labels, outcomes)
        citation = je.citation_correctness(["u1", "u2", "u3"], labels, outcomes)

        assert (severity["n"], severity["unlabelled"]) == (1, 1)
        assert severity["agreement"] == pytest.approx(1.0)
        assert citation["before_judging"]["n"] == 3
        assert citation["before_judging"]["unlabelled"] == 0

    def test_judged_unit_with_no_severity_is_not_compared(self, je):
        labels = _labels(u1=("correct", "high"), u2=("correct", "low"))
        outcomes = [_outcome("u1", severity="high"), _outcome("u2", verdict="safe")]

        result = je.severity_agreement(labels, outcomes)

        assert result["n"] == 1


class TestCorruptedCitations:
    ITEM = {"file": "app/orders.py", "lines": [10, 12], "content": "ORIGINAL_SNIPPET", "snapshot": "pr"}
    DONOR = {"file": "app/users.py", "lines": [3, 4], "content": "DONOR_SNIPPET", "snapshot": "base"}

    def _copies(self, je):
        return je.corrupt_citation(dict(self.ITEM), dict(self.DONOR), "app/other.py")

    def test_one_known_incorrect_copy_per_corruption_type(self, je):
        copies = self._copies(je)

        assert sorted(c["corruption"] for c in copies) == [
            "flipped_snapshot", "other_file", "shifted_lines", "swapped_snippet",
        ]
        assert all(c["known_incorrect"] is True for c in copies)

    def test_each_copy_changes_only_its_own_field(self, je):
        by_type = {c["corruption"]: c for c in self._copies(je)}

        assert by_type["shifted_lines"]["lines"] != self.ITEM["lines"]
        assert by_type["shifted_lines"]["file"] == self.ITEM["file"]
        assert by_type["shifted_lines"]["snapshot"] == self.ITEM["snapshot"]
        assert by_type["other_file"]["file"] == "app/other.py"
        assert by_type["other_file"]["lines"] == self.ITEM["lines"]
        assert by_type["swapped_snippet"]["content"] == "DONOR_SNIPPET"
        assert by_type["swapped_snippet"]["file"] == self.ITEM["file"]
        assert by_type["flipped_snapshot"]["snapshot"] == "base"
        assert by_type["flipped_snapshot"]["content"] == self.ITEM["content"]

    def test_original_citation_is_not_modified(self, je):
        item = dict(self.ITEM)

        je.corrupt_citation(item, dict(self.DONOR), "app/other.py")

        assert item == self.ITEM

    def test_report_states_original_and_corrupted_confidence_per_corruption_type(self, je):
        pairs = [
            {"corruption": "shifted_lines", "original": 0.9, "corrupted": 0.5},
            {"corruption": "shifted_lines", "original": 0.7, "corrupted": 0.3},
            {"corruption": "other_file", "original": 0.8, "corrupted": 0.1},
            {"corruption": "other_file", "original": 0.6, "corrupted": None},
        ]

        report = je.corruption_report(pairs)

        assert report["shifted_lines"]["n"] == 2
        assert report["shifted_lines"]["original_mean"] == pytest.approx(0.8)
        assert report["shifted_lines"]["corrupted_mean"] == pytest.approx(0.4)
        assert report["other_file"]["n"] == 1
        assert report["other_file"]["original_mean"] == pytest.approx(0.8)
        assert report["other_file"]["corrupted_mean"] == pytest.approx(0.1)


class TestCorruptedCitationsThroughTheJudge:
    LOCATIONS = {("app/orders.py", (10, 12), "pr"), ("app/users.py", (3, 4), "pr")}

    @staticmethod
    def _grounded(fid, file, lines):
        return AgentFinding(
            finding_id=fid, cwe_id="CWE-89", explanation="claim", category="sqli", agent="authz",
            file=file, line=lines[0], pr_graph_ok=True, evidence_valid=True,
            evidence=[EvidenceItem(type="code", file=file, lines=list(lines), snapshot="pr",
                                   content=f"SNIPPET_{fid}", grounded_in_pr=True)],
        )

    def _read_code(self, item):
        known = (item.file, tuple(item.lines or ()), item.snapshot) in self.LOCATIONS
        return "GOOD_CODE" if known else "BAD_CODE"

    @staticmethod
    def _judge(request):
        confidence = 0.9 if "GOOD_CODE" in request["state"] else 0.2
        return {"verdict": "possible", "severity": "low", "provenance_confidence": confidence}

    def test_originals_and_corrupted_copies_are_judged_and_confidence_is_reported_per_type(self, je):
        candidates = [
            self._grounded("a", "app/orders.py", (10, 12)),
            self._grounded("b", "app/users.py", (3, 4)),
        ]

        pairs = je.measure_corruptions(
            candidates, self._read_code, LGTMConfig(), self._judge, other_file="app/other.py")
        report = je.corruption_report(pairs)

        assert set(report) == {"shifted_lines", "other_file", "swapped_snippet", "flipped_snapshot"}
        for corruption, row in report.items():
            assert row["n"] == 2, corruption
            assert row["original_mean"] == pytest.approx(0.9), corruption
        for corruption in ("shifted_lines", "other_file", "flipped_snapshot"):
            assert report[corruption]["corrupted_mean"] == pytest.approx(0.2), corruption

    def test_candidate_the_judge_fails_on_is_left_out_of_the_report_and_the_run_completes(self, je):
        candidates = [self._grounded("a", "app/orders.py", (10, 12))]

        def failing(request):
            raise ConnectionError("unreachable")

        pairs = je.measure_corruptions(
            candidates, self._read_code, LGTMConfig(), failing, other_file="app/other.py")

        assert all(row["n"] == 0 for row in je.corruption_report(pairs).values())

    def test_candidates_passed_in_are_not_modified(self, je):
        candidate = self._grounded("a", "app/orders.py", (10, 12))
        before = candidate.model_dump()

        je.measure_corruptions(
            [candidate], self._read_code, LGTMConfig(), self._judge, other_file="app/other.py")

        assert candidate.model_dump() == before


class _Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def _candidate(fid):
    return AgentFinding(
        finding_id=fid, cwe_id="CWE-89", explanation="claim", category="sqli", agent="authz",
        file="app.py", line=1, pr_graph_ok=True, evidence_valid=True,
        evidence=[EvidenceItem(type="code", file="app.py", lines=[1, 2], snapshot="pr",
                               content="x", grounded_in_pr=True)],
    )


GOOD = {"verdict": "vulnerable", "severity": "high", "provenance_confidence": 0.8}


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
            (1, {"verdict": "banana"}),
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

    @pytest.mark.parametrize("mode", ["sast-only", "llm-only"])
    def test_fallback_rate_is_not_reported_for_modes_without_a_judge(self, je, mode):
        records = [
            {"judged": False, "latency_seconds": None},
            {"judged": False, "latency_seconds": None},
        ]

        assert je.run_measures(records, mode)["fallback_rate"] is None


def _finding(judged=True, verdict="vulnerable", category="authz"):
    return {
        "finding_id": "authz:1", "category": category, "verdict": verdict,
        "judged": judged, "evidence_valid": True, "explanation": "claim",
    }


def _not_judged(category="authz"):
    """Candidate the judge failed on: no verdict."""
    return _finding(judged=False, verdict="", category=category)


def _row(cid, expected, findings, mode="lgtm", category="authz"):
    return {
        "id": cid, "category": category, "split": "dev", "expected": expected, "mode": mode,
        "n_findings": len(findings), "verdicts": [f["verdict"] for f in findings],
        "grounded": len(findings), "grounding_rate": 1.0, "latency_seconds": 1.0,
        "est_tokens": 10, "findings": findings,
    }


def _scored_rows(ev, mode):
    return [
        ev.score_case(_row("a", "vulnerable", [_finding()], mode)),
        ev.score_case(_row(
            "b", "vulnerable",
            [_not_judged(), _not_judged(), _finding(verdict="safe")], mode)),
        ev.score_case(_row("c", "safe", [_finding(verdict="safe")], mode)),
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
            ev.score_case(_row("c", "safe", [_finding(verdict="safe")], mode)),
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
            inj, monkeypatch, tmp_path, "lgtm", [_finding(verdict="safe", category="sqli")])

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
        verdict="possible", severity="critical", provenance_confidence=0.8734,
        judged=True, judge_verdict="vulnerable",
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
    "verdict", "severity", "provenance_confidence", "judged", "judge_verdict",
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
        safe = {**_recorded_finding("F1", "judged safe", evidence), "verdict": "safe", "judge_verdict": "safe"}
        not_judged = {
            **_recorded_finding("F2", "not judged", evidence),
            "judged": False, "verdict": "", "judge_verdict": "", "severity": "",
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
            by_claim["judged vulnerable"]: {"citation": "correct"},
            by_claim["judged safe"]: {"citation": "incorrect"},
            by_claim["not judged"]: {"citation": "correct"},
        }}), encoding="utf-8")

        result = je.report(run_dir, export_path, labels_path)

        assert [o["unit_id"] for o in je.run_outcomes(run_dir)] == ids
        assert result["citation_correctness"]["before_judging"]["n"] == 3
        judged = result["citation_correctness"]["judged"]
        assert judged["n"] == 1
        assert judged["percent_correct"] == 100

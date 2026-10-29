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


def _reply(supported=True, confidence=0.8, verdict=None, severity=None, input_tokens=1000):
    """Flat mapping http_judge returns, answering all four questions."""
    return {
        "supported": "yes" if supported else "no",
        "verdict": verdict or ("real" if supported else "not_real"),
        "severity": severity or ("high" if supported else "low"),
        "provenance_confidence": confidence,
        "input_tokens": input_tokens,
    }


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

    SHOPLY = ["sqli_01/0.0", "sqli_01/0.1", "sqli_02_safe/0.0"]
    REAL = ["owner__repo-1/0.0", "owner__repo-2/1.0"]

    @staticmethod
    def _mixed(shoply_yes=("sqli_01/0.0", "sqli_02_safe/0.0"), **extra):
        units = {}
        for uid, supports in [
            ("sqli_01/0.0", "yes"), ("sqli_01/0.1", "no"), ("sqli_02_safe/0.0", "yes"),
        ]:
            units[uid] = {"supports": supports, "origin": "shoply"}
        for uid, supports in [("owner__repo-1/0.0", "no"), ("owner__repo-2/1.0", "no")]:
            units[uid] = {"supports": supports, "origin": "real_world"}
        units.update(extra)
        return {"units": units}

    def test_mixed_origin_labels_score_a_shoply_export_on_shoply_units_only(self, je):
        outcomes = [_outcome(u) for u in self.SHOPLY]

        report = je.citation_support(self.SHOPLY, self._mixed(), outcomes)

        assert report["before_judging"] == {"n": 3, "unlabelled": 0, "percent_yes": pytest.approx(200 / 3)}
        assert report["judged"]["n"] == 3
        assert report["judged"]["percent_yes"] == pytest.approx(200 / 3)

    def test_mixed_origin_labels_score_a_real_world_export_on_real_world_units_only(self, je):
        outcomes = [_outcome(u) for u in self.REAL]

        report = je.citation_support(self.REAL, self._mixed(), outcomes)

        assert report["before_judging"] == {"n": 2, "unlabelled": 0, "percent_yes": 0.0}
        assert report["judged"]["n"] == 2

    def test_mixed_origin_labels_still_reject_an_own_origin_unit_missing_from_the_export(self, je):
        labels = self._mixed(**{"sqli_99/0.0": {"supports": "yes", "origin": "shoply"}})

        with pytest.raises(ValueError) as exc:
            je.citation_support(self.SHOPLY, labels, [_outcome(u) for u in self.SHOPLY])

        assert "sqli_99/0.0" in str(exc.value)

    def test_mixed_origin_labels_still_reject_a_missing_real_world_unit_for_a_real_world_export(self, je):
        labels = self._mixed(**{"owner__repo-9/0.0": {"supports": "no", "origin": "real_world"}})

        with pytest.raises(ValueError) as exc:
            je.citation_support(self.REAL, labels, [_outcome(u) for u in self.REAL])

        assert "owner__repo-9/0.0" in str(exc.value)

    @pytest.mark.parametrize("bad", ["maybe", "Yes", None, True])
    def test_mixed_origin_labels_still_reject_a_bad_supports_value_on_any_unit(self, je, bad):
        labels = self._mixed()
        labels["units"]["sqli_01/0.1"]["supports"] = bad

        with pytest.raises(ValueError) as exc:
            je.citation_support(self.SHOPLY, labels, [_outcome(u) for u in self.SHOPLY])

        assert "sqli_01/0.1" in str(exc.value)

    def test_mixed_origin_labels_reject_a_bad_supports_value_on_an_other_origin_unit(self, je):
        labels = self._mixed()
        labels["units"]["owner__repo-1/0.0"]["supports"] = "maybe"

        with pytest.raises(ValueError) as exc:
            je.citation_support(self.SHOPLY, labels, [_outcome(u) for u in self.SHOPLY])

        assert "owner__repo-1/0.0" in str(exc.value)

    def test_single_origin_labels_file_still_rejects_a_unit_missing_from_the_export(self, je):
        labels = {"units": {
            "sqli_01/0.0": {"supports": "yes", "origin": "shoply"},
            "sqli_77/0.0": {"supports": "yes", "origin": "shoply"},
        }}

        with pytest.raises(ValueError) as exc:
            je.citation_support(self.SHOPLY, labels, [_outcome(u) for u in self.SHOPLY])

        assert "sqli_77/0.0" in str(exc.value)

    def test_single_origin_labels_file_scores_the_export_as_before(self, je):
        labels = {"units": {u: {"supports": s, "origin": "shoply"}
                            for u, s in zip(self.SHOPLY, ["yes", "no", "no"])}}

        report = je.citation_support(self.SHOPLY, labels, [_outcome(u) for u in self.SHOPLY])

        assert report["before_judging"]["n"] == 3
        assert report["before_judging"]["percent_yes"] == pytest.approx(100 / 3)

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

    @pytest.mark.parametrize("mode", ["llm-only"])
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
        return _reply(supported, 0.9 if supported else 0.2)

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

    def test_report_states_per_perturbation_how_the_kev_verdict_moved(self, je):
        report = je.perturbation_report(self._measure(je, self._candidates()))

        for name, row in report.items():
            assert row["verdict_shift"] == {"real->not_real": 2, "not_real->not_real": 1}, name

    def test_verdict_the_judge_keeps_shows_no_shift_to_not_real(self, je):
        def credulous(request):
            return _reply(True, 0.9)

        report = je.perturbation_report(self._measure(je, self._candidates(), judge=credulous))

        for name, row in report.items():
            assert row["verdict_shift"] == {"real->real": 3}, name

    def test_every_perturbed_request_cites_code_that_resolves_and_only_support_is_changed(self, je):
        known = {"a.py", "b.py", "c.py"}

        def read_code(item):
            return f"CODE_OF_{item.file}" if item.file in known and 1 <= item.lines[0] <= item.lines[-1] <= 5 else ""

        states = []

        def judge(request):
            states.append(request["state"])
            return _reply(True, 0.9)

        measured = je.measure_perturbations(
            self._candidates(), read_code, LGTMConfig(), judge,
            unrelated_code=self._unrelated, safe_twin_code=self._safe_twin,
        )

        assert {r["perturbation"] for r in measured["records"]} == {
            "unrelated_code", "mutated_claim", "safe_twin_code"}
        assert len(states) == 3 + 9
        for state in states:
            lines = state.splitlines()
            unresolved = [
                line for i, line in enumerate(lines)
                if line.startswith("Cited item:")
                and (i + 1 == len(lines) or lines[i + 1].startswith("Cited item:"))
            ]
            assert unresolved == [], state

    def test_perturbation_the_judge_still_supports_shows_no_drop(self, je):
        def credulous(request):
            return _reply(True, 0.9)

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


GOOD = _reply()


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
        measures = je.run_measures(records, "lgtm")

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

    @pytest.mark.parametrize("mode", ["llm-only"])
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
    @pytest.mark.parametrize("mode", ["lgtm"])
    def test_case_with_a_not_judged_candidate_is_excluded_and_listed_with_its_count(self, ev, mode):
        summary = ev.summarize(_scored_rows(ev, mode))

        overall = summary["overall"]
        assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (1, 0, 0, 1)
        assert overall["scored"] == 2
        assert overall["accuracy"] == 1.0
        assert summary["not_judged_cases"] == [{"id": "b", "not_judged": 2}]

    @pytest.mark.parametrize("mode", ["lgtm"])
    def test_cases_whose_candidates_were_all_judged_are_scored_and_not_listed(self, ev, mode):
        rows = [
            ev.score_case(_row("a", "vulnerable", [_finding()], mode)),
            ev.score_case(_row("c", "safe", [_finding(supported=False)], mode)),
        ]

        summary = ev.summarize(rows)

        assert summary["overall"]["scored"] == 2
        assert summary.get("not_judged_cases", []) == []

    @pytest.mark.parametrize("mode", ["llm-only"])
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
        return er.write_dir_summary(out, mode, {r["id"] for r in rows}, "m")["summary"]

    def test_judged_mode_excludes_and_lists_the_case_with_a_not_judged_candidate(self, er, ev, tmp_path):
        summary = self._summary(er, ev, tmp_path, "lgtm")

        assert summary["overall"]["scored"] == 2
        assert summary["overall"]["fn"] == 0
        assert summary["not_judged_cases"] == [{"id": "b", "not_judged": 2}]

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_modes_without_a_judge_are_scored_as_before(self, er, ev, tmp_path, mode):
        out = tmp_path / mode
        out.mkdir()
        row = ev.score_case(_row("a", "vulnerable", [_finding(judged=False, verdict="vulnerable")], mode))
        (out / "a.json").write_text(json.dumps(row), encoding="utf-8")

        summary = er.write_dir_summary(out, mode, {"a"}, "m")["summary"]

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


class TestJudgeRecordsPerCase:
    @staticmethod
    def _empty_run(tmp_path):
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", _case_repo(tmp_path), [])
        export_path, labels_path = tmp_path / "export.json", tmp_path / "labels.json"
        export_path.write_text(json.dumps({"units": []}), encoding="utf-8")
        labels_path.write_text(json.dumps({"units": {}}), encoding="utf-8")
        return run_dir, export_path, labels_path

    def test_same_finding_id_in_two_cases_gives_two_records_each_attributable_to_its_case(
        self, je, tmp_path
    ):
        clock = _Clock()
        judge = _scripted_judge(clock, [(1, GOOD), (1, ConnectionError("down"))])
        records = (
            je.measure_judge_run([_candidate("F1")], lambda item: "CODE", LGTMConfig(), judge,
                                 clock=clock, case_id="case_a")
            + je.measure_judge_run([_candidate("F1")], lambda item: "CODE", LGTMConfig(), judge,
                                   clock=clock, case_id="case_b")
        )
        run_dir, export_path, labels_path = self._empty_run(tmp_path)
        records_path = tmp_path / "judge-records.json"
        records_path.write_text(json.dumps(records), encoding="utf-8")

        result = je.report(run_dir, export_path, labels_path, records_path)

        by_case = {r["case_id"]: r for r in json.loads(records_path.read_text(encoding="utf-8"))}
        assert set(by_case) == {"case_a", "case_b"}
        assert (by_case["case_a"]["judged"], by_case["case_b"]["judged"]) == (True, False)
        assert {r["finding_id"] for r in by_case.values()} == {"F1"}
        assert (result["run"]["n"], result["run"]["not_judged"]) == (2, 1)

    def test_records_in_the_old_finding_id_only_form_are_still_read_by_the_report(self, je, tmp_path):
        old_form = [
            {"finding_id": "F1", "judged": True, "latency_seconds": 2.0, "supported": True,
             "provenance_confidence": 0.8, "unsupported_reason": None},
            {"finding_id": "F2", "judged": False, "latency_seconds": 4.0, "supported": None,
             "provenance_confidence": None, "unsupported_reason": None},
        ]
        run_dir, export_path, labels_path = self._empty_run(tmp_path)
        records_path = tmp_path / "judge-records.json"
        records_path.write_text(json.dumps(old_form), encoding="utf-8")

        result = je.report(run_dir, export_path, labels_path, records_path)

        assert (result["run"]["n"], result["run"]["not_judged"]) == (2, 1)
        assert result["run"]["latency_median"] == pytest.approx(3.0)


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


def _kev(verdict="real", severity="high", confidence=0.8, tokens=1000, supported=True, **extra):
    return {
        **_finding(supported=supported), "kev_verdict": verdict, "kev_severity": severity,
        "provenance_confidence": confidence, "input_tokens": tokens, **extra,
    }


def _kev_rows(ev, mode="lgtm"):
    return [
        ev.score_case(_row("a", "vulnerable", [_kev(), _kev("not_real", "low", 0.4, 100, False)], mode)),
        ev.score_case(_row("c", "safe", [_kev("not_real", "low", 0.2, 500, False)], mode)),
    ]


def _without_kev(rows):
    drop = {"kev_verdict", "kev_severity", "input_tokens"}
    return [{**r, "findings": [{k: v for k, v in f.items() if k not in drop} for f in r["findings"]]}
            for r in rows]


class TestKevMetricsInSyntheticSummary:
    def test_summary_reports_verdict_severity_and_provenance_over_judged_candidates(self, ev):
        kev = ev.summarize(_kev_rows(ev))["kev"]

        assert kev["judged"] == 3
        assert kev["verdicts"] == {"real": 1, "not_real": 2}
        assert kev["severities"] == {"high": 1, "low": 2}
        assert kev["provenance_confidence_mean"] == pytest.approx((0.8 + 0.4 + 0.2) / 3)

    def test_not_judged_candidates_are_left_out_of_kev_metrics_and_counted_under_their_reason(self, ev):
        rows = _kev_rows(ev) + [
            ev.score_case(_row("d", "vulnerable", [
                _kev("real", "critical", 0.9, 700),
                {**_not_judged(), "not_judged_reason": "request-too-large"},
                _not_judged(),
            ]))
        ]

        kev = ev.summarize(rows)["kev"]

        assert kev["judged"] == 4
        assert kev["verdicts"] == {"real": 2, "not_real": 2}
        assert kev["severities"] == {"high": 1, "low": 2, "critical": 1}
        assert kev["not_judged"] == {"request-too-large": 1, "judge-failed": 1}

    def test_summary_counts_requests_over_8192_input_tokens_and_skips_unreported_usage(self, ev):
        rows = [ev.score_case(_row("a", "vulnerable", [
            _kev(tokens=8192), _kev(tokens=8193), _kev(tokens=50_000), _kev(tokens=None),
        ]))]

        kev = ev.summarize(rows)["kev"]

        assert kev["requests_over_8192_input_tokens"] == 2

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_runs_without_a_judge_carry_no_kev_metrics(self, ev, mode):
        rows = [
            ev.score_case(_row("a", "vulnerable", [_finding(judged=False, verdict="vulnerable")], mode)),
            ev.score_case(_row("c", "safe", [_finding(judged=False, verdict="safe")], mode)),
        ]

        summary = ev.summarize(rows)

        kev = summary.get("kev", {})
        assert (kev.get("judged", 0), kev.get("verdicts", {}), kev.get("severities", {}),
                kev.get("not_judged", {}), kev.get("requests_over_8192_input_tokens", 0)) == (0, {}, {}, {}, 0)
        assert (summary["overall"]["tp"], summary["overall"]["tn"], summary["overall"]["scored"]) == (1, 1, 2)

    @pytest.mark.parametrize("mode", ["lgtm"])
    def test_existing_scores_and_gating_equal_those_of_the_same_run_without_kev_answers(self, ev, mode):
        with_kev = _kev_rows(ev, mode)
        with_kev[0]["findings"][0]["kev_severity"] = "critical"
        with_kev[1]["findings"][0]["kev_severity"] = "critical"

        rescored = [ev.score_case(dict(r)) for r in with_kev]
        plain = [ev.score_case(dict(r)) for r in _without_kev(with_kev)]

        for a, b in zip(rescored, plain):
            for key in ("predicted", "outcome", "correct", "predicted_grounded", "outcome_grounded",
                        "case_label", "case_label_grounded"):
                assert a[key] == b[key], key
        left = {k: v for k, v in ev.summarize(rescored).items() if k != "kev"}
        right = {k: v for k, v in ev.summarize(plain).items() if k != "kev"}
        assert left == right

    @pytest.mark.parametrize("mode", ["lgtm"])
    def test_supported_candidate_the_kev_verdict_rules_not_real_no_longer_scores_as_detected(self, ev, mode):
        with_kev = _kev_rows(ev, mode)
        with_kev[0]["findings"][0]["kev_verdict"] = "not_real"

        rescored = [ev.score_case(dict(r)) for r in with_kev]
        plain = [ev.score_case(dict(r)) for r in _without_kev(with_kev)]

        assert [r["outcome"] for r in plain] == ["TP", "TN"]
        assert [r["outcome"] for r in rescored] == ["FN", "TN"]
        overall = ev.summarize(rescored)["overall"]
        assert (overall["tp"], overall["fn"], overall["tn"]) == (0, 1, 1)


class TestKevFieldsInSavedResults:
    CASE = {"id": "x", "category": "sqli", "expected_verdict": "vulnerable", "patch_file": "none.patch"}

    @staticmethod
    def _candidate(fid, **kwargs):
        return AgentFinding(
            finding_id=fid, cwe_id="CWE-89", explanation=f"claim {fid}", category="sqli", agent="authz",
            file="app.py", line=1, pr_graph_ok=True, **kwargs,
        )

    def _evaluate(self, ev, monkeypatch, mode, findings):
        class Pipeline:
            def __init__(self, repo, config):
                pass

            def run(self, base, pr, output_dir=None):
                meta = type("Meta", (), {"semgrep_findings_in_diff": 0})()
                return type("Result", (), {"findings": findings, "meta": meta})()

        monkeypatch.setattr(ev, "build_case_repo", lambda *a, **k: None)
        monkeypatch.setattr(ev, "index_repo_docs", lambda *a, **k: None)
        monkeypatch.setattr(ev, "ReviewPipeline", Pipeline)
        return ev.evaluate_case(self.CASE, LGTMConfig(mode=mode))

    def test_judged_candidate_records_kev_verdict_and_severity_and_not_judged_candidate_records_none(
        self, ev, monkeypatch
    ):
        findings = [
            self._candidate("ok", judged=True, supported=True, provenance_confidence=0.7,
                            kev_verdict="real", kev_severity="critical"),
            self._candidate("down", judged=False, not_judged_reason="judge-failed"),
        ]

        saved = {f["finding_id"]: f for f in self._evaluate(ev, monkeypatch, "lgtm", findings)["findings"]}

        assert (saved["ok"]["kev_verdict"], saved["ok"]["kev_severity"]) == ("real", "critical")
        assert saved["ok"]["provenance_confidence"] == 0.7
        assert (saved["down"].get("kev_verdict"), saved["down"].get("kev_severity")) == (None, None)
        assert (saved["down"]["judged"], saved["down"]["not_judged_reason"]) == (False, "judge-failed")

    def test_saved_judged_candidates_record_the_input_tokens_of_their_judge_reply(self, ev, monkeypatch):
        replies = iter([
            {"valid": True, "input_tokens": 1000},
            {"valid": True, "input_tokens": 9000},
            {"valid": False, "input_tokens": 555},
            {"valid": True, "input_tokens": 300},
        ])
        candidates = [
            self._candidate("a1").model_copy(update={"explanation": "claim a"}),
            self._candidate("a2").model_copy(update={"explanation": "claim a"}),
            self._candidate("b"),
            self._candidate("c"),
        ]

        class Pipeline:
            def __init__(self, repo, config):
                self._judge = lambda request: next(replies)

            def run(self, base, pr, output_dir=None):
                judged = []
                for f in candidates:
                    reply = self._judge({"state": f"Claim: {f.explanation}\nCited item: app.py"})
                    update = (
                        {"judged": True, "supported": True, "kev_verdict": "real", "kev_severity": "high"}
                        if reply["valid"] else {"judged": False, "not_judged_reason": "judge-failed"}
                    )
                    judged.append(f.model_copy(update=update))
                meta = type("Meta", (), {"semgrep_findings_in_diff": 0})()
                return type("Result", (), {"findings": judged, "meta": meta})()

        monkeypatch.setattr(ev, "build_case_repo", lambda *a, **k: None)
        monkeypatch.setattr(ev, "index_repo_docs", lambda *a, **k: None)
        monkeypatch.setattr(ev, "ReviewPipeline", Pipeline)

        saved = {f["finding_id"]: f for f in ev.evaluate_case(self.CASE, LGTMConfig(mode="lgtm"))["findings"]}

        assert [saved[k].get("input_tokens") for k in ("a1", "a2", "b", "c")] == [1000, 9000, None, 300]

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_modes_without_a_judge_save_no_kev_fields(self, ev, monkeypatch, mode):
        saved = self._evaluate(ev, monkeypatch, mode, [self._candidate("a", verdict="vulnerable")])

        for f in saved["findings"]:
            assert [f.get(k) for k in ("kev_verdict", "kev_severity", "input_tokens")] == [None, None, None]


class TestKevResume:
    @staticmethod
    def _done(ev, tmp_path, findings, mode="lgtm"):
        path = tmp_path / "a.json"
        path.write_text(json.dumps(ev.score_case(_row("a", "vulnerable", findings, mode))), encoding="utf-8")
        return path

    def test_judged_unit_without_kev_fields_is_judged_again_on_resume(self, ev, tmp_path):
        assert ev.is_done(self._done(ev, tmp_path, [_finding()])) is False

    def test_judged_unit_with_kev_fields_is_kept_on_resume(self, ev, tmp_path):
        assert ev.is_done(self._done(ev, tmp_path, [_kev()])) is True

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_modes_without_a_judge_are_kept_on_resume(self, ev, tmp_path, mode):
        done = self._done(ev, tmp_path, [_finding(judged=False, verdict="vulnerable")], mode)

        assert ev.is_done(done) is True


class TestKevInJudgeEvalReport:
    KEV = {
        "claim real": {"kev_verdict": "real", "kev_severity": "high", "input_tokens": 9000,
                       "provenance_confidence": 0.9},
        "claim not real": {"kev_verdict": "not_real", "kev_severity": "low", "input_tokens": 400,
                           "provenance_confidence": 0.3, "supported": False},
    }
    NOT_JUDGED = {"judged": False, "supported": None, "provenance_confidence": None,
                  "not_judged_reason": "judge-failed"}

    @staticmethod
    def _run(ce, root: Path, findings):
        root.mkdir()
        case = _case_repo(root)
        evidence = [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr")]
        recorded = [{**_recorded_finding(fid, claim, evidence), **fields} for fid, claim, fields in findings]
        run_dir = root / "run"
        _record_run(run_dir, "case_a", case, recorded)
        record_path = run_dir / "case_a.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record.update(mode="lgtm", category="authz", expected="vulnerable")
        record_path.write_text(json.dumps(record), encoding="utf-8")
        export_path, labels_path = root / "export.json", root / "labels.json"
        ce.export_run(run_dir, {"case_a": case["repo"]}, export_path)
        labels_path.write_text(json.dumps({"units": {}}), encoding="utf-8")
        units = {u["claim"]: u["unit_id"] for u in json.loads(export_path.read_text(encoding="utf-8"))["units"]}
        return run_dir, export_path, labels_path, units

    def _findings(self):
        return [("F0", "claim real", self.KEV["claim real"]),
                ("F1", "claim not real", self.KEV["claim not real"]),
                ("F2", "claim down", self.NOT_JUDGED)]

    def test_report_gives_each_judged_candidate_its_verdict_severity_and_provenance(self, ce, je, tmp_path):
        run_dir, export, labels, units = self._run(ce, tmp_path / "a", self._findings())

        kev = je.report(run_dir, export, labels)["kev"]

        by_unit = {c["unit_id"]: c for c in kev["candidates"]}
        real, not_real = by_unit[units["claim real"]], by_unit[units["claim not real"]]
        assert (real["kev_verdict"], real["kev_severity"], real["provenance_confidence"]) == ("real", "high", 0.9)
        assert (not_real["kev_verdict"], not_real["kev_severity"]) == ("not_real", "low")

    def test_report_summarizes_judged_candidates_only_and_counts_not_judged_by_reason(self, ce, je, tmp_path):
        run_dir, export, labels, units = self._run(ce, tmp_path / "a", self._findings())

        kev = je.report(run_dir, export, labels)["kev"]

        assert kev["judged"] == 2
        assert kev["verdicts"] == {"real": 1, "not_real": 1}
        assert kev["severities"] == {"high": 1, "low": 1}
        assert kev["provenance_confidence_mean"] == pytest.approx(0.6)
        assert kev["not_judged"] == {"judge-failed": 1}
        assert kev["requests_over_8192_input_tokens"] == 1
        assert not any(c["unit_id"] == units["claim down"] and c.get("kev_verdict") for c in kev["candidates"])

    def test_existing_report_measures_equal_those_of_the_same_run_without_kev_answers(self, ce, je, tmp_path):
        with_kev = self._run(ce, tmp_path / "a", self._findings())
        plain_findings = [
            (fid, claim, {k: v for k, v in fields.items() if not k.startswith("kev_") and k != "input_tokens"})
            for fid, claim, fields in self._findings()
        ]
        plain = self._run(ce, tmp_path / "b", plain_findings)

        left = je.report(*with_kev[:3])
        right = je.report(*plain[:3])

        kev_derived = {"kev", "kev_agreement"}
        assert {k: v for k, v in left.items() if k not in kev_derived} == {
            k: v for k, v in right.items() if k not in kev_derived
        }


def _hand_run(root: Path, findings: list[dict], units: list[dict] | None = None):
    """Run dir, export and labels files written without a git repo."""
    run_dir = root / "run"
    run_dir.mkdir(parents=True)
    record = {"id": "case_a", "mode": "lgtm", "category": "authz", "expected": "vulnerable", "findings": findings}
    (run_dir / "case_a.json").write_text(json.dumps(record), encoding="utf-8")
    if units is None:
        units = [{"unit_id": f"case_a/{fi}.{ei}", "code": "x", "unreadable": False}
                 for fi, f in enumerate(findings) for ei, _ in enumerate(f["evidence"])]
    export, labels = root / "export.json", root / "labels.json"
    export.write_text(json.dumps({"units": units}), encoding="utf-8")
    labels.write_text(json.dumps({"units": {}}), encoding="utf-8")
    return run_dir, export, labels


def _evidence(n: int) -> list[EvidenceItem]:
    return [EvidenceItem(file="app.py", lines=[i + 1, i + 2], content="c", snapshot="pr") for i in range(n)]


class TestKevInJudgeEvalReportCountsCandidatesOnce:
    def test_finding_citing_several_code_items_counts_once_in_kev_metrics_and_agrees_with_not_judged_by_reason(
        self, je, tmp_path
    ):
        judged = {
            **_recorded_finding("A", "claim a", _evidence(3)),
            "kev_verdict": "real", "kev_severity": "high", "input_tokens": 9000,
            "provenance_confidence": 0.9,
        }
        down = {
            **_recorded_finding("B", "claim b", _evidence(2)),
            "judged": False, "supported": None, "provenance_confidence": None,
            "not_judged_reason": "judge-failed",
        }
        run_dir, export, labels = _hand_run(tmp_path, [judged, down])

        result = je.report(run_dir, export, labels)
        kev = result["kev"]

        assert kev["judged"] == 1
        assert kev["verdicts"] == {"real": 1}
        assert kev["severities"] == {"high": 1}
        assert kev["requests_over_8192_input_tokens"] == 1
        assert kev["not_judged"] == {"judge-failed": 1}
        assert kev["not_judged"] == result["not_judged_by_reason"]
        assert len(kev["candidates"]) == 1


class TestLiveRejudgeSkipsUnreadableUnits:
    @pytest.mark.parametrize("unit_fields, lines", [
        ({"code": "", "unreadable": True, "lines": [2, 3]}, [2, 3]),
        ({"code": "", "unreadable": True, "lines": None}, None),
    ])
    def test_unit_whose_code_cannot_be_read_is_not_sent_to_the_judge_and_is_counted_not_judged(
        self, je, tmp_path, unit_fields, lines
    ):
        readable = {**_recorded_finding("R", "claim readable", _evidence(1)), "supported": None}
        unreadable_evidence = [EvidenceItem(file="gone.py", lines=lines, content="c", snapshot="pr")]
        unreadable = {**_recorded_finding("U", "claim unreadable", unreadable_evidence), "supported": None}
        base = {"file": "app.py", "snapshot": "pr"}
        units = [
            {**base, "unit_id": "case_a/0.0", "lines": [1, 2], "code": "line1\nline2"},
            {**base, "unit_id": "case_a/1.0", "file": "gone.py", **unit_fields},
        ]
        run_dir, export, labels = _hand_run(tmp_path, [readable, unreadable], units)
        requests: list[dict] = []

        def judge(request):
            requests.append(request)
            return _reply()

        records = je.rejudge(run_dir, export, LGTMConfig(), judge)

        assert len(requests) == 1
        assert "claim unreadable" not in json.dumps(requests)
        by_id = {f["finding_id"]: f for f in records[0]["findings"]}
        assert by_id["R"]["judged"] is True
        assert by_id["U"]["judged"] is False
        assert not by_id["U"].get("kev_verdict")

        for n, record in enumerate(records):
            (tmp_path / "live").mkdir(exist_ok=True)
            (tmp_path / "live" / f"{n}.json").write_text(json.dumps(record), encoding="utf-8")
        kev = je.report(tmp_path / "live", export, labels)["kev"]

        assert kev["judged"] == 1
        assert sum(kev["not_judged"].values()) == 1


def _snapshot_repo(root: Path) -> dict:
    repo = root / "snap_repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text(BASE_APP, encoding="utf-8")
    (repo / "removed.py").write_text("old1\nold2\nold3\n", encoding="utf-8")
    (repo / "shrunk.py").write_text("s1\ns2\ns3\ns4\ns5\ns6\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "pr")
    (repo / "app.py").write_text(PR_APP, encoding="utf-8")
    (repo / "removed.py").unlink()
    (repo / "shrunk.py").write_text("s1\ns2\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    pr_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    return {"repo": repo, "base_sha": base_sha, "pr_sha": pr_sha}


def _export_and_rejudge(ce, je, tmp_path: Path, evidence_sets: list[list[EvidenceItem]]):
    case = _snapshot_repo(tmp_path)
    findings = [
        {**_recorded_finding(f"F{i}", f"claim {i}", evidence), "supported": None}
        for i, evidence in enumerate(evidence_sets)
    ]
    run_dir = tmp_path / "run"
    _record_run(run_dir, "case_a", case, findings)
    path = run_dir / "case_a.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["mode"] = "lgtm"
    path.write_text(json.dumps(record), encoding="utf-8")
    export = tmp_path / "export.json"
    units = ce.export_run(run_dir, {"case_a": case["repo"]}, export)
    requests: list[dict] = []

    def judge(request):
        requests.append(request)
        return _reply()

    records = je.rejudge(run_dir, export, LGTMConfig(), judge)
    return units, requests, {f["finding_id"]: f for f in records[0]["findings"]}


class TestNullSnapshotCitationsAreReadAtPrHead:
    def test_null_snapshot_citation_is_exported_with_pr_code_and_judged_on_it(self, ce, je, tmp_path):
        evidence = [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot=None)]

        units, requests, findings = _export_and_rejudge(ce, je, tmp_path, [evidence])

        assert units[0]["snapshot"] is None
        assert units[0]["code"].splitlines() == ["pr2", "pr3"]
        assert not units[0].get("unreadable")
        assert len(requests) == 1
        sent = json.dumps(requests)
        assert "pr2" in sent and "base2" not in sent
        assert findings["F0"]["judged"] is True
        assert findings["F0"]["not_judged_reason"] != je.REASON_CODE_UNREADABLE

    @pytest.mark.parametrize("item_fields", [
        {"file": "removed.py", "lines": [1, 2]},
        {"file": "shrunk.py", "lines": [4, 6]},
        {"file": "never_existed.py", "lines": [1, 1]},
    ], ids=["file-only-at-base", "lines-only-at-base", "file-nowhere"])
    def test_null_snapshot_citation_unresolved_at_pr_head_is_unreadable_and_not_judged_without_base_fallback(
        self, ce, je, tmp_path, item_fields
    ):
        readable = [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot=None)]
        unresolved = [EvidenceItem(content="c", snapshot=None, **item_fields)]

        units, requests, findings = _export_and_rejudge(ce, je, tmp_path, [readable, unresolved])

        assert units[1]["unreadable"] is True
        assert units[1]["code"] == ""
        assert len(requests) == 1
        assert "claim 1" not in json.dumps(requests)
        assert findings["F1"]["judged"] is False
        assert findings["F1"]["not_judged_reason"] == je.REASON_CODE_UNREADABLE
        assert findings["F0"]["judged"] is True


class TestExplicitSnapshotsAreExportedAndRejudgedAsBefore:
    def test_base_and_pr_citations_are_read_at_their_own_snapshot_and_judged(self, ce, je, tmp_path):
        evidence = [
            EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr"),
            EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="base"),
        ]

        units, requests, findings = _export_and_rejudge(ce, je, tmp_path, [evidence])

        assert [u["code"].splitlines() for u in units] == [["pr2", "pr3"], ["base2", "base3"]]
        assert not any(u.get("unreadable") for u in units)
        assert len(requests) == 1
        assert findings["F0"]["judged"] is True

    def test_base_citation_missing_at_base_stays_unreadable_and_not_judged(self, ce, je, tmp_path):
        evidence = [EvidenceItem(file="never_existed.py", lines=[1, 1], content="c", snapshot="base")]

        units, requests, findings = _export_and_rejudge(ce, je, tmp_path, [evidence])

        assert units[0]["unreadable"] is True
        assert requests == []
        assert findings["F0"]["not_judged_reason"] == je.REASON_CODE_UNREADABLE


class TestNullSnapshotUnitsCarryPrHeadCode:
    BASE, PR = "a" * 40, "b" * 40
    FILES = {
        (BASE, "app.py"): "line1\nbase2\nbase3\nline4\n",
        (PR, "app.py"): "line1\npr2\npr3\nline4\n",
    }

    def test_null_snapshot_code_items_carry_the_pr_head_code_and_are_not_unreadable(
        self, ce, monkeypatch
    ):
        from types import SimpleNamespace

        def run(args, **_kwargs):
            if "cat-file" in args:
                return SimpleNamespace(returncode=0, stdout=b"")
            text = self.FILES.get(tuple(args[-1].split(":", 1)))
            if text is None:
                return SimpleNamespace(returncode=128, stdout=b"")
            return SimpleNamespace(returncode=0, stdout=text.encode())

        def finding(lines):
            return {
                "explanation": "claim",
                "evidence": [{"type": "code", "file": "app.py", "lines": lines, "snapshot": None}],
            }

        record = {
            "id": "case_a", "base_sha": self.BASE, "pr_sha": self.PR,
            "findings": [finding([2, 3]), finding([4, 4])],
        }
        written = []
        monkeypatch.setattr(ce, "read_records", lambda _run_dir: [record])
        monkeypatch.setattr(ce, "subprocess", SimpleNamespace(run=run))
        monkeypatch.setattr(ce, "Path", lambda p: p)
        out = SimpleNamespace(write_text=lambda text, **_kw: written.append(text))

        units = ce.export_run("run", {"case_a": "repo"}, out)

        assert [u["code"].splitlines() for u in units] == [["pr2", "pr3"], ["line4"]]
        assert not any(u.get("unreadable") for u in units)
        assert [u["snapshot"] for u in units] == [None, None]
        assert json.loads(written[0])["units"] == units


# --- kev-judge-measurement: verdict and support scored separately, labelled real candidates ---

ROOT = Path(__file__).resolve().parent.parent
STALE_CASES = ("sqli_04_safe", "sqli_07_safe", "sqli_11_safe")


def _kf(supported=True, kev_verdict=None, verdict="", category="authz"):
    return {**_finding(supported=supported, verdict=verdict, category=category), "kev_verdict": kev_verdict}


def _ko(unit_id, supported=True, kev_verdict="real", kev_severity="high", agent_verdict="", judged=True):
    return {
        "unit_id": unit_id, "judged": judged,
        "supported": supported if judged else None,
        "kev_verdict": kev_verdict if judged else None,
        "kev_severity": kev_severity if judged else None,
        "agent_verdict": agent_verdict,
        "provenance_confidence": 0.5 if judged else None,
    }


def _kl(**units):
    """_kl(u1=("yes", "real", "high"), u2=("no", "not_real", None, {"kind": "x"})) -> labels file content."""
    labels = {"labeling_model": "claude-opus-5.5", "units": {}}
    for uid, (supports, verdict, severity, *rest) in units.items():
        entry = {"supports": supports, "verdict": verdict}
        if severity:
            entry["severity"] = severity
        labels["units"][uid] = {**entry, **(rest[0] if rest else {})}
    return labels


class TestSupportedButNotRealIsNotAVulnerability:
    @pytest.mark.parametrize("kev_verdict,supported,expected", [
        ("not_real", True, "safe"),
        ("real", True, "vulnerable"),
        (None, True, "vulnerable"),
        ("real", False, "safe"),
    ])
    def test_finding_is_a_vulnerability_only_when_supported_and_not_ruled_not_real(
        self, ev, kev_verdict, supported, expected
    ):
        finding = _kf(supported=supported, kev_verdict=kev_verdict)

        assert ev.finding_verdict(finding, True) == expected

    def test_supported_but_not_real_candidate_on_a_safe_case_is_not_a_false_alarm(self, ev):
        row = ev.score_case(_row("authz_09_safe", "safe", [_kf(supported=True, kev_verdict="not_real")]))

        assert row["outcome"] == "TN"

    def test_supported_but_not_real_candidate_on_a_vulnerable_case_does_not_detect_it(self, ev):
        row = ev.score_case(_row("authz_01_vulnerable", "vulnerable", [_kf(supported=True, kev_verdict="not_real")]))

        assert row["outcome"] == "FN"

    def test_supported_and_real_candidate_on_a_safe_case_is_still_a_false_alarm(self, ev):
        row = ev.score_case(_row("authz_09_safe", "safe", [_kf(supported=True, kev_verdict="real")]))

        assert row["outcome"] == "FP"

    def test_supported_but_not_real_candidate_is_not_listed_as_off_category(self, ev):
        row = _row("sqli_01_vulnerable", "vulnerable", [_kf(supported=True, kev_verdict="not_real")], category="sqli")
        row["findings"][0]["category"] = "authz"

        assert ev.scope_fields(row)["off_category"] == []

    def test_judge_eval_case_accuracy_counts_the_not_real_candidate_as_not_flagged(self, je):
        cases = [_row("authz_09_safe", "safe", [_kf(supported=True, kev_verdict="not_real")])]

        assert je.verdict_accuracy(cases)["correct"] == 1


class TestKevAccuracy:
    LABELS = _kl(
        u1=("yes", "real", "high"),
        u2=("yes", "real", "medium"),
        u3=("no", "not_real", None),
        u4=("no", "not_real", None),
    )

    def _outcomes(self):
        return [
            _ko("u1", True, "real", "high"),
            _ko("u2", True, "not_real", "low"),
            _ko("u3", True, "not_real", "low"),
            _ko("u4", False, "not_real", "low"),
        ]

    def test_supported_and_verdict_accuracy_are_two_separate_numbers_against_labels(self, je):
        accuracy = je.kev_accuracy(self.LABELS, self._outcomes())

        assert (accuracy["supported"]["n"], accuracy["supported"]["correct"]) == (4, 3)
        assert accuracy["supported"]["accuracy"] == 0.75
        assert (accuracy["verdict"]["n"], accuracy["verdict"]["correct"]) == (4, 3)
        flipped = self._outcomes()
        flipped[0]["kev_verdict"] = "not_real"
        after = je.kev_accuracy(self.LABELS, flipped)
        assert after["verdict"]["accuracy"] == 0.5
        assert after["supported"]["accuracy"] == 0.75

    def test_severity_accuracy_is_its_own_number_over_units_with_a_severity_label(self, je):
        accuracy = je.kev_accuracy(self.LABELS, self._outcomes())

        assert (accuracy["severity"]["n"], accuracy["severity"]["correct"]) == (2, 1)
        assert accuracy["severity"]["accuracy"] == 0.5

    def test_severity_miss_leaves_supported_and_verdict_accuracy_unchanged(self, je):
        outcomes = self._outcomes()
        outcomes[0]["kev_severity"] = "critical"

        accuracy = je.kev_accuracy(self.LABELS, outcomes)

        assert accuracy["severity"]["accuracy"] == 0.0
        assert accuracy["supported"]["accuracy"] == 0.75
        assert accuracy["verdict"]["accuracy"] == 0.75

    def test_not_judged_and_unlabelled_units_are_left_out(self, je):
        labels = _kl(**{"u1": ("yes", "real", "high"), "u2": ("yes", "real", "high")})
        outcomes = [_ko("u1"), _ko("u2", judged=False), _ko("unlabelled")]

        assert je.kev_accuracy(labels, outcomes)["supported"]["n"] == 1

    def test_support_only_and_verdict_only_labels_use_independent_denominators(self, je):
        labels = _kl(
            support_only=("yes", None, None),
            verdict_only=(None, "not_real", None),
        )
        outcomes = [_ko("support_only", True, "real"), _ko("verdict_only", False, "not_real")]

        accuracy = je.kev_accuracy(labels, outcomes)
        assert accuracy["supported"] == {"n": 1, "correct": 1, "accuracy": 1.0}
        assert accuracy["verdict"] == {"n": 1, "correct": 1, "accuracy": 1.0}

    def test_no_labelled_judged_unit_reports_no_accuracy(self, je):
        accuracy = je.kev_accuracy(self.LABELS, [_ko("other")])

        assert accuracy["supported"] == {"n": 0, "correct": 0, "accuracy": None}
        assert accuracy["verdict"]["accuracy"] is None
        assert accuracy["severity"]["accuracy"] is None

    def test_stale_candidates_are_left_out_even_when_a_label_names_them(self, je):
        labels = _kl(**{"sqli_04_safe/0.0": ("yes", "real", "high"), "u1": ("yes", "real", "high")})
        outcomes = [_ko("sqli_04_safe/0.0", False, "not_real"), _ko("u1")]

        accuracy = je.kev_accuracy(labels, outcomes)

        assert (accuracy["supported"]["n"], accuracy["supported"]["correct"]) == (1, 1)


class TestKevAgreement:
    def test_rate_at_which_verdict_and_supported_answers_disagree(self, je):
        outcomes = [
            _ko("a", True, "real"),
            _ko("b", True, "not_real"),
            _ko("c", False, "real"),
            _ko("d", False, "not_real"),
            _ko("e", judged=False),
        ]

        agreement = je.kev_agreement(outcomes)["verdict_vs_supported"]

        assert (agreement["n"], agreement["disagree"], agreement["rate"]) == (4, 2, 0.5)

    def test_rate_at_which_the_kev_verdict_equals_the_agent_verdict(self, je):
        outcomes = [
            _ko("a", kev_verdict="real", agent_verdict="vulnerable"),
            _ko("b", kev_verdict="not_real", agent_verdict="vulnerable"),
            _ko("c", kev_verdict="not_real", agent_verdict="safe"),
            _ko("d", kev_verdict="real", agent_verdict=""),
            _ko("e", kev_verdict="not_real", agent_verdict=""),
        ]

        agreement = je.kev_agreement(outcomes)["verdict_vs_agent"]

        assert (agreement["n"], agreement["equal"]) == (5, 3)
        assert agreement["rate"] == pytest.approx(3 / 5)

    def test_exported_lgtm_candidate_with_empty_verdict_counts_as_the_agent_asserting_a_vulnerability(
        self, je, tmp_path
    ):
        case = _case_repo(tmp_path)
        evidence = [EvidenceItem(file="app.py", lines=[2, 3], content="c", snapshot="pr")]
        real = {**_recorded_finding("F0", "kev real", evidence), "kev_verdict": "real"}
        not_real = {**_recorded_finding("F1", "kev not real", evidence), "kev_verdict": "not_real"}
        run_dir = tmp_path / "run"
        _record_run(run_dir, "case_a", case, [real, not_real])

        outcomes = je.run_outcomes(run_dir)
        agreement = je.kev_agreement(outcomes)["verdict_vs_agent"]

        assert [o["agent_verdict"] for o in outcomes] == ["", ""]
        assert (agreement["n"], agreement["equal"], agreement["rate"]) == (2, 1, 0.5)

    def test_no_answered_candidate_reports_no_rate(self, je):
        agreement = je.kev_agreement([_ko("a", judged=False)])

        assert agreement["verdict_vs_supported"]["rate"] is None
        assert agreement["verdict_vs_agent"]["rate"] is None

    def test_stale_candidates_are_left_out(self, je):
        outcomes = [_ko("sqli_07_safe/0.0", True, "not_real"), _ko("a", True, "real")]

        assert je.kev_agreement(outcomes)["verdict_vs_supported"]["n"] == 1


class TestStaleCandidates:
    def test_the_three_regenerated_shoply_safe_cases_are_listed_stale_with_the_reason(self, je):
        outcomes = [_ko(f"{case}/0.0") for case in STALE_CASES] + [_ko("authz_01_vulnerable/0.0")]

        stale = je.stale_candidates(outcomes)

        assert sorted(s["case_id"] for s in stale) == sorted(STALE_CASES)
        assert all("predate" in s["reason"].lower() for s in stale)

    def test_only_stale_cases_present_in_the_run_are_listed_once_each(self, je):
        stale = je.stale_candidates([_ko("sqli_04_safe/0.0"), _ko("sqli_04_safe/1.0"), _ko("authz_01_safe/0.0")])

        assert [s["case_id"] for s in stale] == ["sqli_04_safe"]


class TestLabelSummary:
    def test_counts_labelled_examples_per_origin_and_states_they_are_model_generated(self, je):
        labels = _kl(
            a=("yes", "real", "high", {"origin": "shoply"}),
            b=("no", "not_real", None, {"origin": "shoply"}),
            c=("yes", "real", "low", {"origin": "real_world"}),
        )

        summary = je.label_summary(labels)

        assert summary["n"] == 3
        assert summary["origins"] == {"shoply": 2, "real_world": 1}
        assert summary["source"] == "model"
        assert summary["labeling_model"] == "claude-opus-5.5"

    def test_labels_without_a_recorded_labeling_model_are_rejected(self, je):
        labels = _kl(a=("yes", "real", "high", {"origin": "shoply"}))
        del labels["labeling_model"]

        with pytest.raises(ValueError, match="labeling_model"):
            je.label_summary(labels)


def _live(origin="shoply", supports="no", verdict="not_real", kind="live_shaped"):
    return (supports, verdict, None, {"kind": kind, "origin": origin})


class TestSupportedByKindAndSafeCaseAcceptance:
    def test_supported_accuracy_is_broken_down_by_candidate_kind_including_live_shaped(self, je):
        labels = _kl(
            a=_live(supports="yes", verdict="real"),
            b=_live(supports="yes", verdict="real"),
            c=_live(kind="safe_twin"),
            d=_live(origin="real_world"),
        )
        outcomes = [_ko("a", True), _ko("b", False), _ko("c", False), _ko("d", True)]

        by_kind = je.supported_by_kind(labels, outcomes)

        assert by_kind["live_shaped"] == {"n": 3, "correct": 1, "accuracy": pytest.approx(1 / 3)}
        assert by_kind["safe_twin"] == {"n": 1, "correct": 1, "accuracy": 1.0}

    def test_not_judged_and_unlabelled_candidates_are_left_out_of_every_kind(self, je):
        by_kind = je.supported_by_kind(_kl(a=_live()), [_ko("a", judged=False), _ko("zz", True)])

        assert all(entry["n"] == 0 for entry in by_kind.values())

    def test_share_of_safe_case_candidates_kev_accepted_is_reported_per_origin(self, je):
        labels = _kl(**{
            "s1/0.0": _live(), "s1/1.0": _live(), "s2/0.0": _live(),
            "r1/0.0": _live("real_world"),
            "v1/0.0": _live(supports="yes", verdict="real"),
        })
        outcomes = [
            _ko("s1/0.0", True), _ko("s1/1.0", False), _ko("s2/0.0", False),
            _ko("r1/0.0", True), _ko("v1/0.0", True),
        ]

        share = je.safe_case_acceptance(labels, outcomes, safe_cases={"s1", "s2", "r1"})

        assert share["shoply"] == {"n": 3, "accepted": 1, "share": pytest.approx(1 / 3)}
        assert share["real_world"] == {"n": 1, "accepted": 1, "share": 1.0}

    def test_origin_without_safe_case_candidates_reports_no_share(self, je):
        share = je.safe_case_acceptance(_kl(**{"a/0.0": _live()}), [_ko("a/0.0", False)], safe_cases={"a"})

        assert share["real_world"] == {"n": 0, "accepted": 0, "share": None}


class TestQuoteAbsence:
    PR_FILE = "def a():\n    return 1\n\ndef b():\n    return order\n"

    def _record(self, case_id, content, lines, file="app.py"):
        return {
            "id": case_id,
            "findings": [{"evidence": [{"type": "code", "file": file, "lines": lines, "content": content}]}],
        }

    def _rows(self, je, record, text):
        return je.quote_absence([record], lambda _case, _file: text)

    def test_quote_found_in_the_pr_file_is_not_absent(self, je):
        record = self._record("authz_10_vulnerable", "def b():\n    return order", [4, 5])

        [row] = self._rows(je, record, self.PR_FILE)

        assert (row["case_id"], row["absent"], row["cause"]) == ("authz_10_vulnerable", False, None)

    def test_quote_missing_from_a_file_that_has_the_cited_lines_is_blamed_on_the_agent_quote(self, je):
        [row] = self._rows(je, self._record("authz_12_vulnerable", "return order_for(user)", [4, 5]), self.PR_FILE)

        assert (row["absent"], row["cause"]) == (True, "agent_quote")

    def test_cited_file_missing_from_the_pr_is_a_repository_mismatch(self, je):
        [row] = self._rows(je, self._record("authz_10_vulnerable", "return order", [4, 5]), None)

        assert (row["absent"], row["cause"]) == (True, "repository_mismatch")

    def test_cited_lines_beyond_the_pr_file_are_a_repository_mismatch(self, je):
        [row] = self._rows(je, self._record("authz_10_vulnerable", "return order", [40, 41]), self.PR_FILE)

        assert (row["absent"], row["cause"]) == (True, "repository_mismatch")

    def test_only_authz_10_and_authz_12_vulnerable_are_reported(self, je):
        records = [
            self._record("authz_10_vulnerable", "x", [1, 1]),
            self._record("authz_11_vulnerable", "x", [1, 1]),
            self._record("authz_12_vulnerable", "x", [1, 1]),
        ]

        rows = je.quote_absence(records, lambda _case, _file: self.PR_FILE)

        assert sorted(r["case_id"] for r in rows) == ["authz_10_vulnerable", "authz_12_vulnerable"]


class TestJudgeEvalReportWiring:
    def _write(self, tmp_path):
        evidence = [{"type": "code", "file": "a.py", "lines": [1, 2], "snapshot": "pr"}]
        detected = {**_kf(True, "real", verdict="vulnerable"), "kev_severity": "high",
                    "provenance_confidence": 0.9, "evidence": evidence}
        ruled_out = {**_kf(True, "not_real", verdict="vulnerable"), "kev_severity": "low",
                     "provenance_confidence": 0.9, "evidence": evidence}
        run = tmp_path / "run"
        run.mkdir()
        for cid, expected, findings in (
            ("authz_01_vulnerable", "vulnerable", [detected]),
            ("authz_09_safe", "safe", [ruled_out]),
        ):
            (run / f"{cid}.json").write_text(json.dumps(_row(cid, expected, findings)), encoding="utf-8")
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"units": [
            {"unit_id": "authz_01_vulnerable/0.0"}, {"unit_id": "authz_09_safe/0.0"},
        ]}), encoding="utf-8")
        labels = tmp_path / "labels.json"
        labels.write_text(json.dumps(_kl(**{
            "authz_01_vulnerable/0.0": ("yes", "real", "high", {"kind": "live_shaped", "origin": "shoply"}),
            "authz_09_safe/0.0": ("yes", "not_real", "low", {"kind": "live_shaped", "origin": "shoply"}),
        })), encoding="utf-8")
        return run, export, labels

    def test_report_carries_the_kev_accuracy_agreement_and_label_sections(self, je, tmp_path):
        report = je.report(*self._write(tmp_path))

        assert report["kev_accuracy"]["supported"]["accuracy"] == 1.0
        assert report["kev_accuracy"]["verdict"]["accuracy"] == 1.0
        assert report["kev_accuracy"]["severity"]["accuracy"] == 1.0
        assert report["kev_agreement"]["verdict_vs_supported"]["n"] == 2
        assert report["kev_agreement"]["verdict_vs_agent"]["equal"] == 1
        assert report["labels"]["n"] == 2
        assert report["labels"]["source"] == "model"
        assert report["supported_by_kind"]["live_shaped"]["n"] == 2
        assert report["safe_case_acceptance"]["shoply"] == {"n": 1, "accepted": 1, "share": 1.0}
        assert report["stale"] == []


class TestFreshCandidatesOfTheRegeneratedShoplyCases:
    def _report(self, je, tmp_path, run: Path):
        units = {f"{case}/0.0": ("yes", "not_real", None, {"kind": "live_shaped", "origin": "shoply"}) for case in STALE_CASES}
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"units": [{"unit_id": uid} for uid in units]}), encoding="utf-8")
        labels = tmp_path / "labels.json"
        labels.write_text(json.dumps(_kl(**units)), encoding="utf-8")
        return je.report(run, export, labels, read_pr_file=lambda *_: None)

    def test_candidates_exported_from_a_new_run_are_scored_and_not_reported_stale(self, je, tmp_path):
        run = tmp_path / "run"
        run.mkdir()
        evidence = [{"type": "code", "file": "a.py", "lines": [1, 2], "snapshot": "pr"}]
        finding = {**_kf(True, "not_real", verdict="vulnerable"), "kev_severity": "low",
                   "provenance_confidence": 0.9, "evidence": evidence}
        for case in STALE_CASES:
            (run / f"{case}.json").write_text(json.dumps(_row(case, "safe", [finding])), encoding="utf-8")

        report = self._report(je, tmp_path, run)

        assert report["kev_accuracy"]["supported"] == {"n": 3, "correct": 3, "accuracy": 1.0}
        assert report["kev_accuracy"]["verdict"]["n"] == 3
        assert report["supported_by_kind"]["live_shaped"]["n"] == 3
        assert report["safe_case_acceptance"]["shoply"] == {"n": 3, "accepted": 3, "share": 1.0}
        assert report["stale"] == []

    def test_the_stored_run6_final_candidates_are_still_reported_stale_with_the_reason(self, je, tmp_path):
        report = self._report(je, tmp_path, ROOT / "benchmark" / "runs" / "archive" / "run6-final" / "lgtm")

        assert sorted(s["case_id"] for s in report["stale"]) == sorted(STALE_CASES)
        assert all(s["reason"] for s in report["stale"])

    def test_live_rejudge_of_the_stored_run6_final_run_still_reports_the_cases_stale_and_leaves_them_out_of_scoring(
        self, je, tmp_path, monkeypatch, capsys
    ):
        evidence = [{"type": "code", "file": "a.py", "lines": [1, 2], "snapshot": "pr"}]
        finding = {**_kf(True, "not_real", verdict="vulnerable"), "kev_severity": "low",
                   "provenance_confidence": 0.9, "evidence": evidence}
        rejudged = [_row(case, "safe", [finding]) for case in STALE_CASES]
        monkeypatch.setattr(je, "rejudge", lambda *_args, **_kwargs: rejudged)
        units = {f"{case}/0.0": ("yes", "not_real", None, {"kind": "live_shaped", "origin": "shoply"}) for case in STALE_CASES}
        export, labels = tmp_path / "export.json", tmp_path / "labels.json"
        export.write_text(json.dumps({"units": [{"unit_id": uid} for uid in units]}), encoding="utf-8")
        labels.write_text(json.dumps(_kl(**units)), encoding="utf-8")
        stored = ROOT / "benchmark" / "runs" / "archive" / "run6-final" / "lgtm"
        monkeypatch.setattr(sys, "argv", ["judge_eval.py", str(stored), str(export), str(labels), "--live"])

        je.main()
        out = json.loads(capsys.readouterr().out)

        assert sorted(s["case_id"] for s in out["stale"]) == sorted(STALE_CASES)
        assert out["kev_accuracy"]["supported"]["n"] == 0
        assert out["kev_agreement"]["verdict_vs_supported"]["n"] == 0


class TestStoredLabelsAndCriteria:
    LABELS = ROOT / "benchmark" / "kev_model_labels.json"
    CRITERIA = ROOT / "docs" / "kev-labeling-criteria.md"

    def test_labeling_criteria_document_defines_support_verdict_and_severity_levels(self):
        text = self.CRITERIA.read_text(encoding="utf-8").lower()

        for term in ("supported", "verdict", "not_real", "severity", "low", "medium", "high", "critical"):
            assert term in text

    def test_stored_labels_record_the_labeling_model_and_the_criteria_they_follow(self):
        labels = json.loads(self.LABELS.read_text(encoding="utf-8"))

        assert labels["labeling_model"].strip()
        assert (ROOT / labels["criteria"]).resolve() == self.CRITERIA.resolve()

    def test_stored_labels_hold_supported_verdict_kind_and_origin_for_each_unit(self):
        units = json.loads(self.LABELS.read_text(encoding="utf-8"))["units"]

        assert units
        assert all(u["supports"] in ("yes", "no") and u["verdict"] in ("real", "not_real", "undetermined") for u in units.values())
        assert all(u.get("kind") and u.get("origin") in ("shoply", "real_world") for u in units.values())

    def test_stored_labels_cover_the_regenerated_run_and_only_the_archived_run_is_stale(self, je):
        units = json.loads(self.LABELS.read_text(encoding="utf-8"))["units"]
        regenerated = ROOT / "benchmark" / "runs" / "shoply-regen-20261028" / "lgtm"
        archived = ROOT / "benchmark" / "runs" / "archive" / "run6-final" / "lgtm"

        for case in ("sqli_07_safe", "sqli_11_safe"):
            assert [uid for uid in units if uid.split("/")[0] == case]
        assert je.stale_cases_for(regenerated) == ()
        assert sorted(je.stale_cases_for(archived)) == sorted(STALE_CASES)


class TestUndeterminedLabels:
    LABELS = _kl(
        a=("yes", "real", "high"),
        b=("no", "undetermined", None),
        c=("yes", "undetermined", None),
    )

    def test_kev_accuracy_leaves_undetermined_units_out_of_the_verdict_measure(self, je):
        outcomes = [_ko("a", True, "real"), _ko("b", True, "real"), _ko("c", False, "not_real")]

        verdict = je.kev_accuracy(self.LABELS, outcomes)["verdict"]

        assert (verdict["n"], verdict["correct"], verdict["accuracy"]) == (1, 1, 1.0)

    def test_kev_agreement_leaves_undetermined_units_out_of_the_verdict_measures(self, je):
        outcomes = [
            _ko("a", True, "real", agent_verdict="vulnerable"),
            _ko("b", True, "not_real", agent_verdict="vulnerable"),
            _ko("c", False, "real", agent_verdict="safe"),
        ]

        agreement = je.kev_agreement(outcomes, self.LABELS)

        assert (agreement["verdict_vs_supported"]["n"], agreement["verdict_vs_supported"]["disagree"]) == (1, 0)
        assert (agreement["verdict_vs_agent"]["n"], agreement["verdict_vs_agent"]["equal"]) == (1, 1)

    def test_report_lists_the_undetermined_units(self, je, tmp_path):
        evidence = [{"type": "code", "file": "a.py", "lines": [1, 2], "snapshot": "pr"}]
        finding = {**_kf(True, "real", verdict="vulnerable"), "kev_severity": "high",
                   "provenance_confidence": 0.9, "evidence": evidence}
        run = tmp_path / "run"
        run.mkdir()
        for cid in ("authz_01_vulnerable", "authz_02_vulnerable"):
            (run / f"{cid}.json").write_text(json.dumps(_row(cid, "vulnerable", [finding])), encoding="utf-8")
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"units": [
            {"unit_id": "authz_01_vulnerable/0.0"}, {"unit_id": "authz_02_vulnerable/0.0"},
        ]}), encoding="utf-8")
        labels = tmp_path / "labels.json"
        labels.write_text(json.dumps(_kl(**{
            "authz_01_vulnerable/0.0": ("yes", "real", "high", {"kind": "live_shaped", "origin": "shoply"}),
            "authz_02_vulnerable/0.0": ("no", "undetermined", None, {"kind": "live_shaped", "origin": "shoply"}),
        })), encoding="utf-8")

        report = je.report(run, export, labels)

        assert report["undetermined"] == ["authz_02_vulnerable/0.0"]
        assert report["kev_accuracy"]["verdict"]["n"] == 1
        assert report["kev_agreement"]["verdict_vs_supported"]["n"] == 1


class TestMixedOriginLabelsGiveTheSameResultsAsOwnUnitsOnly:
    OUTCOMES = [_ko("s1/0.0", True), _ko("s1/1.0", False), _ko("s2/0.0", True)]

    @staticmethod
    def _labels_for(*, with_real_world):
        units = {
            "s1/0.0": _live(supports="yes", verdict="real"),
            "s1/1.0": _live(),
            "s2/0.0": _live(kind="safe_twin"),
        }
        if with_real_world:
            units["r1/0.0"] = _live("real_world", supports="yes", verdict="real")
            units["r2/0.0"] = _live("real_world")
        return _kl(**units)

    def test_confidence_agreement_ignores_the_other_origin_units(self, je):
        outcomes = [{**o, "provenance_confidence": 0.5} for o in self.OUTCOMES]

        mixed = je.confidence_agreement(self._labels_for(with_real_world=True), outcomes)
        own = je.confidence_agreement(self._labels_for(with_real_world=False), outcomes)

        assert mixed == own
        assert mixed["yes"]["n"] + mixed["no"]["n"] > 0

    def test_per_origin_safe_case_counts_ignore_the_other_origin_units(self, je):
        mixed = je.safe_case_acceptance(self._labels_for(with_real_world=True), self.OUTCOMES, {"s1", "s2"})
        own = je.safe_case_acceptance(self._labels_for(with_real_world=False), self.OUTCOMES, {"s1", "s2"})

        assert mixed == own
        assert mixed["shoply"]["n"] == 3
        assert mixed["real_world"]["n"] == 0

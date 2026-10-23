"""Unit tests for the standalone Kev validation benchmark (benchmark/kev_support/): case set and ground
truth, the few-shot and zero-shot arms, per-case result records, rate and severity scoring, permute
order-sensitivity scoring, error and too-large handling, and the command-line entry. The Kev judge
and the permute route are in-process fakes; nothing reaches a network or a cluster."""

from __future__ import annotations

import ast
import importlib
import io
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

import pytest

from lgtm.validation.judge import (
    QUESTION_CONFIDENCE,
    QUESTION_SEVERITY,
    QUESTION_SUPPORT,
    QUESTION_VERDICT,
    SEVERITY_LEVELS,
)
from lgtm.validation.judge_examples import EXAMPLES

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

CONTROL = "control"
INCORRECT_KINDS = (
    "safe_twin",
    "unrelated_code",
    "missing_check",
    "sqli_no_sql",
    "wrong_cwe",
    "live_shaped",
    "real_elsewhere",
)
ARMS = ("few_shot", "zero_shot")
CHOICE_QUESTIONS = (QUESTION_SUPPORT, QUESTION_VERDICT, QUESTION_SEVERITY)
ALL_QUESTIONS = {*CHOICE_QUESTIONS, QUESTION_CONFIDENCE}
OPTIONS = {
    QUESTION_SUPPORT: ("yes", "no"),
    QUESTION_VERDICT: ("real", "not_real"),
    QUESTION_SEVERITY: SEVERITY_LEVELS,
}
TOKEN_LIMIT = 8192


@pytest.fixture(scope="module")
def fixtures_mod():
    return importlib.import_module("kev_support.fixtures")


@pytest.fixture(scope="module")
def runner():
    return importlib.import_module("kev_support.runner")


@pytest.fixture(scope="module")
def all_fixtures(fixtures_mod):
    return fixtures_mod.load_fixtures()


def _choice(question: str, choice: str) -> dict:
    options = OPTIONS[question]
    rest = round(0.4 / (len(options) - 1), 4)
    return {
        "type": "choice",
        "choice": choice,
        "confidence": 0.5,
        "probabilities": {o: 0.6 if o == choice else rest for o in options},
    }


def kev_reply(*, supported="yes", verdict="real", severity="high", noul=0.9, tokens=1000) -> dict:
    return {
        "answers": {
            QUESTION_SUPPORT: _choice(QUESTION_SUPPORT, supported),
            QUESTION_VERDICT: _choice(QUESTION_VERDICT, verdict),
            QUESTION_SEVERITY: _choice(QUESTION_SEVERITY, severity),
            QUESTION_CONFIDENCE: {"type": "noul", "noul": noul},
        },
        "usage": {"input_tokens": tokens, "output_tokens": 0},
    }


def truth_reply(f, tokens=1000) -> dict:
    """The reply of a judge that agrees with the ground truth of the case."""
    supported = f.provenance == "supported"
    return kev_reply(
        supported="yes" if supported else "no",
        verdict=f.verdict,
        severity=f.severity or "low",
        noul=0.9 if supported else 0.1,
        tokens=tokens,
    )


def permute_reply(question: str, choices: list[str], *, stable: bool = True) -> dict:
    options = list(OPTIONS[question])
    return {
        "runs": [
            {
                "order": options[i % len(options) :] + options[: i % len(options)],
                "probabilities": {o: 1.0 if o == c else 0.0 for o in options},
                "choice": c,
            }
            for i, c in enumerate(choices)
        ],
        "argmax_stable": stable,
        "spread": {o: 0.0 for o in options},
    }


def _by_id(fixtures):
    return {f.case_id: f for f in fixtures}


def ideal_judge(fixtures):
    by_id = _by_id(fixtures)
    return lambda case_id, arm, request: truth_reply(by_id[case_id])


def ideal_permute(fixtures):
    by_id = _by_id(fixtures)

    def permute(case_id, arm, question, request):
        choice = truth_reply(by_id[case_id])["answers"][question]["choice"]
        return permute_reply(question, [choice] * 6)

    return permute


@pytest.fixture
def bench(runner, tmp_path, all_fixtures):
    """Runs the benchmark over a fake judge; defaults to a judge that agrees with the ground truth."""

    def go(judge=None, permute=None, fixtures=None):
        return runner.run(
            tmp_path / "out",
            work_dir=tmp_path / "work",
            judge=judge or ideal_judge(all_fixtures),
            permute=permute or ideal_permute(all_fixtures),
            fixtures=fixtures,
        )

    return go


def cases_of(report) -> dict:
    return {c["case_id"]: c for c in report["cases"]}


def of_kind(fixtures, kind, count=None):
    picked = [f for f in fixtures if f.kind == kind]
    return picked if count is None else picked[:count]


class TestCaseSet:
    def test_holds_every_kind_with_enough_distinct_cases(self, all_fixtures):
        counts = Counter(f.kind for f in all_fixtures)

        assert set(counts) == {*INCORRECT_KINDS, CONTROL}
        assert all(counts[kind] >= 10 for kind in INCORRECT_KINDS)
        assert counts[CONTROL] >= 20
        ids = [f.case_id for f in all_fixtures]
        assert len(set(ids)) == len(ids)
        signatures = {
            (f.finding.explanation, tuple((e.file, tuple(e.lines or ())) for e in f.finding.evidence))
            for f in all_fixtures
        }
        assert len(signatures) == len(all_fixtures)

    def test_every_case_states_verdict_severity_and_provenance_ground_truth(self, all_fixtures):
        for f in all_fixtures:
            assert f.verdict in {"real", "not_real"}, f.case_id
            assert f.provenance in {"supported", "unsupported"}, f.case_id
            assert hasattr(f, "severity"), f.case_id
            if f.verdict == "real":
                assert f.severity in SEVERITY_LEVELS, f.case_id

    def test_only_controls_are_real_and_a_wrong_citation_of_a_flaw_real_elsewhere_is_not_real_without_severity_and_unsupported(
        self, all_fixtures
    ):
        assert {(f.verdict, f.provenance) for f in of_kind(all_fixtures, CONTROL)} == {("real", "supported")}
        assert {(f.verdict, f.severity, f.provenance) for f in of_kind(all_fixtures, "real_elsewhere")} == {
            ("not_real", None, "unsupported")
        }
        assert {f.kind for f in all_fixtures if f.verdict == "real"} == {CONTROL}


    def test_live_shaped_cases_cite_three_to_five_items_and_the_claim_quotes_the_code(self, all_fixtures):
        for f in of_kind(all_fixtures, "live_shaped"):
            assert 3 <= len(f.finding.evidence) <= 5, f.case_id
            quoted = [
                line.strip()
                for e in f.finding.evidence
                if e.type == "code"
                for line in e.content.splitlines()
                if len(line.strip()) >= 10
            ]
            assert any(line in f.finding.explanation for line in quoted), f.case_id

    def test_every_cited_file_and_line_range_exists_in_its_case_repository(
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
                    assert 1 <= item.lines[0] <= item.lines[1] <= len(lines), f.case_id
                    text = "\n".join(lines[item.lines[0] - 1 : item.lines[1]])
                assert _squash(item.content) in _squash(text), (f.case_id, item.file or item.source)

    def test_worked_examples_reproduce_no_benchmark_cited_code_or_claim(self, all_fixtures):
        examples = _squash(" ".join(EXAMPLES.values()))

        for f in all_fixtures:
            assert _squash(f.finding.explanation) not in examples, f.case_id
            for item in f.finding.evidence:
                for line in item.content.splitlines():
                    if len(line.strip()) >= 12:
                        assert _squash(line) not in examples, (f.case_id, line)


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


OTHER_FLAW_ROW = "wrong_cwe_other_flaw"


class TestWrongCweOtherFlaw:
    def test_every_wrong_cwe_case_is_not_real_without_severity_and_unsupported(self, all_fixtures):
        wrong = of_kind(all_fixtures, "wrong_cwe")

        assert wrong
        assert {(f.verdict, f.severity, f.provenance) for f in wrong} == {("not_real", None, "unsupported")}

    def test_tagged_cases_are_listed_with_their_tag_and_counted_in_the_sub_row_and_wrong_cwe(
        self, bench, fixtures_mod, all_fixtures
    ):
        tagged = [f for f in all_fixtures if fixtures_mod.OTHER_FLAW in f.tags]
        subset = [*of_kind(all_fixtures, "wrong_cwe"), *of_kind(all_fixtures, CONTROL, 2)]

        report = bench(fixtures=subset)

        assert tagged
        assert all(f.kind == "wrong_cwe" for f in tagged)
        recs = cases_of(report)
        for f in subset:
            assert recs[f.case_id]["tags"] == list(f.tags)
        assert [c["tags"] for c in report["cases"] if c["kind"] == CONTROL] == [[], []]
        for arm in ARMS:
            assert OTHER_FLAW_ROW not in report["cells"][arm]
            assert report["subrows"][arm][OTHER_FLAW_ROW]["cases"] == len(tagged)
            assert report["cells"][arm]["wrong_cwe"]["cases"] == len(of_kind(all_fixtures, "wrong_cwe"))

    def test_a_real_answer_on_tagged_cases_lowers_the_sub_row_verdict_rate(self, bench, fixtures_mod, all_fixtures):
        tagged = [f for f in all_fixtures if fixtures_mod.OTHER_FLAW in f.tags]
        flipped = {f.case_id for f in tagged[:2]}
        by_id = _by_id(tagged)

        def judge(case_id, arm, request):
            if case_id in flipped:
                return kev_reply(supported="yes", verdict="real", severity="high", noul=0.9)
            return truth_reply(by_id[case_id])

        report = bench(judge=judge, fixtures=tagged)

        for arm in ARMS:
            verdict = report["subrows"][arm][OTHER_FLAW_ROW]["verdict"]
            assert (verdict["count"], verdict["n"]) == (len(tagged) - 2, len(tagged))


class TestArms:
    def test_both_arms_judge_the_same_cases_with_only_the_few_shot_arm_carrying_examples(
        self, bench, all_fixtures
    ):
        seen = []

        def judge(case_id, arm, request):
            seen.append((case_id, arm, request))
            return truth_reply(_by_id(all_fixtures)[case_id])

        report = bench(judge=judge)

        ids = {f.case_id for f in all_fixtures}
        assert {c for c, arm, _ in seen if arm == "few_shot"} == ids
        assert {c for c, arm, _ in seen if arm == "zero_shot"} == ids
        assert set(cases_of(report)) == ids
        for rec in report["cases"]:
            assert set(rec["arms"]) == set(ARMS)
        for _, arm, request in seen:
            carries = [
                EXAMPLES[q] in request["questions"][q]["instructions"] for q in EXAMPLES if q in request["questions"]
            ]
            assert all(carries) if arm == "few_shot" else not any(carries)

    def test_every_request_is_a_production_request_with_the_four_questions_and_no_code_only_request(
        self, bench, all_fixtures
    ):
        sent = []
        inner = ideal_judge(all_fixtures)
        inner_permute = ideal_permute(all_fixtures)

        def judge(case_id, arm, request):
            sent.append((arm, request))
            return inner(case_id, arm, request)

        def permute(case_id, arm, question, request):
            sent.append((arm, request))
            return inner_permute(case_id, arm, question, request)

        bench(judge=judge, permute=permute)

        assert {arm for arm, _ in sent} == set(ARMS)
        for _, request in sent:
            assert set(request["questions"]) == ALL_QUESTIONS
            assert request["state"].startswith("Claim:")


class TestResultRecords:
    def test_every_case_and_arm_records_answers_option_scores_noul_and_ground_truth(self, bench, all_fixtures):
        replies = {}

        def judge(case_id, arm, request):
            f = _by_id(all_fixtures)[case_id]
            replies[(case_id, arm)] = truth_reply(f, tokens=1234)
            return replies[(case_id, arm)]

        report = bench(judge=judge)

        by_id = _by_id(all_fixtures)
        for case_id, rec in cases_of(report).items():
            f = by_id[case_id]
            assert rec["kind"] == f.kind
            assert rec["ground_truth"]["verdict"] == f.verdict
            assert rec["ground_truth"]["provenance"] == f.provenance
            assert rec["ground_truth"]["severity"] == f.severity
            for arm in ARMS:
                answers = replies[(case_id, arm)]["answers"]
                got = rec["arms"][arm]
                assert got["status"] == "answered"
                for q in CHOICE_QUESTIONS:
                    assert got["answers"][q] == answers[q]["choice"]
                    assert got["scores"][q] == answers[q]["probabilities"]
                assert got["noul"] == answers[QUESTION_CONFIDENCE]["noul"]

    def test_real_elsewhere_case_is_recorded_with_its_own_kind_and_not_real_unsupported_ground_truth(
        self, bench, all_fixtures
    ):
        elsewhere = of_kind(all_fixtures, "real_elsewhere", 1)[0]
        twin = of_kind(all_fixtures, "safe_twin", 1)[0]
        control = of_kind(all_fixtures, CONTROL, 1)[0]

        report = bench(fixtures=[elsewhere, twin, control])

        recs = cases_of(report)
        assert recs[elsewhere.case_id]["kind"] == "real_elsewhere"
        assert recs[twin.case_id]["kind"] == "safe_twin"
        truth = recs[elsewhere.case_id]["ground_truth"]
        assert (truth["verdict"], truth["severity"], truth["provenance"]) == ("not_real", None, "unsupported")
        assert recs[control.case_id]["ground_truth"]["verdict"] == "real"
        assert recs[control.case_id]["ground_truth"]["provenance"] == "supported"

    def test_every_request_records_the_input_tokens_kev_reported(self, bench, all_fixtures):
        subset = all_fixtures[:3]
        tokens = {f.case_id: 500 + 100 * i for i, f in enumerate(subset)}
        by_id = _by_id(subset)

        report = bench(
            judge=lambda case_id, arm, request: truth_reply(by_id[case_id], tokens=tokens[case_id]),
            fixtures=subset,
        )

        for case_id, rec in cases_of(report).items():
            for arm in ARMS:
                assert rec["arms"][arm]["input_tokens"] == tokens[case_id]

    def test_summary_counts_per_arm_the_requests_reporting_more_than_8192_input_tokens(self, bench, all_fixtures):
        subset = all_fixtures[:4]
        few_shot_tokens = dict(zip((f.case_id for f in subset), (TOKEN_LIMIT, TOKEN_LIMIT + 1, 20_000, 100)))
        by_id = _by_id(subset)

        def judge(case_id, arm, request):
            tokens = few_shot_tokens[case_id] if arm == "few_shot" else 100
            return truth_reply(by_id[case_id], tokens=tokens)

        report = bench(judge=judge, fixtures=subset)

        assert report["input_tokens"]["few_shot"]["requests_over_8192_input_tokens"] == 2
        assert report["input_tokens"]["zero_shot"]["requests_over_8192_input_tokens"] == 0


class TestCellRates:
    def test_cell_rows_of_an_arm_partition_the_cases(self, bench, all_fixtures):
        report = bench()

        for arm in ARMS:
            cells = report["cells"][arm]
            assert set(cells) == {f.kind for f in all_fixtures}
            assert sum(cell["cases"] for cell in cells.values()) == len(all_fixtures)

    def test_cell_states_cases_evaluated_and_errors_for_both_arms(self, bench, all_fixtures):
        kind = "safe_twin"
        subset = of_kind(all_fixtures, kind)

        report = bench(fixtures=subset)

        for arm in ARMS:
            cell = report["cells"][arm][kind]
            assert (cell["cases"], cell["evaluated"], cell["errors"]) == (len(subset), len(subset), 0)

    def test_verdict_and_provenance_rates_carry_count_and_wilson_interval(self, bench, all_fixtures):
        subset = of_kind(all_fixtures, CONTROL, 10)
        by_id = _by_id(subset)
        wrong = {f.case_id for f in subset[:5]}

        def judge(case_id, arm, request):
            f = by_id[case_id]
            if case_id in wrong:
                return kev_reply(supported="no", verdict="not_real", severity="low", noul=0.1)
            return truth_reply(f)

        report = bench(judge=judge, fixtures=subset)

        for arm in ARMS:
            cell = report["cells"][arm][CONTROL]
            for rate in (cell["verdict"], cell["provenance"]):
                assert (rate["count"], rate["n"]) == (5, 10)
                assert rate["wilson"] == pytest.approx([0.2366, 0.7634], abs=0.001)

    def test_rates_of_different_kinds_are_computed_separately(self, bench, all_fixtures):
        controls = of_kind(all_fixtures, CONTROL, 10)
        twins = of_kind(all_fixtures, "safe_twin", 10)
        subset = controls + twins

        report = bench(
            judge=lambda case_id, arm, request: kev_reply(supported="yes", verdict="real", severity="high"),
            fixtures=subset,
        )

        assert report["cells"]["few_shot"][CONTROL]["verdict"]["count"] == 10
        assert report["cells"]["few_shot"]["safe_twin"]["verdict"]["count"] == 0


class TestSeverityScoring:
    def test_real_elsewhere_cases_stay_out_of_the_severity_figures(self, bench, all_fixtures):
        controls = of_kind(all_fixtures, CONTROL, 4)
        elsewhere = of_kind(all_fixtures, "real_elsewhere", 4)

        report = bench(
            judge=lambda case_id, arm, request: kev_reply(supported="yes", verdict="real", severity="critical"),
            fixtures=[*controls, *elsewhere],
        )

        for arm in ARMS:
            assert report["severity"][arm]["n"] == len(controls)
            assert report["cells"][arm]["real_elsewhere"]["verdict"]["count"] == 0
            assert report["cells"][arm]["real_elsewhere"]["verdict"]["n"] == len(elsewhere)

    def test_severity_is_scored_in_levels_over_real_verdict_cases_only(self, bench, all_fixtures):
        real = of_kind(all_fixtures, CONTROL, 4)
        not_real = [f for f in all_fixtures if f.verdict == "not_real"][:3]
        offsets = dict(zip((f.case_id for f in real), (0, 0, 1, 2)))
        by_id = _by_id([*real, *not_real])

        def judge(case_id, arm, request):
            f = by_id[case_id]
            if f.verdict == "not_real":
                return kev_reply(severity="critical", verdict="not_real", supported="no", noul=0.1)
            index = SEVERITY_LEVELS.index(f.severity)
            step = offsets[case_id]
            shifted = index + step if index + step < len(SEVERITY_LEVELS) else index - step
            return kev_reply(severity=SEVERITY_LEVELS[shifted])

        report = bench(judge=judge, fixtures=[*real, *not_real])

        for arm in ARMS:
            severity = report["severity"][arm]
            assert severity["n"] == 4
            assert severity["mae"] == pytest.approx(0.75)
            assert (severity["exact"]["count"], severity["exact"]["n"]) == (2, 4)
            assert (severity["within_one"]["count"], severity["within_one"]["n"]) == (3, 4)
            assert len(severity["exact"]["wilson"]) == 2


ORDER_SCENARIOS = [
    pytest.param(["a", "b", "b", "b", "b", "b"], True, "b", True, id="runs-disagree-with-plain-answer"),
    pytest.param(["b"] * 6, True, "a", False, id="runs-agree-only-plain-answer-differs"),
    pytest.param(["a"] * 6, False, "a", True, id="argmax-not-stable"),
    pytest.param(["a"] * 6, True, "a", False, id="everything-agrees"),
]


class TestOrderSensitivity:
    @pytest.mark.parametrize("question", CHOICE_QUESTIONS)
    @pytest.mark.parametrize(("runs", "stable", "plain", "sensitive"), ORDER_SCENARIOS)
    def test_each_choice_question_is_scored_on_its_own_permute_runs(
        self, bench, all_fixtures, question, runs, stable, plain, sensitive
    ):
        target = all_fixtures[0]
        first, second = OPTIONS[question][:2]
        pick = {"a": first, "b": second}
        base = ideal_permute(all_fixtures)

        def judge(case_id, arm, request):
            reply = truth_reply(target)
            reply["answers"][question] = _choice(question, pick[plain])
            return reply

        def permute(case_id, arm, q, request):
            if q == question:
                return permute_reply(q, [pick[r] for r in runs], stable=stable)
            return base(case_id, arm, q, request)

        report = bench(judge=judge, permute=permute, fixtures=[target])

        for arm in ARMS:
            scored = cases_of(report)[target.case_id]["arms"][arm]["permute"]
            assert scored[question]["order_sensitive"] is sensitive
            for other in set(CHOICE_QUESTIONS) - {question}:
                assert scored[other]["order_sensitive"] is False

    def test_plain_route_instability_is_reported_apart_from_order_sensitivity(self, bench, all_fixtures):
        target = all_fixtures[0]
        first, second = OPTIONS[QUESTION_VERDICT]

        def judge(case_id, arm, request):
            reply = truth_reply(target)
            reply["answers"][QUESTION_VERDICT] = _choice(QUESTION_VERDICT, first)
            return reply

        def permute(case_id, arm, q, request):
            choice = second if q == QUESTION_VERDICT else truth_reply(target)["answers"][q]["choice"]
            return permute_reply(q, [choice] * 6)

        report = bench(judge=judge, permute=permute, fixtures=[target])

        scored = cases_of(report)[target.case_id]["arms"]["few_shot"]["permute"][QUESTION_VERDICT]
        assert scored["plain_unstable"] is True
        assert scored["order_sensitive"] is False

    def test_every_permute_run_is_recorded_with_order_probabilities_choice_stability_and_spread(
        self, bench, all_fixtures
    ):
        target = all_fixtures[0]
        replies = {}

        def permute(case_id, arm, q, request):
            first, second = OPTIONS[q][:2]
            replies[(arm, q)] = permute_reply(q, [first, second, first, second, first, second], stable=False)
            replies[(arm, q)]["spread"] = {o: 0.25 for o in OPTIONS[q]}
            return replies[(arm, q)]

        report = bench(permute=permute, fixtures=[target])

        for arm in ARMS:
            recorded = cases_of(report)[target.case_id]["arms"][arm]["permute"]
            assert set(recorded) == set(CHOICE_QUESTIONS)
            for q in CHOICE_QUESTIONS:
                assert recorded[q]["runs"] == replies[(arm, q)]["runs"]
                assert recorded[q]["argmax_stable"] is False
                assert recorded[q]["spread"] == replies[(arm, q)]["spread"]


class TestErrorsAndLimits:
    @pytest.mark.parametrize("failure", [RuntimeError("kev unreachable"), TimeoutError("kev timed out")])
    def test_failed_calls_are_errors_with_their_reason_while_other_cases_are_still_scored_and_exit_is_non_zero(
        self, runner, tmp_path, all_fixtures, failure
    ):
        failing = {f.case_id for f in all_fixtures[:3]}
        inner = ideal_judge(all_fixtures)

        def judge(case_id, arm, request):
            if case_id in failing and arm == "few_shot":
                raise failure
            return inner(case_id, arm, request)

        out = tmp_path / "out"
        code = runner.main(
            ["--out", str(out), "--work-dir", str(tmp_path / "work")],
            judge=judge,
            permute=ideal_permute(all_fixtures),
        )

        report = json.loads((out / "report.json").read_text())
        recs = cases_of(report)
        for case_id in failing:
            got = recs[case_id]["arms"]["few_shot"]
            assert got["status"] == "error"
            assert str(failure) in got["reason"]
            assert recs[case_id]["arms"]["zero_shot"]["status"] == "answered"
        assert all(
            recs[c]["arms"]["few_shot"]["status"] == "answered" for c in recs if c not in failing
        )
        cells = report["cells"]["few_shot"].values()
        errors = sum(cell["errors"] for cell in cells)
        evaluated = sum(cell["evaluated"] for cell in cells)
        assert errors == 3
        assert evaluated == len(all_fixtures) - 3
        assert code != 0

    def test_failed_calls_are_never_scored_as_answers(self, bench, all_fixtures):
        subset = of_kind(all_fixtures, CONTROL, 10)

        def judge(case_id, arm, request):
            raise ConnectionRefusedError("kev unreachable")

        report = bench(judge=judge, fixtures=subset)

        for arm in ARMS:
            cell = report["cells"][arm][CONTROL]
            assert (cell["errors"], cell["evaluated"]) == (10, 0)
            assert cell["verdict"]["count"] == 0
            assert cell["verdict"]["n"] == 0

    def test_run_where_the_judge_is_unreachable_exits_non_zero(self, runner, tmp_path, all_fixtures):
        def judge(case_id, arm, request):
            raise ConnectionRefusedError("kev unreachable")

        code = runner.main(
            ["--out", str(tmp_path / "out"), "--work-dir", str(tmp_path / "work")],
            judge=judge,
            permute=ideal_permute(all_fixtures),
        )

        assert code != 0

    def test_run_where_the_permute_route_is_missing_exits_non_zero_with_the_plain_answers_scored(
        self, runner, tmp_path, all_fixtures
    ):
        def permute(case_id, arm, question, request):
            raise OSError("HTTP Error 404: Not Found")

        out = tmp_path / "out"
        code = runner.main(
            ["--out", str(out), "--work-dir", str(tmp_path / "work")],
            judge=ideal_judge(all_fixtures),
            permute=permute,
        )

        assert code != 0
        report = json.loads((out / "report.json").read_text())
        rec = report["cases"][0]["arms"]["few_shot"]
        assert rec["answers"][QUESTION_VERDICT] in OPTIONS[QUESTION_VERDICT]

    def test_request_over_the_length_limit_is_recorded_as_too_large_counted_in_its_cell_and_the_run_continues(
        self, bench, all_fixtures
    ):
        import copy

        subset = of_kind(all_fixtures, CONTROL, 5)
        oversized = copy.deepcopy(subset[0])
        oversized.finding.explanation = "x" * 30_000
        subset[0] = oversized
        judged = []
        inner = ideal_judge(all_fixtures)

        def judge(case_id, arm, request):
            judged.append(case_id)
            return inner(case_id, arm, request)

        report = bench(judge=judge, fixtures=subset)

        assert oversized.case_id not in judged
        for arm in ARMS:
            got = cases_of(report)[oversized.case_id]["arms"][arm]
            assert got["status"] == "too_large"
            assert not got.get("answers")
            cell = report["cells"][arm][CONTROL]
            assert (cell["cases"], cell["too_large"], cell["evaluated"], cell["errors"]) == (5, 1, 4, 0)

    def test_finding_failing_evidence_validation_is_reported_apart_and_never_judged(self, bench, all_fixtures):
        import copy

        subset = of_kind(all_fixtures, CONTROL, 3)
        broken = copy.deepcopy(subset[0])
        next(e for e in broken.finding.evidence if e.type == "code").lines = [9000, 9001]
        subset[0] = broken
        judged = set()
        inner = ideal_judge(all_fixtures)

        def judge(case_id, arm, request):
            judged.add(case_id)
            return inner(case_id, arm, request)

        report = bench(judge=judge, fixtures=subset)

        assert broken.case_id not in judged
        assert report["evidence_failures"] == [broken.case_id]


class _Response(io.BytesIO):
    pass


class _FakeOpener:
    def __init__(self, log):
        self.log = log

    def open(self, request, timeout=None):
        body = json.loads(request.data)
        self.log.append((request.full_url, body))
        if request.full_url.endswith("/permute"):
            question = body["question"]
            first = next(iter(body["request"]["questions"][question]["criteria"]))
            reply = permute_reply(question, [first] * 2)
            reply["runs"] = [{**run, "probabilities": {first: 1.0}} for run in reply["runs"]]
        else:
            reply = kev_reply(supported="yes", verdict="real", severity="low", noul=0.5)
        return _Response(json.dumps(reply).encode())


class TestEntryPoint:
    def test_writes_report_to_a_new_output_directory_and_leaves_existing_results_alone(
        self, runner, tmp_path, all_fixtures
    ):
        old = tmp_path / "results" / "old.json"
        old.parent.mkdir()
        old.write_text('{"keep": true}')
        out = tmp_path / "runs" / "kev-support"

        code = runner.main(
            ["--out", str(out), "--work-dir", str(tmp_path / "work")],
            judge=ideal_judge(all_fixtures),
            permute=ideal_permute(all_fixtures),
        )

        assert code == 0
        report = json.loads((out / "report.json").read_text())
        assert {c["case_id"] for c in report["cases"]} == {f.case_id for f in all_fixtures}
        assert old.read_text() == '{"keep": true}'
        assert [p for p in tmp_path.iterdir() if p.name not in {"results", "runs", "work"}] == []

    def test_contacts_only_the_judge_endpoint_from_the_judge_settings(self, runner, tmp_path, monkeypatch):
        from lgtm.config import LGTMConfig

        endpoint = LGTMConfig().judge_endpoint.rstrip("/")
        log = []
        monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener(log))

        code = runner.main(["--out", str(tmp_path / "out"), "--work-dir", str(tmp_path / "work")])

        assert code == 0
        assert {url for url, _ in log} == {f"{endpoint}/v1/systemone", f"{endpoint}/v1/systemone/permute"}
        permute_bodies = [body for url, body in log if url.endswith("/permute")]
        assert permute_bodies
        assert all("request" in body and body["n_perm"] == 6 for body in permute_bodies)
        assert all(body["question"] in CHOICE_QUESTIONS for body in permute_bodies)
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


CLASS_PATTERNS = {
    22: r"path traversal|base directory|\.\./",
    78: r"shell command|command injection",
    79: r"cross-site scripting|\bxss\b|without (output )?encoding",
    94: r"code injection|\beval\b",
    200: r"sensitive (data|information) (is )?(exposed|returned)",
    285: r"improper authorization",
    287: r"improper authentication",
    306: r"without (any )?authentication",
    352: r"\bcsrf\b|cross-site request forgery",
    502: r"deserializ",
    611: r"xml external|\bxxe\b",
    639: r"invoice|changing the id|id in the url",
    798: r"hard-?coded (credential|secret|password)",
    862: r"without (any )?authorization",
    918: r"\bssrf\b|server-side request forgery",
}
SCENARIO_QUESTIONS = ("verdict", "severity")
SHARED_CLAIM_WORDS = 3
_STOP = set(
    "the a an of to in is are be by with no not any that this it its as on for from and or so can into without "
    "which who every user caller supplied check result yet name claim answer example answers real".split()
)


def _cwe_number(cwe_id) -> int | None:
    found = re.search(r"\d+", str(cwe_id or ""))
    return int(found.group()) if found else None


def _stems(text: str) -> set[str]:
    stems = set()
    for word in re.findall(r"[a-z]+", text.lower()):
        if len(word) < 4 or word in _STOP:
            continue
        for suffix in ("ing", "ed", "es", "s"):
            if word.endswith(suffix) and len(word) - len(suffix) >= 4:
                word = word[: -len(suffix)]
                break
        stems.add(word)
    return stems


def reproduced_cases(example: str, fixtures) -> list[str]:
    """Case ids whose weakness class or claim scenario the example restates."""
    text = _squash(example)
    covered = {_cwe_number(f.finding.cwe_id) for f in fixtures}
    classes = {cwe for cwe, pattern in CLASS_PATTERNS.items() if re.search(pattern, text) and cwe in covered}
    hits = []
    for f in fixtures:
        shared = _stems(text) & _stems(f.finding.explanation)
        if _cwe_number(f.finding.cwe_id) in classes or len(shared) >= SHARED_CLAIM_WORDS:
            hits.append(f.case_id)
    return hits


RETIRED_EXAMPLES = {
    "old C": "Example C. A download handler joins a user supplied name onto the base directory with no "
    "check that the result stays inside it, and the claim names path traversal. Answer: real.",
    "old E": "Example E. Any visitor can read every customer invoice by changing the id in the URL. "
    "Answer: critical.",
}


class TestWorkedExamplesAreDistinctFromTheCaseSet:
    @pytest.mark.parametrize("name", RETIRED_EXAMPLES)
    def test_detector_flags_the_retired_examples_that_restated_a_case(self, name, all_fixtures):
        assert reproduced_cases(RETIRED_EXAMPLES[name], all_fixtures)

    @pytest.mark.parametrize("question", SCENARIO_QUESTIONS)
    @pytest.mark.parametrize("letter_text", range(2))
    def test_no_example_restates_the_weakness_or_scenario_of_a_benchmark_case(
        self, question, letter_text, all_fixtures
    ):
        example = re.split(r"\n(?=Example )", EXAMPLES[question])[1 + letter_text]

        assert reproduced_cases(example, all_fixtures) == [], example


class TestKevReplyWithoutInputTokens:
    @pytest.mark.parametrize("usage", [None, {}, {"output_tokens": 0}], ids=["no_usage", "empty_usage", "no_input_tokens"])
    def test_records_none_and_the_case_stays_answered_and_the_summary_still_computes(
        self, usage, bench, all_fixtures
    ):
        subset = all_fixtures[:3]
        silent = subset[0].case_id
        by_id = _by_id(subset)

        def judge(case_id, arm, request):
            reply = truth_reply(by_id[case_id], tokens=TOKEN_LIMIT + 1 if arm == "few_shot" else 100)
            if case_id == silent:
                reply.pop("usage")
                if usage is not None:
                    reply["usage"] = usage
            return reply

        report = bench(judge=judge, fixtures=subset)

        silent_arms = cases_of(report)[silent]["arms"]
        for arm in ARMS:
            assert silent_arms[arm]["status"] == "answered"
            assert silent_arms[arm]["input_tokens"] is None
            assert report["cells"][arm]
        assert report["input_tokens"]["few_shot"] == {"n": 2, "requests_over_8192_input_tokens": 2}
        assert report["input_tokens"]["zero_shot"] == {"n": 2, "requests_over_8192_input_tokens": 0}

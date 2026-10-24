"""Unit tests for the confidence scoring of the Kev validation benchmark (benchmark/kev_support/confidence.py):
Brier score, clipped log loss, expected calibration error, mean probability on the correct option, AUROC of
provenance_confidence, the headline score, and metrics left out of reports that lack their inputs. Reports
are hand-built dicts with hand-computed expectations; nothing reaches a judge, a network or a cluster.

Expected interface: `kev_support.confidence.score(report) -> dict` over a report.json-shaped dict, with
    epsilon                                     1e-6
    metrics[arm][question]["all" | "kinds"][kind]  question in verdict, supported, provenance, severity;
                                                   metric keys brier, log_loss, ece, mean_prob_correct, excluded
    auroc[arm]["all"], auroc[arm]["kinds"][kind]  float, None when only one class is present
    headline[arm]                               mean Brier of verdict, provenance and severity
    left_out                                    list of {"question", "reason"}; a left-out question has no
                                                entry in metrics[arm]
"""

from __future__ import annotations

import importlib
import math
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.validation.judge import (
    QUESTION_CONFIDENCE,
    QUESTION_SEVERITY,
    QUESTION_SUPPORT,
    QUESTION_VERDICT,
)

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

LEVELS = ("low", "medium", "high", "critical")
APPROX = {"abs": 1e-9}


@pytest.fixture(scope="module")
def confidence():
    return importlib.import_module("kev_support.confidence")


def _rec(verdict: dict, supported: dict, severity: dict, noul: float) -> dict:
    return {
        "status": "answered",
        "reason": "",
        "answers": {
            QUESTION_VERDICT: max(verdict, key=verdict.get),
            QUESTION_SUPPORT: max(supported, key=supported.get),
            QUESTION_SEVERITY: max(severity, key=severity.get),
        },
        "scores": {QUESTION_VERDICT: verdict, QUESTION_SUPPORT: supported, QUESTION_SEVERITY: severity},
        "noul": noul,
    }


def _case(case_id, kind, verdict, provenance, severity, arms) -> dict:
    return {
        "case_id": case_id,
        "kind": kind,
        "tags": [],
        "ground_truth": {"verdict": verdict, "provenance": provenance, "severity": severity},
        "arms": arms,
    }


def _v(real: float) -> dict:
    return {"real": real, "not_real": round(1 - real, 10)}


def _s(yes: float) -> dict:
    return {"yes": yes, "no": round(1 - yes, 10)}


UNIFORM = {level: 0.25 for level in LEVELS}
SKEWED = {"low": 0.7, "medium": 0.1, "high": 0.1, "critical": 0.1}


def _fixture_report() -> dict:
    """Two arms; c1 and c2 are controls, c3 a safe_twin, c4 a real_elsewhere, c5 an errored safe_twin and
    c6 a too-large control. The zero_shot arm gives probability 0.12 to the correct verdict everywhere."""
    few = {
        "c1": _rec(_v(0.85), _s(0.92), {"low": 0.06, "medium": 0.08, "high": 0.82, "critical": 0.04}, 0.88),
        "c2": _rec(_v(0.35), _s(0.55), {"low": 0.46, "medium": 0.30, "high": 0.14, "critical": 0.10}, 0.62),
        "c3": _rec(_v(0.25), _s(0.15), UNIFORM, 0.08),
        "c4": _rec(_v(0.95), _s(0.65), SKEWED, 0.72),
    }
    zero = {
        "c1": _rec(_v(0.12), _s(0.92), few["c1"]["scores"][QUESTION_SEVERITY], 0.88),
        "c2": _rec(_v(0.12), _s(0.55), few["c2"]["scores"][QUESTION_SEVERITY], 0.62),
        "c3": _rec(_v(0.88), _s(0.15), UNIFORM, 0.08),
        "c4": _rec(_v(0.12), _s(0.65), SKEWED, 0.72),
    }
    truth = {
        "c1": ("control", "real", "supported", "high"),
        "c2": ("control", "real", "supported", "low"),
        "c3": ("safe_twin", "not_real", "unsupported", None),
        "c4": ("real_elsewhere", "real", "unsupported", "critical"),
    }
    cases = [
        _case(cid, kind, verdict, prov, sev, {"few_shot": few[cid], "zero_shot": zero[cid]})
        for cid, (kind, verdict, prov, sev) in truth.items()
    ]
    errored = {"status": "error", "reason": "ConnectionError: refused"}
    large = {"status": "too_large", "reason": "request over the limit"}
    cases.append(_case("c5", "safe_twin", "not_real", "unsupported", None, {"few_shot": errored, "zero_shot": errored}))
    cases.append(_case("c6", "control", "real", "supported", "medium", {"few_shot": large, "zero_shot": large}))
    return {"arms": ["few_shot", "zero_shot"], "cases": cases}


def _mean_ll(*correct_probs: float) -> float:
    return -sum(math.log(p) for p in correct_probs) / len(correct_probs)


ALL_FEW_SHOT = {
    "verdict": dict(brier=0.255, log_loss=_mean_ll(0.85, 0.35, 0.75, 0.95), ece=0.275, mean_prob_correct=0.725, excluded=2),
    "supported": dict(brier=0.32695, log_loss=_mean_ll(0.92, 0.55, 0.85, 0.35), ece=0.3325, mean_prob_correct=0.6675, excluded=2),
    "provenance": dict(brier=0.3418, log_loss=_mean_ll(0.88, 0.62, 0.92, 0.28), ece=0.325, mean_prob_correct=0.675, excluded=2),
    "severity": dict(brier=0.2276, log_loss=_mean_ll(0.82, 0.46), ece=0.36, mean_prob_correct=0.64),
}

VERDICT_FEW_SHOT_BY_KIND = {
    "control": dict(brier=0.445, log_loss=_mean_ll(0.85, 0.35), ece=0.4, mean_prob_correct=0.6, excluded=1),
    "safe_twin": dict(brier=0.125, log_loss=_mean_ll(0.75), ece=0.25, mean_prob_correct=0.75, excluded=1),
    "real_elsewhere": dict(brier=0.005, log_loss=_mean_ll(0.95), ece=0.05, mean_prob_correct=0.95, excluded=0),
}


def _check(got: dict, expected: dict) -> None:
    for name, value in expected.items():
        assert got[name] == pytest.approx(value, **APPROX), name


class TestPerQuestionMetrics:
    @pytest.mark.parametrize("question", list(ALL_FEW_SHOT))
    def test_arm_metrics_equal_hand_computed_values(self, confidence, question):
        got = confidence.score(_fixture_report())["metrics"]["few_shot"][question]["all"]

        _check(got, ALL_FEW_SHOT[question])

    @pytest.mark.parametrize("kind", list(VERDICT_FEW_SHOT_BY_KIND))
    def test_verdict_metrics_per_kind_equal_hand_computed_values(self, confidence, kind):
        got = confidence.score(_fixture_report())["metrics"]["few_shot"]["verdict"]["kinds"][kind]

        _check(got, VERDICT_FEW_SHOT_BY_KIND[kind])

    def test_each_arm_is_scored_from_its_own_records(self, confidence):
        metrics = confidence.score(_fixture_report())["metrics"]

        assert metrics["zero_shot"]["verdict"]["all"]["brier"] == pytest.approx(2 * 0.88**2, **APPROX)
        assert metrics["few_shot"]["verdict"]["all"]["brier"] == pytest.approx(0.255, **APPROX)

    def test_severity_is_scored_on_control_cases_only(self, confidence):
        severity = confidence.score(_fixture_report())["metrics"]["few_shot"]["severity"]

        assert set(severity["kinds"]) == {"control"}
        assert severity["kinds"]["control"]["excluded"] == 1
        _check(severity["kinds"]["control"], ALL_FEW_SHOT["severity"])

    def test_calibration_bins_pool_cases_with_equal_width_bins(self, confidence):
        same_bin = [
            _case("a", "control", "real", "supported", "low", {"few_shot": _rec(_v(0.81), _s(0.9), UNIFORM, 0.9)}),
            _case("b", "control", "real", "supported", "low", {"few_shot": _rec(_v(0.11), _s(0.9), UNIFORM, 0.9)}),
        ]
        # top probabilities 0.81 (right) and 0.89 (wrong) share bin [0.8, 0.9): confidence 0.85, accuracy 0.5
        report = {"arms": ["few_shot"], "cases": same_bin}

        got = confidence.score(report)["metrics"]["few_shot"]["verdict"]["all"]["ece"]

        assert got == pytest.approx(0.35, **APPROX)

    def test_top_probability_of_one_falls_in_the_last_bin(self, confidence):
        last_bin = [
            _case("a", "control", "real", "supported", "low", {"few_shot": _rec(_v(0.0), _s(0.9), UNIFORM, 0.9)}),
            _case("b", "control", "real", "supported", "low", {"few_shot": _rec(_v(0.91), _s(0.9), UNIFORM, 0.9)}),
        ]
        # 1.0 (wrong) and 0.91 (right) share bin [0.9, 1.0]: confidence 0.955, accuracy 0.5
        got = confidence.score({"arms": ["few_shot"], "cases": last_bin})["metrics"]["few_shot"]["verdict"]["all"]["ece"]

        assert got == pytest.approx(0.455, **APPROX)


class TestLogLossClipping:
    def test_zero_probability_on_the_correct_option_is_clipped_at_epsilon(self, confidence):
        case = _case("z", "control", "real", "supported", "low", {"few_shot": _rec({"real": 0.0, "not_real": 1.0}, _s(0.9), UNIFORM, 0.9)})
        result = confidence.score({"arms": ["few_shot"], "cases": [case]})

        verdict = result["metrics"]["few_shot"]["verdict"]["all"]
        assert result["epsilon"] == 1e-6
        assert verdict["log_loss"] == pytest.approx(-math.log(1e-6), **APPROX)
        assert verdict["brier"] == pytest.approx(2.0, **APPROX)


def _auroc_case(case_id, kind, supported, noul):
    probs = _rec(_v(0.6), _s(0.6), UNIFORM, noul)
    return _case(case_id, kind, "real", "supported" if supported else "unsupported", "low", {"few_shot": probs})


class TestAuroc:
    def test_arm_and_kind_auroc_equal_hand_computed_values(self, confidence):
        auroc = confidence.score(_fixture_report())["auroc"]["few_shot"]

        # positives 0.88, 0.62; negatives 0.08 (safe_twin), 0.72 (real_elsewhere)
        assert auroc["all"] == pytest.approx(0.75, **APPROX)
        assert auroc["kinds"]["safe_twin"] == pytest.approx(1.0, **APPROX)
        assert auroc["kinds"]["real_elsewhere"] == pytest.approx(0.5, **APPROX)

    def test_tied_scores_count_half(self, confidence):
        cases = [
            _auroc_case("p1", "control", True, 0.5),
            _auroc_case("p2", "control", True, 0.7),
            _auroc_case("n1", "safe_twin", False, 0.5),
            _auroc_case("n2", "safe_twin", False, 0.3),
        ]

        got = confidence.score({"arms": ["few_shot"], "cases": cases})["auroc"]["few_shot"]["all"]

        assert got == pytest.approx(0.875, **APPROX)

    def test_single_class_auroc_is_unavailable(self, confidence):
        cases = [_auroc_case("p1", "control", True, 0.9), _auroc_case("p2", "control", True, 0.6)]

        got = confidence.score({"arms": ["few_shot"], "cases": cases})["auroc"]["few_shot"]["all"]

        assert got is None


class TestHeadline:
    def test_headline_is_mean_of_verdict_provenance_and_severity_brier(self, confidence):
        headline = confidence.score(_fixture_report())["headline"]["few_shot"]

        # (0.255 + 0.3418 + 0.2276) / 3; the supported question is not part of it
        assert headline == pytest.approx(0.2748, **APPROX)


class TestLeftOutMetrics:
    def _without(self, mutate):
        report = _fixture_report()
        for case in report["cases"]:
            for arm in case["arms"].values():
                if arm["status"] == "answered":
                    mutate(case, arm)
        return report

    @pytest.mark.parametrize(
        ("question", "mutate"),
        [
            ("supported", lambda case, arm: arm["scores"].pop(QUESTION_SUPPORT)),
            ("severity", lambda case, arm: case["ground_truth"].pop("severity", None)),
        ],
        ids=["option-distribution-missing", "ground-truth-missing"],
    )
    def test_unscorable_question_is_stated_left_out_and_never_estimated(self, confidence, question, mutate):
        result = confidence.score(self._without(mutate))

        assert any(e["question"] == question and e["reason"] for e in result["left_out"])
        for arm in ("few_shot", "zero_shot"):
            assert question not in result["metrics"][arm]
            assert result["metrics"][arm]["verdict"]["all"]["brier"] is not None

    def test_computable_metrics_keep_their_values_when_another_is_left_out(self, confidence):
        result = confidence.score(self._without(lambda case, arm: arm["scores"].pop(QUESTION_SUPPORT)))

        _check(result["metrics"]["few_shot"]["verdict"]["all"], ALL_FEW_SHOT["verdict"])
        assert result["auroc"]["few_shot"]["all"] == pytest.approx(0.75, **APPROX)


class TestExistingAccuracyMetrics:
    def test_accuracy_metrics_are_unchanged_by_confidence_scoring(self, tmp_path, monkeypatch):
        runner = importlib.import_module("kev_support.runner")
        monkeypatch.setattr(runner, "build_repos", lambda work_dir: {"shop": Path(work_dir)})
        monkeypatch.setattr(runner, "EvidenceValidator", lambda path, rev: SimpleNamespace(read_cited_code=None))
        monkeypatch.setattr(runner, "evidence_issues", lambda fixture, repo: [])
        options = {
            QUESTION_SUPPORT: ("yes", "no"),
            QUESTION_VERDICT: ("real", "not_real"),
            QUESTION_SEVERITY: LEVELS,
        }
        monkeypatch.setattr(
            runner,
            "build_judge_request",
            lambda *args, **kwargs: {"questions": {q: {"criteria": {o: "" for o in opts}} for q, opts in options.items()}},
        )
        # case_id -> (verdict answer, severity answer, noul)
        answers = {
            "control-1": ("real", "medium", 0.9),
            "twin-1": ("real", "low", 0.9),
            "elsewhere-1": ("real", "critical", 0.2),
        }

        def judge(case_id, arm, request):
            verdict, severity, noul = answers[case_id]
            pick = {QUESTION_SUPPORT: "yes", QUESTION_VERDICT: verdict, QUESTION_SEVERITY: severity}
            replies = {
                q: {"choice": pick[q], "probabilities": {o: 1.0 if o == pick[q] else 0.0 for o in options[q]}}
                for q in options
            }
            return {"answers": {**replies, QUESTION_CONFIDENCE: {"noul": noul}}, "usage": {"input_tokens": 10}}

        def permute(case_id, arm, question, request):
            return {"runs": [{"choice": options[question][0]}], "argmax_stable": True, "spread": {}}

        def fixture(case_id, kind, verdict, severity, provenance):
            return SimpleNamespace(
                case_id=case_id, kind=kind, repo="shop", finding=SimpleNamespace(), verdict=verdict,
                severity=severity, provenance=provenance, tags=(),
            )

        fixtures = [
            fixture("control-1", "control", "real", "high", "supported"),
            fixture("twin-1", "safe_twin", "not_real", None, "unsupported"),
            fixture("elsewhere-1", "real_elsewhere", "real", "critical", "unsupported"),
        ]

        report = runner.run(tmp_path / "out", work_dir=tmp_path / "work", judge=judge, permute=permute, fixtures=fixtures)

        for arm in ("few_shot", "zero_shot"):
            cells = report["cells"][arm]
            assert [cells[k]["evaluated"] for k in ("control", "safe_twin", "real_elsewhere")] == [1, 1, 1]
            assert [(cells[k]["verdict"]["count"], cells[k]["verdict"]["n"]) for k in ("control", "safe_twin", "real_elsewhere")] == [(1, 1), (0, 1), (1, 1)]
            assert [(cells[k]["provenance"]["count"], cells[k]["provenance"]["n"]) for k in ("control", "safe_twin", "real_elsewhere")] == [(1, 1), (0, 1), (1, 1)]
            severity = report["severity"][arm]
            assert (severity["n"], severity["mae"]) == (2, 0.5)
            assert (severity["exact"]["count"], severity["within_one"]["count"]) == (1, 2)

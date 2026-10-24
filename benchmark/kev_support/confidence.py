"""Confidence scoring of a Kev bench report: Brier score, clipped log loss, expected calibration error, mean
probability on the correct option and AUROC of provenance_confidence, computed from recorded option probabilities."""

from __future__ import annotations

import math
from collections.abc import Callable

from lgtm.validation.judge import QUESTION_SEVERITY, QUESTION_SUPPORT, QUESTION_VERDICT

EPSILON = 1e-6
BINS = 10
CONTROL = "control"
QUESTIONS = ("verdict", "supported", "provenance", "severity")
HEADLINE_QUESTIONS = ("verdict", "provenance", "severity")


def _choice(key: str, truth_key: str) -> Callable[[dict, dict], tuple[dict | None, str | None]]:
    def get(case: dict, rec: dict) -> tuple[dict | None, str | None]:
        probs = (rec.get("scores") or {}).get(key)
        truth = case["ground_truth"].get(truth_key)
        return (probs, truth) if isinstance(probs, dict) and truth in probs else (None, None)

    return get


def _supported(case: dict, rec: dict) -> tuple[dict | None, str | None]:
    probs = (rec.get("scores") or {}).get(QUESTION_SUPPORT)
    provenance = case["ground_truth"].get("provenance")
    truth = None if provenance is None else ("yes" if provenance == "supported" else "no")
    return (probs, truth) if isinstance(probs, dict) and truth in probs else (None, None)


def _provenance(case: dict, rec: dict) -> tuple[dict | None, str | None]:
    noul, provenance = rec.get("noul"), case["ground_truth"].get("provenance")
    if noul is None or provenance is None:
        return None, None
    return {"supported": noul, "unsupported": 1 - noul}, provenance


EXTRACT = {
    "verdict": _choice(QUESTION_VERDICT, "verdict"),
    "supported": _supported,
    "provenance": _provenance,
    "severity": _choice(QUESTION_SEVERITY, "severity"),
}


def _metrics(pairs: list[tuple[dict, str]], excluded: int) -> dict:
    n = len(pairs)
    if not n:
        return {"brier": None, "log_loss": None, "ece": None, "mean_prob_correct": None, "excluded": excluded}
    bins: dict[int, list[tuple[float, bool]]] = {}
    for probs, truth in pairs:
        top = max(probs, key=probs.get)
        index = min(int(probs[top] * BINS), BINS - 1)
        bins.setdefault(index, []).append((probs[top], top == truth))
    return {
        "brier": sum(sum((p - (o == truth)) ** 2 for o, p in probs.items()) for probs, truth in pairs) / n,
        "log_loss": sum(-math.log(max(probs[truth], EPSILON)) for probs, truth in pairs) / n,
        "ece": sum(len(b) * abs(sum(c for c, _ in b) / len(b) - sum(ok for _, ok in b) / len(b)) for b in bins.values()) / n,
        "mean_prob_correct": sum(probs[truth] for probs, truth in pairs) / n,
        "excluded": excluded,
    }


def _auroc(points: list[tuple[float, bool]]) -> float | None:
    positives = [s for s, supported in points if supported]
    negatives = [s for s, supported in points if not supported]
    if not positives or not negatives:
        return None
    wins = sum((p > q) + 0.5 * (p == q) for p in positives for q in negatives)
    return wins / (len(positives) * len(negatives))


def _points(cases: list[dict], arm: str) -> list[tuple[float, bool]]:
    points = []
    for case in cases:
        rec, provenance = case["arms"][arm], case["ground_truth"].get("provenance")
        if rec["status"] == "answered" and rec.get("noul") is not None and provenance is not None:
            points.append((rec["noul"], provenance == "supported"))
    return points


def score(report: dict) -> dict:
    cases, arms = report["cases"], report["arms"]
    kinds = list(dict.fromkeys(c["kind"] for c in cases))
    result: dict = {"epsilon": EPSILON, "metrics": {}, "auroc": {}, "headline": {}, "left_out": []}
    for arm in arms:
        result["metrics"][arm] = {}
        for question in QUESTIONS:
            scope = [c for c in cases if c["kind"] == CONTROL] if question == "severity" else cases
            pairs: dict[str, list] = {}
            excluded: dict[str, int] = {}
            for case in scope:
                rec, kind = case["arms"][arm], case["kind"]
                pair = EXTRACT[question](case, rec) if rec["status"] == "answered" else (None, None)
                if pair[0] is None:
                    excluded[kind] = excluded.get(kind, 0) + 1
                else:
                    pairs.setdefault(kind, []).append(pair)
            scored = [p for ps in pairs.values() for p in ps]
            if not scored:
                result["left_out"].append(
                    {
                        "arm": arm,
                        "question": question,
                        "reason": "no answered case has the option probabilities and ground truth this question needs",
                    }
                )
                continue
            result["metrics"][arm][question] = {
                "all": _metrics(scored, sum(excluded.values())),
                "kinds": {
                    kind: _metrics(pairs.get(kind, []), excluded.get(kind, 0))
                    for kind in kinds
                    if question != "severity" or kind == CONTROL
                },
            }
        result["auroc"][arm] = {
            "all": _auroc(_points(cases, arm)),
            "kinds": {
                kind: _auroc(_points([c for c in cases if c["kind"] in (kind, CONTROL)], arm))
                for kind in kinds
                if kind != CONTROL
            },
        }
        briers = [result["metrics"][arm].get(q, {}).get("all", {}).get("brier") for q in HEADLINE_QUESTIONS]
        result["headline"][arm] = None if None in briers else sum(briers) / len(briers)
    return result

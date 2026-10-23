#!/usr/bin/env python3
"""Citation correctness and judge-quality measures from a recorded run and a labels file.

Usage:
    python benchmark/judge_eval.py RUN_DIR EXPORT.json LABELS.json [--judge-records RECORDS.json]
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import statistics
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH.parent / "src"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate = _load("lgtm_bench_evaluate", BENCH / "evaluate.py")
citation_export = _load("lgtm_bench_citation_export", BENCH / "citation_export.py")

from lgtm.agents.base import AgentFinding, EvidenceItem  # noqa: E402
from lgtm.config import LGTMConfig  # noqa: E402
from lgtm.validation.judge import JudgeCall, judge_candidates  # noqa: E402

LABELS = ("correct", "incorrect")
SEVERITIES = ("critical", "high", "medium", "low")
CORRUPTIONS = ("shifted_lines", "other_file", "swapped_snippet", "flipped_snapshot")
LINE_SHIFT = 20


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _percent(correct: int, n: int) -> float | None:
    return 100 * correct / n if n else None


def _validate_labels(unit_ids: Sequence[str], labels: dict) -> dict[str, dict]:
    units = labels.get("units", {})
    known = set(unit_ids)
    for uid, entry in units.items():
        if uid not in known:
            raise ValueError(f"labels file names unit {uid!r}, which is not in the export")
        if entry.get("citation") not in LABELS:
            raise ValueError(f"unit {uid!r} has label {entry.get('citation')!r}; use correct or incorrect")
        if "severity" in entry and entry["severity"] not in SEVERITIES:
            raise ValueError(f"unit {uid!r} has severity {entry['severity']!r}; use one of {', '.join(SEVERITIES)}")
    return units


def citation_correctness(unit_ids: Sequence[str], labels: dict, outcomes: list[dict]) -> dict:
    units = _validate_labels(unit_ids, labels)
    judged_ids = [o["unit_id"] for o in outcomes if o["judged"] and o["supported"]]

    def population(ids: Sequence[str]) -> dict:
        labelled = [units[i]["citation"] for i in ids if i in units]
        n = len(labelled)
        return {
            "n": n,
            "unlabelled": len(ids) - n,
            "percent_correct": _percent(labelled.count("correct"), n),
        }

    return {"before_judging": population(list(unit_ids)), "judged": population(judged_ids)}


def confidence_agreement(labels: dict, outcomes: list[dict]) -> dict:
    units = labels.get("units", {})
    by_label: dict[str, list[float]] = {label: [] for label in LABELS}
    for o in outcomes:
        entry = units.get(o["unit_id"])
        if o["judged"] and entry:
            by_label[entry["citation"]].append(o["provenance_confidence"])
    return {label: {"mean": _mean(v), "n": len(v)} for label, v in by_label.items()}


def verdict_accuracy(cases: list[dict]) -> dict:
    n = correct = unlabelled = excluded = 0
    for case in cases:
        if evaluate.result_is_error(case) or evaluate.not_judged_count(case):
            excluded += 1
            continue
        if not case.get("expected"):
            unlabelled += 1
            continue
        judged = [f for f in case["findings"] if f.get("judged")]
        predicted = evaluate.predict_case_verdict(judged, case["category"], judged=True)
        n += 1
        correct += evaluate.outcome_for(predicted, case["expected"]) in ("TP", "TN")
    return {
        "n": n, "correct": correct, "unlabelled": unlabelled, "excluded": excluded,
        "accuracy": correct / n if n else None,
    }


def severity_agreement(labels: dict, outcomes: list[dict]) -> dict:
    units = labels.get("units", {})
    n = agree = unlabelled = 0
    for o in outcomes:
        entry = units.get(o["unit_id"])
        if not (o["judged"] and o["severity"] and entry and entry["citation"] == "correct"):
            continue
        if entry.get("severity"):
            n += 1
            agree += entry["severity"] == o["severity"]
        else:
            unlabelled += 1
    return {"n": n, "agree": agree, "unlabelled": unlabelled, "agreement": agree / n if n else None}


def corrupt_citation(item: dict, donor_item: dict, other_file: str) -> list[dict]:
    lines = item.get("lines") or [1, 1]
    changes = {
        "shifted_lines": {"lines": [line + LINE_SHIFT for line in lines]},
        "other_file": {"file": other_file},
        "swapped_snippet": {"content": donor_item["content"]},
        "flipped_snapshot": {"snapshot": "base" if item.get("snapshot") == "pr" else "pr"},
    }
    return [
        {**copy.deepcopy(item), **change, "corruption": name, "known_incorrect": True}
        for name, change in changes.items()
    ]


def _first_code_index(finding: AgentFinding) -> int | None:
    return next((i for i, e in enumerate(finding.evidence) if e.type == "code"), None)


def measure_corruptions(
    candidates: list[AgentFinding],
    read_code: Callable[[EvidenceItem], str],
    config: LGTMConfig,
    judge: JudgeCall,
    other_file: str,
) -> list[dict]:
    grounded = [(c, _first_code_index(c)) for c in candidates]
    grounded = [(c, i) for c, i in grounded if i is not None]
    pairs = []
    for pos, (finding, idx) in enumerate(grounded):
        donor = grounded[(pos + 1) % len(grounded)]
        item = finding.evidence[idx].model_dump()
        copies = corrupt_citation(item, donor[0].evidence[donor[1]].model_dump(), other_file)
        original = finding.model_copy(deep=True)
        corrupted = []
        for corrupt in copies:
            variant = finding.model_copy(deep=True)
            variant.evidence[idx] = EvidenceItem.model_validate(
                {k: v for k, v in corrupt.items() if k in EvidenceItem.model_fields}
            )
            corrupted.append(variant)
        judge_candidates([original, *corrupted], read_code, config, judge)
        for corrupt, variant in zip(copies, corrupted):
            pairs.append({
                "corruption": corrupt["corruption"],
                "original": original.provenance_confidence if original.judged else None,
                "corrupted": variant.provenance_confidence if variant.judged else None,
            })
    return pairs


def corruption_report(pairs: list[dict]) -> dict:
    report = {}
    for name in dict.fromkeys(p["corruption"] for p in pairs):
        kept = [
            p for p in pairs
            if p["corruption"] == name and p["original"] is not None and p["corrupted"] is not None
        ]
        report[name] = {
            "n": len(kept),
            "original_mean": _mean([p["original"] for p in kept]),
            "corrupted_mean": _mean([p["corrupted"] for p in kept]),
        }
    return report


def measure_judge_run(
    candidates: list[AgentFinding],
    read_code: Callable[[EvidenceItem], str],
    config: LGTMConfig,
    judge: JudgeCall,
    clock: Callable[[], float] = time.monotonic,
) -> list[dict]:
    records = []
    for candidate in candidates:
        copied = candidate.model_copy(deep=True)
        started = clock()
        judge_candidates([copied], read_code, config, judge)
        records.append({
            "finding_id": copied.finding_id,
            "judged": copied.judged,
            "latency_seconds": clock() - started,
            "supported": copied.supported,
            "severity": copied.severity,
            "provenance_confidence": copied.provenance_confidence,
        })
    return records


def run_measures(records: list[dict], mode: str) -> dict:
    n = len(records)
    not_judged = sum(1 for r in records if not r["judged"])
    latencies = sorted(r["latency_seconds"] for r in records if r.get("latency_seconds") is not None)
    rank = -(-95 * len(latencies) // 100)
    return {
        "n": n,
        "not_judged": not_judged,
        "fallback_rate": not_judged / n if n and mode in evaluate.JUDGED_MODES else None,
        "latency_median": statistics.median(latencies) if latencies else None,
        "latency_p95": latencies[rank - 1] if latencies else None,
    }


def run_outcomes(run_dir: Path) -> list[dict]:
    """One outcome per exported unit, read from the recorded findings."""
    return [
        {
            "unit_id": uid,
            "judged": bool(finding.get("judged")),
            "supported": finding.get("supported"),
            "severity": finding.get("severity", ""),
            "provenance_confidence": finding.get("provenance_confidence"),
        }
        for record in citation_export.read_records(run_dir)
        for uid, finding, _item in citation_export.code_items(record)
    ]


def report(
    run_dir: Path, export_path: Path, labels_path: Path, judge_records_path: Path | None = None
) -> dict:
    run_dir = Path(run_dir)
    unit_ids = [u["unit_id"] for u in json.loads(Path(export_path).read_text(encoding="utf-8"))["units"]]
    labels = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    outcomes = run_outcomes(run_dir)
    records = citation_export.read_records(run_dir)
    modes = {r.get("mode") for r in records}
    findings = [f for r in records for f in r["findings"]]
    if judge_records_path:
        judge_records = json.loads(Path(judge_records_path).read_text(encoding="utf-8"))
    else:
        judge_records = [{"judged": bool(f.get("judged")), "latency_seconds": None} for f in findings]
    return {
        "citation_correctness": citation_correctness(unit_ids, labels, outcomes),
        "confidence_agreement": confidence_agreement(labels, outcomes),
        "severity_agreement": severity_agreement(labels, outcomes),
        "verdict_accuracy": verdict_accuracy(records),
        "run": run_measures(judge_records, modes.pop() if len(modes) == 1 else "mixed"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("export", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--judge-records", type=Path, default=None,
                        help="JSON list from measure_judge_run; adds judge latency")
    args = parser.parse_args()
    print(json.dumps(report(args.run_dir, args.export, args.labels, args.judge_records), indent=2))


if __name__ == "__main__":
    main()

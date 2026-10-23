#!/usr/bin/env python3
"""Citation support and judge-quality measures from a recorded run and a labels file.

Usage:
    python benchmark/judge_eval.py RUN_DIR EXPORT.json LABELS.json [--judge-records RECORDS.json]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import sys
import tempfile
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

LABELS = ("yes", "no")
PERTURBATIONS = ("unrelated_code", "mutated_claim", "safe_twin_code")
MUTATED_CLAIM = "The code writes the request body to a debug log and returns a fixed 200 response."
UNRELATED_LINES = 40


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _percent(yes: int, n: int) -> float | None:
    return 100 * yes / n if n else None


def _validate_labels(unit_ids: Sequence[str], labels: dict) -> dict[str, dict]:
    units = labels.get("units", {})
    known = set(unit_ids)
    for uid, entry in units.items():
        if uid not in known:
            raise ValueError(f"labels file names unit {uid!r}, which is not in the export")
        if not isinstance(entry, dict) or entry.get("supports") not in LABELS:
            label = entry.get("supports") if isinstance(entry, dict) else entry
            raise ValueError(f"unit {uid!r} has label {label!r}; use yes or no")
    return units


def citation_support(unit_ids: Sequence[str], labels: dict, outcomes: list[dict]) -> dict:
    units = _validate_labels(unit_ids, labels)
    judged_ids = [o["unit_id"] for o in outcomes if o["judged"] and o["supported"]]

    def population(ids: Sequence[str]) -> dict:
        labelled = [units[i]["supports"] for i in ids if i in units]
        n = len(labelled)
        return {
            "n": n,
            "unlabelled": len(ids) - n,
            "percent_yes": _percent(labelled.count("yes"), n),
        }

    return {"before_judging": population(list(unit_ids)), "judged": population(judged_ids)}


def confidence_agreement(labels: dict, outcomes: list[dict]) -> dict:
    units = labels.get("units", {})
    by_label: dict[str, list[float]] = {label: [] for label in LABELS}
    for o in outcomes:
        entry = units.get(o["unit_id"])
        if o["judged"] and entry:
            by_label[entry["supports"]].append(o["provenance_confidence"])
    return {label: {"mean": _mean(v), "n": len(v)} for label, v in by_label.items()}


def supported_agreement(labels: dict, outcomes: list[dict]) -> dict:
    units = labels.get("units", {})
    n = agree = unlabelled = 0
    for o in outcomes:
        if not o["judged"]:
            continue
        entry = units.get(o["unit_id"])
        if not entry:
            unlabelled += 1
            continue
        n += 1
        agree += o["supported"] == (entry["supports"] == "yes")
    return {
        "n": n, "agree": agree, "unlabelled": unlabelled,
        "not_judged": sum(1 for o in outcomes if not o["judged"]),
        "agreement": agree / n if n else None,
    }


def not_judged_by_reason(findings: list[dict]) -> dict:
    reasons = [f.get("not_judged_reason") or "unknown" for f in findings if not f.get("judged")]
    return {reason: reasons.count(reason) for reason in dict.fromkeys(reasons)}


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


def _first_code_index(finding: AgentFinding) -> int | None:
    return next((i for i, e in enumerate(finding.evidence) if e.type == "code"), None)


def measure_perturbations(
    candidates: list[AgentFinding],
    read_code: Callable[[EvidenceItem], str],
    config: LGTMConfig,
    judge: JudgeCall,
    unrelated_code: Callable[[AgentFinding], str | None],
    safe_twin_code: Callable[[AgentFinding], str | None],
) -> dict:
    """Judge each originally judged candidate and its known-unsupported copies.

    A provider returning nothing skips that copy; skips are counted per perturbation.
    """
    providers = {"unrelated_code": unrelated_code, "safe_twin_code": safe_twin_code}
    records: list[dict] = []
    skipped = {name: 0 for name in PERTURBATIONS}
    for candidate in candidates:
        idx = _first_code_index(candidate)
        if idx is None:
            continue
        cited = candidate.evidence[idx]
        try:
            if not read_code(cited):
                continue
        except Exception:  # noqa: BLE001 - an unreadable citation is not perturbed
            continue
        original = candidate.model_copy(deep=True)
        judge_candidates([original], read_code, config, judge)
        if not original.judged:
            continue
        for name in PERTURBATIONS:
            variant = candidate.model_copy(deep=True)
            read = read_code
            if name == "mutated_claim":
                variant.explanation = MUTATED_CLAIM
            else:
                text = providers[name](candidate)
                if not text:
                    skipped[name] += 1
                    continue
                variant.evidence = [e for i, e in enumerate(variant.evidence) if e.type != "code" or i == idx]

                def read(item, text=text):
                    same = (item.file, item.lines, item.snapshot) == (cited.file, cited.lines, cited.snapshot)
                    return text if same else read_code(item)

            judge_candidates([variant], read, config, judge)
            records.append({
                "finding_id": candidate.finding_id,
                "perturbation": name,
                "known_unsupported": True,
                "original_supported": original.supported,
                "original_confidence": original.provenance_confidence,
                "judged": variant.judged,
                "supported": variant.supported,
                "confidence": variant.provenance_confidence,
            })
    return {"records": records, "skipped": skipped}


def perturbation_report(measured: dict) -> dict:
    """Original minus perturbed, over pairs where both were judged."""
    report = {}
    for name in PERTURBATIONS:
        kept = [r for r in measured["records"] if r["perturbation"] == name and r["judged"]]
        drop = lambda a, b: _mean([r[a] for r in kept]) - _mean([r[b] for r in kept]) if kept else None  # noqa: E731
        report[name] = {
            "n": len(kept),
            "skipped": measured["skipped"][name],
            "support_rate_drop": drop("original_supported", "supported"),
            "confidence_drop": drop("original_confidence", "confidence"),
        }
    return report


def _read_at(repo: Path, ref: str, item: dict) -> str | None:
    sha = citation_export._git(repo, "rev-parse", ref).stdout.decode().strip()
    return citation_export._read_lines(repo, sha, item)


def _unrelated_from(repo: Path, ref: str) -> Callable[[AgentFinding], str | None]:
    def provide(finding: AgentFinding) -> str | None:
        names = citation_export._git(repo, "ls-tree", "-r", "--name-only", ref).stdout.decode().splitlines()
        other = next((n for n in names if n.endswith(".py") and n != finding.file), None)
        if other is None:
            return None
        done = citation_export._git(repo, "show", f"{ref}:{other}")
        return "\n".join(done.stdout.decode("utf-8", "replace").splitlines()[:UNRELATED_LINES]) or None

    return provide


def _twin_from(
    repo: Path, ref: str, twin_repo: Path | None, twin_ref: str
) -> Callable[[AgentFinding], str | None]:
    def provide(finding: AgentFinding) -> str | None:
        idx = _first_code_index(finding)
        if twin_repo is None or idx is None:
            return None
        item = finding.evidence[idx].model_dump()
        twin = _read_at(twin_repo, twin_ref, item)
        return twin if twin and twin != _read_at(repo, ref, item) else None

    return provide


def perturb_case(
    case: dict, candidates: list[AgentFinding], config: LGTMConfig, judge: JudgeCall,
    repo: Path | None = None,
) -> dict:
    """Perturbation run for one vulnerable case with the real code providers.

    Synthetic cases build their repos from the patches; a real-world case needs ``repo``,
    a clone already prepared by ``real_world/fetch.py`` (its ``rw/<id>/pr`` branch holds the
    cited code, ``rw/<id>/base`` the fixed variant).
    """
    with tempfile.TemporaryDirectory(prefix="lgtm-perturb-", dir=BENCH.parent, ignore_cleanup_errors=True) as tmp:
        if repo is None:
            repo, ref, patch = Path(tmp) / "case", "pr", BENCH / case["patch_file"]
            repo.mkdir()
            evaluate.build_case_repo(repo, patch)
            safe_patch = patch.with_name(patch.name.replace("_vulnerable", "_safe"))
            twin_repo, twin_ref = None, "pr"
            if "_vulnerable" in patch.name and safe_patch.is_file():
                twin_repo = Path(tmp) / "twin"
                twin_repo.mkdir()
                evaluate.build_case_repo(twin_repo, safe_patch)
        else:
            ref, twin_ref = f"rw/{case['id']}/pr", f"rw/{case['id']}/base"
            twin_repo = repo if case.get("construction") == "synthetic-revert" else None

        def read_code(item: EvidenceItem) -> str:
            text = _read_at(repo, ref, item.model_dump())
            if text is None:
                raise FileNotFoundError(item.file)
            return text

        return measure_perturbations(
            candidates, read_code, config, judge,
            unrelated_code=_unrelated_from(repo, ref),
            safe_twin_code=_twin_from(repo, ref, twin_repo, twin_ref),
        )


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
            "provenance_confidence": copied.provenance_confidence,
            "unsupported_reason": copied.unsupported_reason,
        })
    return records


def run_measures(records: list[dict], mode: str) -> dict:
    records = [r for r in records if not r.get("unsupported_reason")]
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
        judge_records = [
            {"judged": bool(f.get("judged")), "latency_seconds": None, "unsupported_reason": f.get("unsupported_reason")}
            for f in findings
        ]
    return {
        "citation_support": citation_support(unit_ids, labels, outcomes),
        "confidence_agreement": confidence_agreement(labels, outcomes),
        "supported_agreement": supported_agreement(labels, outcomes),
        "case_accuracy": verdict_accuracy(records),
        "not_judged_by_reason": not_judged_by_reason(
            [f for r in records if r.get("mode") in evaluate.JUDGED_MODES for f in r["findings"]]
        ),
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

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
from collections import Counter
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
from lgtm.validation.judge import JudgeCall, http_judge, judge_candidates  # noqa: E402

LABELS = ("yes", "no")
PERTURBATIONS = ("unrelated_code", "mutated_claim", "safe_twin_code")
MUTATED_CLAIM = "The code writes the request body to a debug log and returns a fixed 200 response."
UNRELATED_LINES = 40
REASON_CODE_UNREADABLE = "code-unreadable"


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


STALE_CASES = ("sqli_04_safe", "sqli_07_safe", "sqli_11_safe")
STALE_REASON = "cited text predates the regenerated Shoply patches"
QUOTE_ABSENCE_CASES = ("authz_10_vulnerable", "authz_12_vulnerable")
AGENT_TO_KEV = {"vulnerable": "real", "safe": "not_real"}


def _case_of(unit_id: str) -> str:
    return unit_id.split("/")[0]


def _labelled_judged(labels: dict, outcomes: list[dict]):
    """(outcome, label) pairs of judged, labelled units outside the stale cases."""
    units = labels.get("units", {})
    return [
        (o, units[o["unit_id"]]) for o in outcomes
        if o["judged"] and o["unit_id"] in units and _case_of(o["unit_id"]) not in STALE_CASES
    ]


def _tally(n: int, correct: int) -> dict:
    return {"n": n, "correct": correct, "accuracy": correct / n if n else None}


def kev_accuracy(labels: dict, outcomes: list[dict]) -> dict:
    pairs = _labelled_judged(labels, outcomes)
    with_severity = [(o, e) for o, e in pairs if e.get("severity")]
    return {
        "supported": _tally(len(pairs), sum(o["supported"] == (e["supports"] == "yes") for o, e in pairs)),
        "verdict": _tally(len(pairs), sum(o["kev_verdict"] == e.get("verdict") for o, e in pairs)),
        "severity": _tally(len(with_severity), sum(o["kev_severity"] == e["severity"] for o, e in with_severity)),
    }


def kev_agreement(outcomes: list[dict]) -> dict:
    judged = [
        o for o in outcomes
        if o["judged"] and o.get("kev_verdict") and _case_of(o["unit_id"]) not in STALE_CASES
    ]
    disagree = sum(bool(o["supported"]) != (o["kev_verdict"] == "real") for o in judged)
    mapped = [(AGENT_TO_KEV.get(o.get("agent_verdict")), o["kev_verdict"]) for o in judged]
    mapped = [(agent, kev) for agent, kev in mapped if agent]
    equal = sum(agent == kev for agent, kev in mapped)
    return {
        "verdict_vs_supported": {
            "n": len(judged), "disagree": disagree, "rate": disagree / len(judged) if judged else None,
        },
        "verdict_vs_agent": {"n": len(mapped), "equal": equal, "rate": equal / len(mapped) if mapped else None},
    }


def stale_candidates(outcomes: list[dict]) -> list[dict]:
    present = dict.fromkeys(_case_of(o["unit_id"]) for o in outcomes)
    return [{"case_id": case, "reason": STALE_REASON} for case in STALE_CASES if case in present]


def label_summary(labels: dict) -> dict:
    model = labels.get("labeling_model")
    if not model:
        raise ValueError("labels file records no labeling_model")
    return {
        "n": len(labels.get("units", {})),
        "origins": dict(Counter(e.get("origin") for e in labels.get("units", {}).values())),
        "source": "model",
        "labeling_model": model,
    }


def supported_by_kind(labels: dict, outcomes: list[dict]) -> dict:
    kinds = {e.get("kind"): [0, 0] for e in labels.get("units", {}).values()}
    for o, e in _labelled_judged(labels, outcomes):
        tally = kinds[e.get("kind")]
        tally[0] += 1
        tally[1] += o["supported"] == (e["supports"] == "yes")
    return {kind: _tally(n, correct) for kind, (n, correct) in kinds.items()}


def safe_case_acceptance(labels: dict, outcomes: list[dict], safe_cases: set[str]) -> dict:
    tally = {"shoply": [0, 0], "real_world": [0, 0]}
    for o, e in _labelled_judged(labels, outcomes):
        if _case_of(o["unit_id"]) in safe_cases and e.get("origin") in tally:
            tally[e["origin"]][0] += 1
            tally[e["origin"]][1] += bool(o["supported"])
    return {
        origin: {"n": n, "accepted": accepted, "share": accepted / n if n else None}
        for origin, (n, accepted) in tally.items()
    }


def quote_absence(
    records: list[dict], read_pr_file: Callable[[str, str], str | None],
    case_ids: Sequence[str] = QUOTE_ABSENCE_CASES,
) -> list[dict]:
    rows = []
    for record in records:
        if record["id"] not in case_ids:
            continue
        for finding in record["findings"]:
            for item in finding.get("evidence") or []:
                if item.get("type", "code") != "code":
                    continue
                text = read_pr_file(record["id"], item["file"])
                lines = item.get("lines")
                if text is None or (lines and lines[0] > len(text.splitlines())):
                    cause = "repository_mismatch"
                elif (item.get("content") or "") in text:
                    cause = None
                else:
                    cause = "agent_quote"
                rows.append({
                    "case_id": record["id"], "file": item["file"], "lines": lines,
                    "absent": cause is not None, "cause": cause,
                })
    return rows


def _pr_file_reader(tmp: Path) -> Callable[[str, str], str | None]:
    patches = {c["id"]: c["patch_file"] for c in json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))["cases"]}

    def read(case_id: str, file: str) -> str | None:
        if case_id not in patches:
            return None
        repo = tmp / case_id
        if not repo.exists():
            repo.mkdir()
            evaluate.build_case_repo(repo, BENCH / patches[case_id])
        done = citation_export._git(repo, "show", f"pr:{file}")
        return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None

    return read


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
                "original_verdict": original.kev_verdict,
                "verdict": variant.kev_verdict,
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
            "verdict_shift": dict(Counter(f"{r['original_verdict']}->{r['verdict']}" for r in kept)),
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
    case_id: str | None = None,
) -> list[dict]:
    records = []
    for candidate in candidates:
        copied = candidate.model_copy(deep=True)
        started = clock()
        judge_candidates([copied], read_code, config, judge)
        records.append({
            "case_id": case_id,
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
            "mode": record.get("mode"),
            "judged": bool(finding.get("judged")),
            "supported": finding.get("supported"),
            "provenance_confidence": finding.get("provenance_confidence"),
            "kev_verdict": finding.get("kev_verdict"),
            "kev_severity": finding.get("kev_severity"),
            "agent_verdict": finding.get("verdict"),
            "input_tokens": finding.get("input_tokens"),
            "not_judged_reason": finding.get("not_judged_reason"),
        }
        for record in citation_export.read_records(run_dir)
        for uid, finding, _item in citation_export.code_items(record)
    ]


def report(
    run_dir: Path, export_path: Path, labels_path: Path, judge_records_path: Path | None = None,
    read_pr_file: Callable[[str, str], str | None] | None = None,
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
    if read_pr_file or not any(r["id"] in QUOTE_ABSENCE_CASES for r in records):
        absence = quote_absence(records, read_pr_file or (lambda *_: None))
    else:
        with tempfile.TemporaryDirectory(prefix="lgtm-quotes-", dir=BENCH.parent, ignore_cleanup_errors=True) as tmp:
            absence = quote_absence(records, _pr_file_reader(Path(tmp)))
    return {
        "quote_absence": absence,
        "citation_support": citation_support(unit_ids, labels, outcomes),
        "confidence_agreement": confidence_agreement(labels, outcomes),
        "supported_agreement": supported_agreement(labels, outcomes),
        "case_accuracy": verdict_accuracy(records),
        "not_judged_by_reason": not_judged_by_reason(
            [f for r in records if r.get("mode") in evaluate.JUDGED_MODES for f in r["findings"]]
        ),
        "run": run_measures(judge_records, modes.pop() if len(modes) == 1 else "mixed"),
        "kev": kev_report(records),
        "kev_accuracy": kev_accuracy(labels, outcomes),
        "kev_agreement": kev_agreement(outcomes),
        "labels": label_summary(labels) if labels.get("labeling_model") else None,
        "supported_by_kind": supported_by_kind(labels, outcomes),
        "safe_case_acceptance": safe_case_acceptance(
            labels, outcomes, {r["id"] for r in records if r.get("expected") == "safe"}
        ),
        "stale": stale_candidates(outcomes),
    }


def kev_report(records: list[dict]) -> dict:
    """Kev metrics with one entry per judged-mode finding, whatever number of code items it cites."""
    findings = [
        f for r in records if r.get("mode") in evaluate.JUDGED_MODES for f in r["findings"]
    ]
    candidates = []
    for r in records:
        if r.get("mode") not in evaluate.JUDGED_MODES:
            continue
        for fi, f in enumerate(r["findings"]):
            if f.get("judged") and f.get("kev_verdict"):
                first = next((ei for ei, e in enumerate(f.get("evidence") or []) if e.get("type", "code") == "code"), 0)
                candidates.append({
                    "unit_id": citation_export.unit_id(r["id"], fi, first),
                    **{k: f.get(k) for k in ("kev_verdict", "kev_severity", "provenance_confidence")},
                })
    return {**evaluate.kev_metrics(findings), "candidates": candidates}


def rejudge(run_dir: Path, export_path: Path, config: LGTMConfig, judge: JudgeCall | None = None) -> list[dict]:
    """Records of a run with each judged-mode candidate judged again, reading code from the export."""
    units = json.loads(Path(export_path).read_text(encoding="utf-8"))["units"]
    judge = judge or http_judge(config)
    records = citation_export.read_records(Path(run_dir))
    for record in records:
        if record.get("mode") not in evaluate.JUDGED_MODES:
            continue
        codes = {
            (u["file"], tuple(u["lines"] or ()), u["snapshot"]): u["code"]
            for u in units if u["unit_id"].startswith(f"{record['id']}/")
        }

        def read_code(item: EvidenceItem) -> str:
            return codes.get((item.file, tuple(item.lines or ()), item.snapshot), "")

        for i, finding in enumerate(record["findings"]):
            candidate = AgentFinding.model_validate(finding)
            if any(e.type == "code" and not read_code(e) for e in candidate.evidence):
                record["findings"][i] = {
                    **finding, "supported": None, "judged": False, "provenance_confidence": None,
                    "not_judged_reason": REASON_CODE_UNREADABLE, "unsupported_reason": "",
                    "kev_verdict": None, "kev_severity": None, "input_tokens": None,
                }
                continue
            replies: list = []

            def recording(request: dict) -> dict:
                replies.append(judge(request))
                return replies[-1]

            judge_candidates([candidate], read_code, config, recording)
            answered = candidate.model_dump(
                include={"supported", "judged", "provenance_confidence", "not_judged_reason", "unsupported_reason"}
            )
            record["findings"][i] = {
                **finding, **answered,
                "kev_verdict": candidate.kev_verdict,
                "kev_severity": candidate.kev_severity,
                "input_tokens": replies[-1].get("input_tokens") if replies else None,
            }
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("export", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--judge-records", type=Path, default=None,
                        help="JSON list from measure_judge_run; adds judge latency")
    parser.add_argument("--live", action="store_true",
                        help="judge the run's candidates again with the live judge endpoint, then report")
    args = parser.parse_args()
    if not args.live:
        print(json.dumps(report(args.run_dir, args.export, args.labels, args.judge_records), indent=2))
        return
    with tempfile.TemporaryDirectory(prefix="lgtm-judge-live-") as tmp:
        for n, record in enumerate(rejudge(args.run_dir, args.export, LGTMConfig())):
            (Path(tmp) / f"{n}.json").write_text(json.dumps(record), encoding="utf-8")
        print(json.dumps(report(Path(tmp), args.export, args.labels, args.judge_records), indent=2))


if __name__ == "__main__":
    main()

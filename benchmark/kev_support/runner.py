"""Standalone Kev validation benchmark: runs the authored fixtures through evidence validation and
the production Kev judge request in a few-shot and a zero-shot arm and writes a scored report."""

from __future__ import annotations

import argparse
import json
import math
import sys
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kev_support.confidence import score as confidence_score  # noqa: E402
from kev_support.fixtures import KINDS, OTHER_FLAW, Fixture, build_repos, load_fixtures  # noqa: E402
from lgtm.config import LGTMConfig  # noqa: E402
from lgtm.validation.evidence import EvidenceValidator  # noqa: E402
from lgtm.validation.judge import (  # noqa: E402
    JUDGE_REPLY_MAX_BYTES,
    JUDGE_STATE_MAX_CHARS,
    LOOPBACK_HOSTS,
    QUESTION_CONFIDENCE,
    QUESTION_SEVERITY,
    QUESTION_SUPPORT,
    QUESTION_VERDICT,
    SEVERITY_LEVELS,
    SYSTEM_ONE_PATH,
    RequestTooLarge,
    _NoRedirect,
    build_judge_request,
)

PERMUTE_PATH = SYSTEM_ONE_PATH + "/permute"
PERMUTE_RUNS = 6
TOKEN_LIMIT = 8192
ARMS = {"few_shot": True, "zero_shot": False}
CHOICE_QUESTIONS = (QUESTION_SUPPORT, QUESTION_VERDICT, QUESTION_SEVERITY)
OTHER_FLAW_ROW = "wrong_cwe_other_flaw"
CELL_KINDS = ("control", *KINDS)

JudgeCall = Callable[[str, str, dict], Mapping]
PermuteCall = Callable[[str, str, str, dict], Mapping]


def evidence_issues(fixture: Fixture, repo: Path) -> list[str]:
    validator = EvidenceValidator(repo, "HEAD")
    issues = []
    for item in fixture.finding.evidence:
        check = validator._validate_policy_item if item.type == "policy" else validator._validate_code_item
        issues += check(item)
    return issues


def wilson(count: int, n: int, z: float = 1.96) -> list[float | None]:
    if n == 0:
        return [None, None]
    p = count / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _rate(count: int, n: int) -> dict:
    return {"count": count, "n": n, "wilson": wilson(count, n)}


def _answer(reply: Mapping, request: dict) -> dict:
    answers = reply["answers"]
    picked, scores = {}, {}
    for question in CHOICE_QUESTIONS:
        choice = answers[question]["choice"]
        if choice not in request["questions"][question]["criteria"]:
            raise ValueError(f"{question} answer {choice!r} is not an option")
        picked[question] = choice
        scores[question] = answers[question]["probabilities"]
    return {
        "answers": picked,
        "scores": scores,
        "noul": float(answers[QUESTION_CONFIDENCE]["noul"]),
        "input_tokens": (reply.get("usage") or {}).get("input_tokens"),
    }


def _permuted(permute: PermuteCall, case_id: str, arm: str, request: dict, plain: Mapping) -> tuple[dict, int]:
    scored, failures = {}, 0
    for question in CHOICE_QUESTIONS:
        try:
            reply = permute(case_id, arm, question, request)
            runs = list(reply["runs"])
            choices = {run["choice"] for run in runs}
            stable = bool(reply["argmax_stable"])
            scored[question] = {
                "runs": runs,
                "argmax_stable": stable,
                "spread": reply["spread"],
                "order_sensitive": len(choices) > 1 or not stable,
                "plain_unstable": len(choices) == 1 and plain[question] not in choices,
            }
        except Exception as exc:  # noqa: BLE001 - a failed permute call is reported for this question only
            scored[question] = {"error": f"{type(exc).__name__}: {exc}"}
            failures += 1
    return scored, failures


def _score_case(f: Fixture, arm: str, build, judge: JudgeCall, permute: PermuteCall) -> dict:
    try:
        request = build(ARMS[arm])
    except RequestTooLarge as exc:
        return {"status": "too_large", "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 - one unbuildable request is reported for this case and arm only
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    try:
        record = {"status": "answered", "reason": "", **_answer(judge(f.case_id, arm, request), request)}
    except Exception as exc:  # noqa: BLE001 - a failed call is reported for this case and arm only
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    record["permute"], record["permute_errors"] = _permuted(permute, f.case_id, arm, request, record["answers"])
    return record


def _summarise(report: dict, fixtures: list[Fixture]) -> None:
    by_id = {f.case_id: f for f in fixtures}
    report["cells"], report["subrows"], report["severity"], report["input_tokens"] = {}, {}, {}, {}
    for arm in ARMS:
        cells = {
            kind: {
                "cases": 0, "evaluated": 0, "errors": 0, "too_large": 0, "evidence_invalid": 0,
                "permute_errors": 0, "verdict": [0, 0], "provenance": [0, 0],
            }
            for kind in (*CELL_KINDS, OTHER_FLAW_ROW)
        }
        diffs, tokens = [], []
        for rec in report["cases"]:
            got, f = rec["arms"][arm], by_id[rec["case_id"]]
            rows = [cells[rec["kind"]]]
            if OTHER_FLAW in f.tags:
                rows.append(cells[OTHER_FLAW_ROW])
            for cell in rows:
                cell["cases"] += 1
            if got["status"] != "answered":
                for cell in rows:
                    cell[{"error": "errors"}.get(got["status"], got["status"])] += 1
                continue
            if got["input_tokens"] is not None:
                tokens.append(got["input_tokens"])
            for cell in rows:
                cell["evaluated"] += 1
                cell["permute_errors"] += got["permute_errors"]
                for name, correct in (
                    ("verdict", got["answers"][QUESTION_VERDICT] == f.verdict),
                    ("provenance", (got["noul"] >= 0.5) == (f.provenance == "supported")),
                ):
                    cell[name][0] += correct
                    cell[name][1] += 1
            if f.verdict == "real":
                diffs.append(
                    abs(SEVERITY_LEVELS.index(got["answers"][QUESTION_SEVERITY]) - SEVERITY_LEVELS.index(f.severity))
                )
        for cell in cells.values():
            for name in ("verdict", "provenance"):
                cell[name] = _rate(*cell[name])
        report["subrows"][arm] = {OTHER_FLAW_ROW: cells.pop(OTHER_FLAW_ROW)}
        report["cells"][arm] = cells
        report["severity"][arm] = {
            "n": len(diffs),
            "mae": sum(diffs) / len(diffs) if diffs else None,
            "exact": _rate(sum(d == 0 for d in diffs), len(diffs)),
            "within_one": _rate(sum(d <= 1 for d in diffs), len(diffs)),
        }
        report["input_tokens"][arm] = {"n": len(tokens), "requests_over_8192_input_tokens": sum(t > TOKEN_LIMIT for t in tokens)}


def run(
    out_dir: Path,
    *,
    work_dir: Path,
    judge: JudgeCall,
    permute: PermuteCall,
    fixtures: list[Fixture] | None = None,
) -> dict:
    fixtures = load_fixtures() if fixtures is None else fixtures
    repos = build_repos(Path(work_dir))
    config = LGTMConfig()
    validators = {key: EvidenceValidator(path, "HEAD") for key, path in repos.items()}
    failures = [f.case_id for f in fixtures if evidence_issues(f, repos[f.repo])]
    report: dict = {"evidence_failures": failures, "arms": list(ARMS), "cases": []}
    for f in fixtures:

        def build(few_shot: bool, f: Fixture = f) -> dict:
            return build_judge_request(
                f.finding,
                validators[f.repo].read_cited_code,
                model=config.judge_model,
                max_chars=JUDGE_STATE_MAX_CHARS,
                few_shot=few_shot,
            )

        if f.case_id in failures:
            arms = {arm: {"status": "evidence_invalid", "reason": "cited evidence failed validation"} for arm in ARMS}
        else:
            arms = {arm: _score_case(f, arm, build, judge, permute) for arm in ARMS}
        report["cases"].append(
            {
                "case_id": f.case_id,
                "kind": f.kind,
                "tags": list(f.tags),
                "ground_truth": {"verdict": f.verdict, "provenance": f.provenance, "severity": f.severity},
                "arms": arms,
            }
        )
    _summarise(report, fixtures)
    report["confidence"] = confidence_score(report)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _post_client(config: LGTMConfig, path: str) -> Callable[[dict], Mapping]:
    url = config.judge_endpoint.rstrip("/") + path
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def post(body: dict) -> Mapping:
        target = urllib.parse.urlsplit(url)
        if target.scheme != "http" or target.hostname not in LOOPBACK_HOSTS:
            raise ValueError("judge endpoint must be http on a loopback host")
        http_request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(http_request, timeout=config.judge_timeout) as response:
            raw = response.read(JUDGE_REPLY_MAX_BYTES + 1)
        if len(raw) > JUDGE_REPLY_MAX_BYTES:
            raise ValueError("reply exceeds the size limit")
        return json.loads(raw)

    return post


def main(argv: Sequence[str] | None = None, *, judge: JudgeCall | None = None, permute: PermuteCall | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path, help="new directory that receives report.json")
    parser.add_argument("--work-dir", type=Path, help="directory for the temporary case repositories")
    parser.add_argument("--rescore", type=Path, help="recompute the confidence scores of this report.json without calling Kev")
    args = parser.parse_args(argv)

    if args.rescore:
        source = args.rescore.resolve()
        target = args.out / f"{source.parent.name}.json"
        if target.resolve() == source:
            parser.error("--out would overwrite the report being re-scored")
        report = json.loads(source.read_text(encoding="utf-8"))
        report["confidence"] = confidence_score(report)
        args.out.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"re-scored report written to {target}")
        return 0

    config = LGTMConfig()
    if judge is None:
        post_judge = _post_client(config, SYSTEM_ONE_PATH)
        judge = lambda case_id, arm, request: post_judge(request)  # noqa: E731
    if permute is None:
        post_permute = _post_client(config, PERMUTE_PATH)
        permute = lambda case_id, arm, question, request: post_permute(  # noqa: E731
            {"request": request, "question": question, "n_perm": PERMUTE_RUNS, "seed": 0}
        )
    if args.work_dir:
        report = run(args.out, work_dir=args.work_dir, judge=judge, permute=permute)
    else:
        with tempfile.TemporaryDirectory(prefix="kev-support-") as work:
            report = run(args.out, work_dir=Path(work), judge=judge, permute=permute)
    print(f"report written to {args.out / 'report.json'}")
    cells = [c for arm in report["cells"].values() for c in arm.values()]
    failed = any(c["errors"] or c["permute_errors"] for c in cells)
    return 1 if failed or not any(c["evaluated"] for c in cells) else 0


if __name__ == "__main__":
    raise SystemExit(main())

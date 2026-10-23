"""Standalone Kev validation benchmark: runs the authored fixtures through evidence validation and
the Kev judge in every request format and writes a per-kind, per-format report."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kev_support.fixtures import CONTROL, KINDS, Fixture, build_repos, load_fixtures  # noqa: E402
from lgtm.config import LGTMConfig  # noqa: E402
from lgtm.validation.evidence import EvidenceValidator  # noqa: E402
from lgtm.validation.judge import (  # noqa: E402
    JUDGE_REPLY_MAX_BYTES,
    JUDGE_STATE_MAX_CHARS,
    LOOPBACK_HOSTS,
    QUESTION_SUPPORT,
    REQUEST_FORMATS,
    SYSTEM_ONE_PATH,
    build_judge_request,
    http_judge,
)

PERMUTE_PATH = SYSTEM_ONE_PATH + "/permute"
PERMUTE_RUNS = 6

Call = Callable[[str, str, dict], Mapping]


def evidence_issues(fixture: Fixture, repo: Path) -> list[str]:
    validator = EvidenceValidator(repo, "HEAD")
    issues = []
    for item in fixture.finding.evidence:
        check = validator._validate_policy_item if item.type == "policy" else validator._validate_code_item
        issues += check(item)
    return issues


def _verdict(answer: Mapping) -> str:
    supported = answer[QUESTION_SUPPORT]
    if supported not in ("yes", "no"):
        raise ValueError(f"unknown support answer: {supported!r}")
    return supported


def _new_cell(fixture_kind: str) -> dict:
    return {"kept" if fixture_kind == CONTROL else "rejected": 0, "errors": 0, "evidence_invalid": 0, "evaluated": 0}


def run(
    out_dir: Path,
    *,
    work_dir: Path,
    judge: Call,
    permute: Call,
    fixtures: list[Fixture] | None = None,
    formats: Sequence[str] = REQUEST_FORMATS,
) -> dict:
    fixtures = load_fixtures() if fixtures is None else fixtures
    repos = build_repos(Path(work_dir))
    config = LGTMConfig()
    validators = {key: EvidenceValidator(path, "HEAD") for key, path in repos.items()}
    failures = [f.case_id for f in fixtures if evidence_issues(f, repos[f.repo])]
    invalid = set(failures)
    report = {
        "evidence_failures": failures,
        "formats": {
            fmt: {
                "kinds": {kind: _new_cell(kind) for kind in KINDS},
                "controls": _new_cell(CONTROL),
                "unstable": {"count": 0, "cases": []},
                "order_sensitive": {"count": 0, "cases": []},
            }
            for fmt in formats
        },
    }
    for fmt in formats:
        entry = report["formats"][fmt]
        for f in fixtures:
            cell = entry["controls"] if f.kind == CONTROL else entry["kinds"][f.kind]
            if f.case_id in invalid:
                cell["evidence_invalid"] += 1
                continue
            try:
                request = build_judge_request(
                    f.finding,
                    validators[f.repo].read_cited_code,
                    model=config.judge_model,
                    max_chars=JUDGE_STATE_MAX_CHARS,
                    request_format=fmt,
                )
                first = _verdict(judge(f.case_id, fmt, request))
            except Exception:  # noqa: BLE001 - a failed call is reported for this finding and format only
                cell["errors"] += 1
                continue
            cell["evaluated"] += 1
            if (first == "yes") == (f.kind == CONTROL):
                cell["kept" if f.kind == CONTROL else "rejected"] += 1
            stability_failed = False
            for name, call in (("unstable", judge), ("order_sensitive", permute)):
                try:
                    other = _verdict(call(f.case_id, fmt, request))
                except Exception:  # noqa: BLE001 - the first verdict stays scored
                    stability_failed = True
                    continue
                if other != first:
                    entry[name]["count"] += 1
                    entry[name]["cases"].append(f.case_id)
            cell["errors"] += stability_failed
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _permute_client(config: LGTMConfig) -> Call:
    url = config.judge_endpoint.rstrip("/") + PERMUTE_PATH
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(case_id: str, request_format: str, request: dict) -> Mapping:
        target = urllib.parse.urlsplit(url)
        if target.scheme != "http" or target.hostname not in LOOPBACK_HOSTS:
            raise ValueError("judge endpoint must be http on a loopback host")
        body = {"request": request, "question": QUESTION_SUPPORT, "n_perm": PERMUTE_RUNS, "seed": 0}
        http_request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(http_request, timeout=config.judge_timeout) as response:
            raw = response.read(JUDGE_REPLY_MAX_BYTES + 1)
        if len(raw) > JUDGE_REPLY_MAX_BYTES:
            raise ValueError("permute reply exceeds the size limit")
        choices = [r["choice"] for r in json.loads(raw)["runs"]]
        # Run 0 uses the supplied option order; the first differing run is the order-sensitive verdict.
        return {QUESTION_SUPPORT: next((c for c in choices if c != choices[0]), choices[0])}

    return call


def main(argv: Sequence[str] | None = None, *, judge: Call | None = None, permute: Call | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path, help="new directory that receives report.json")
    parser.add_argument("--work-dir", type=Path, help="directory for the temporary case repositories")
    args = parser.parse_args(argv)

    config = LGTMConfig()
    if judge is None:
        plain = http_judge(config)
        judge = lambda case_id, request_format, request: plain(request)  # noqa: E731
    permute = permute or _permute_client(config)
    if args.work_dir:
        report = run(args.out, work_dir=args.work_dir, judge=judge, permute=permute)
    else:
        with tempfile.TemporaryDirectory(prefix="kev-support-") as work:
            report = run(args.out, work_dir=Path(work), judge=judge, permute=permute)
    print(f"report written to {args.out / 'report.json'}")
    cells = [c for e in report["formats"].values() for c in (*e["kinds"].values(), e["controls"])]
    return 1 if any(c["errors"] for c in cells) or not any(c["evaluated"] for c in cells) else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""The LGTM review report: one pull request's review as a print-ready HTML page, and as a PDF.

The PDF is printed by headless Chrome from the same HTML, so the report needs no PDF library. If Chrome is
not installed, the dashboard falls back to the HTML page, which prints cleanly from any browser.
"""

from __future__ import annotations

import datetime
import html
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

CWE = {
    "CWE-89": "SQL injection", "CWE-639": "Insecure direct object reference", "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization", "CWE-285": "Improper authorization", "CWE-284": "Improper access control",
}
AGENTS = {"investigator": "Investigator", "authz_reviewer": "Authorization reviewer", "sqli_reviewer": "SQL-injection reviewer",
          "sast_triage": "Semgrep triage"}
TRIAGE = {"open": "Open", "confirmed": "Confirmed", "accepted_risk": "Accepted risk", "false_positive": "False positive",
          "fixed": "Fixed", None: "Open", "": "Open"}
OUTCOME = {"TP": "caught the advisory's bug", "FN": "missed the advisory's bug", "TN": "correctly quiet on the fix",
           "FP": "false alarm on the fix", "ERROR": "errored"}
CHROME = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
          "/Applications/Chromium.app/Contents/MacOS/Chromium", "google-chrome", "chromium", "chromium-browser"]


def e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def rich(s) -> str:
    out = e(s)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", out)


def cwe_name(c) -> str:
    return CWE.get(c or "", c or "Security issue")


def when(iso) -> str:
    if not iso:
        return "–"
    try:
        return datetime.datetime.fromisoformat(str(iso).replace("Z", "")).strftime("%-d %B %Y, %H:%M")
    except ValueError:
        return str(iso)


def secs(n) -> str:
    if n is None:
        return "–"
    n = round(float(n))
    return f"{n // 60}m {n % 60:02d}s" if n >= 60 else f"{n}s"


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def drop_reason(f: dict) -> str:
    if f.get("supported") is False:
        return f.get("unsupported_reason") or "The cited evidence did not check out"
    if f.get("kev_verdict") == "not_real":
        return "The judge ruled it not real"
    if f.get("not_judged_reason"):
        return "Not judged: " + f["not_judged_reason"].replace("-", " ")
    return "Not reported"


def code_excerpt(diff: dict | None, path: str, line, radius: int = 4) -> str:
    """The lines of the change around a finding, from the review's diff, with the flagged line marked."""
    if not diff or not diff.get("available") or not line:
        return ""
    for fd in diff.get("files", []):
        if fd.get("path") != path:
            continue
        rows = [l for h in fd.get("hunks", []) for l in h.get("lines", [])]
        idx = next((i for i, l in enumerate(rows) if l.get("new") == int(line)), None)
        if idx is None:
            return ""
        lo, hi = max(0, idx - radius), min(len(rows), idx + radius + 1)
        out = []
        for l in rows[lo:hi]:
            kind = "add" if l.get("t") == "+" else "del" if l.get("t") == "-" else ""
            flag = " flag" if l.get("new") == int(line) else ""
            num = l.get("new") if l.get("new") is not None else l.get("old")
            out.append(f'<tr class="{kind}{flag}"><td class="ln">{e(num)}</td><td class="sg">{e(l.get("t") if l.get("t") != " " else "")}</td><td class="cd">{e(l.get("text"))}</td></tr>')
        return f'<table class="code">{"".join(out)}</table>'
    return ""


def brief_html(b: dict | None) -> str:
    if not b:
        return ""
    rows = [("Where", b.get("where")), ("Impact", b.get("impact")), ("Breaks", b.get("breaks")), ("Fix", b.get("fix"))]
    return (f'<div class="brief"><p class="bh">{rich(b.get("headline"))}</p><dl>'
            + "".join(f"<dt>{k}</dt><dd>{rich(v)}</dd>" for k, v in rows if v) + "</dl></div>")


def fix_html(f: dict) -> str:
    b = f.get("brief") or {}
    if not b.get("fix"):
        return f'<div class="fix"><h4>Suggested fix</h4><p>{rich(f.get("suggested_fix"))}</p></div>'
    code = f'<pre class="fixcode"><code>{e(b["fix_code"])}</code></pre>' if b.get("fix_code") else ""
    return f'<div class="fix"><h4>Suggested fix</h4><p>{rich(b["fix"])}</p>{code}</div>'


def report_html(detail: dict, generated: datetime.datetime | None = None) -> str:
    run = detail["run"]
    res = detail.get("result") or {}
    meta = res.get("meta") or {}
    findings = res.get("findings") or []
    flagged = [f for f in findings if f.get("flagged")]
    dropped = [f for f in findings if not f.get("flagged")]
    supported = sum(1 for f in findings if f.get("supported"))
    imported = run.get("source") == "imported"
    generated = generated or datetime.datetime.now()
    model = str(run.get("model") or meta.get("model") or "").replace("bedrock:", "") or "the reviewer model"
    tools = sum(int(meta.get(k) or 0) for k in ("investigator_tool_calls", "reviewer_tool_calls", "sast_triage_tool_calls"))
    semgrep = meta.get("semgrep_findings_in_diff")
    semgrep = len(semgrep) if isinstance(semgrep, list) else (semgrep or 0)

    # verdict
    if run.get("status") in ("queued", "running"):
        tone, head, sub = "neutral", "Review in progress", "This report shows the review as it stands; download it again when the review finishes."
    elif res.get("verdict") == "error" or run.get("status") == "failed":
        tone, head, sub = "neutral", "The review did not finish", run.get("error") or "The pipeline reported an error."
    elif flagged:
        blocked = run.get("conclusion") == "blocked"
        tone = "bad"
        head = f"{'Blocked' if blocked else 'Findings'}: {plural(len(flagged), 'security finding')}"
        sub = ("The merge is blocked by the severity policy until the findings are fixed or dismissed."
               if blocked else "Reported on the pull request; none is at or above the blocking severity.")
    else:
        tone, head, sub = "good", "Passed: no security findings", "Every changed Python file was reviewed for SQL injection and broken authorization. Nothing could be backed by evidence."
    if imported and run.get("outcome"):
        sub = f"Benchmark run, scored against the published advisory: LGTM {OUTCOME.get(run['outcome'], run['outcome'])}."

    facts = [
        ("Repository", e(run.get("repo"))),
        ("Pull request", f"#{e(run.get('pr_number'))}" if run.get("pr_number") else "–"),
        ("Branch", f"<code>{e(run.get('head_ref'))}</code> into <code>{e(run.get('base_ref'))}</code>" if run.get("head_ref") else "–"),
        ("Commit reviewed", f"<code>{e((run.get('head_sha') or meta.get('pr_sha') or '')[:12]) or '–'}</code>"),
        ("Author", e(run.get("author") or "–")),
        ("Reviewed", e(when(run.get("started_at") or run.get("created_at")))),
        ("Review time", e(secs(run.get("latency") or meta.get("latency_seconds")))),
        ("Reviewer model", e(model)),
        ("Evidence judge", "Claude (stand-in for Kev)" if run.get("judge") == "claude" else "Kev-4B"),
        ("Changed Python files", e(meta.get("python_files_changed", "–"))),
        ("Lines added", e(meta.get("added_lines", "–"))),
        ("Agent tool calls", e(tools)),
        ("Semgrep hits in the diff", e(semgrep)),
        ("Source", "Benchmark harness on a cached clone (never posted to GitHub)" if imported else "LGTM GitHub App"),
    ]
    if imported and (meta.get("cve") or meta.get("advisory_title")):
        facts.append(("Advisory", e(" ".join(x for x in (meta.get("advisory_title"), f"({meta['cve']})" if meta.get("cve") else "") if x))))

    def bar(n, of, cls=""):
        pct = 100 * n / of if of else 0
        return f'<div class="bar {cls}"><span style="width:{max(pct, 1.5 if n else 0):.1f}%"></span></div>'

    total = max(1, len(findings))
    funnel = f"""
      <div class="funnel">
        <div class="frow"><span class="fl">Raised by the agents</span>{bar(len(findings), total)}<b>{len(findings)}</b></div>
        <div class="frow"><span class="fl">Evidence holds up</span>{bar(supported, total)}<b>{supported}</b></div>
        <div class="frow"><span class="fl">Confirmed and reported</span>{bar(len(flagged), total, 'hot')}<b>{len(flagged)}</b></div>
      </div>"""

    summary_rows = "".join(
        f'<tr><td>{i}</td><td><span class="sev {e(f.get("severity"))}">{e((f.get("severity") or "unrated").title())}</span></td>'
        f'<td>{e(cwe_name(f.get("cwe")))} <span class="muted">{e(f.get("cwe") or "")}</span></td>'
        f'<td><code>{e(f.get("file"))}:{e(f.get("line"))}</code></td>'
        f'<td>{"Confirmed" if f.get("kev_verdict") == "real" else e(f.get("kev_verdict") or "Not judged")}</td>'
        f'<td>{e(TRIAGE.get(f.get("triage"), f.get("triage")))}</td></tr>'
        for i, f in enumerate(flagged, 1))

    def evidence(f):
        items = [x for x in (f.get("evidence") or []) if x.get("content")]
        code = [x for x in items if x.get("type") != "policy"][:2]
        policy = [x for x in items if x.get("type") == "policy"][:1]
        out = []
        for x in code:
            lines = x.get("lines")
            where = f'{x.get("file") or ""}{":" + "–".join(str(v) for v in lines) if isinstance(lines, list) and lines else ""}'
            note = "in this change" if x.get("grounded_in_pr") else "existing code"
            body = x["content"].strip()
            if len(body) > 1400:
                body = body[:1400] + "\n…"
            out.append(f'<div class="ev"><p class="ev-h"><code>{e(where)}</code><span class="muted">{note}</span></p><pre>{e(body)}</pre></div>')
        for x in policy:
            text = x["content"].strip()
            out.append(f'<blockquote class="policy"><p class="ev-h"><span class="muted">From the repository\'s security policy</span></p>{rich(text[:700])}{"…" if len(text) > 700 else ""}</blockquote>')
        return "".join(out)

    sections = []
    for i, f in enumerate(flagged, 1):
        jn = "Claude judge" if run.get("judge") == "claude" else "Kev judge"
        judge = (f"Confirmed by the {jn}" if f.get("kev_verdict") == "real" else f"{jn}: {e(f.get('kev_verdict') or 'not judged')}")
        conf = f" (confidence {f['confidence']:.0%})" if isinstance(f.get("confidence"), (int, float)) else ""
        excerpt = code_excerpt(res.get("diff") or detail.get("diff"), f.get("file"), f.get("line"))
        sections.append(f"""
        <section class="finding">
          <header class="fh">
            <span class="fnum">{i}</span>
            <div><h3>{e(cwe_name(f.get("cwe")))} <span class="muted">{e(f.get("cwe") or "")}</span></h3>
              <p class="fmeta"><span class="sev {e(f.get("severity"))}">{e((f.get("severity") or "unrated").title())}</span>
                <code>{e(f.get("file"))}:{e(f.get("line"))}</code><span>{judge}{conf}</span>
                <span>Status: {e(TRIAGE.get(f.get("triage"), f.get("triage")))}</span></p></div>
          </header>
          {brief_html(f.get("brief"))}
          {'<h4>Full reasoning</h4>' if f.get("brief") else ''}<p class="why">{rich(f.get("explanation"))}</p>
          {f'<h4>The flagged change</h4>{excerpt}' if excerpt else ''}
          {fix_html(f) if f.get("suggested_fix") else ''}
          {f'<h4>Evidence the agents cited</h4>{evidence(f)}' if any(x.get("content") for x in f.get("evidence") or []) else ''}
          <p class="found-by">Found by the {e(AGENTS.get(f.get("agent"), f.get("agent") or "reviewer"))} with {plural(int(f.get("tool_calls") or 0), "tool call")}.</p>
        </section>""")

    dropped_rows = "".join(
        f'<tr><td>{e(cwe_name(f.get("cwe")))}</td><td><code>{e(f.get("file"))}:{e(f.get("line"))}</code></td>'
        f'<td>{e(AGENTS.get(f.get("agent"), f.get("agent") or ""))}</td><td>{e(drop_reason(f))}</td></tr>' for f in dropped)
    trail = "".join(
        f'<tr><td>{e(AGENTS.get(t.get("agent"), t.get("agent")))}</td><td class="muted">{e(t.get("label") if t.get("label") != t.get("agent") else "")}</td>'
        f'<td class="num">{t.get("turns", "–")}</td><td class="num">{len(t.get("calls") or [])}</td></tr>'
        for t in ((res.get("trace") or {}).get("runs") or []))

    title = run.get("pr_title") or meta.get("title") or "Pull request review"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>LGTM security review: {e(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap">
<style>{CSS}</style></head>
<body>
<main>
  <header class="top">
    <div class="brand"><svg viewBox="0 0 24 24"><path d="M12 2.5 4 5.5v6.2c0 4.6 3.3 8.5 8 9.8 4.7-1.3 8-5.2 8-9.8V5.5z"/><path d="m8.5 12.2 2.4 2.4 4.8-5" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>LGTM</span></div>
    <div class="doc">Security review report<br><span class="muted">{e(generated.strftime("%-d %B %Y"))} · {e(run.get("id"))}</span></div>
  </header>

  <h1>{e(title)}{f' <span class="muted">#{e(run.get("pr_number"))}</span>' if run.get("pr_number") else ''}</h1>
  <p class="repo">{e(run.get("repo"))}</p>

  <div class="verdict {tone}"><p class="vh">{e(head)}</p><p class="vs">{e(sub)}</p></div>

  <div class="cols">
    <dl class="facts">{"".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in facts)}</dl>
    <div class="side">
      <h2>How the candidates were narrowed</h2>
      {funnel}
      <p class="note">Every candidate must cite code that exists, and the evidence judge must agree the evidence proves the bug, before it reaches the pull request.</p>
    </div>
  </div>

  {f'''<h2>Findings</h2>
  <table class="sum"><thead><tr><th>#</th><th>Severity</th><th>Issue</th><th>Location</th><th>Judge</th><th>Status</th></tr></thead><tbody>{summary_rows}</tbody></table>
  {"".join(sections)}''' if flagged else '<h2>Findings</h2><p class="none">No security findings. LGTM reports a bug only when it can point at the lines that prove it.</p>'}

  {f'''<section class="appendix"><h2>Candidates LGTM checked and did not report</h2>
  <table class="sum"><thead><tr><th>Issue</th><th>Location</th><th>Raised by</th><th>Why it was dropped</th></tr></thead><tbody>{dropped_rows}</tbody></table></section>''' if dropped else ''}

  {f'''<section class="appendix"><h2>Review trail</h2>
  <table class="sum"><thead><tr><th>Agent</th><th>Section</th><th class="num">Turns</th><th class="num">Tool calls</th></tr></thead><tbody>{trail}</tbody></table></section>''' if trail else ''}

  <p class="end">Generated by LGTM from review {e(run.get("id"))}. Findings come from LLM agents checked by an evidence validator and an evidence judge; treat them as a reviewer's comments, not a guarantee.</p>
</main>
</body></html>"""


CSS = r"""
@page { size: A4; margin: 18mm 16mm 20mm; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font: 10pt/1.5 Inter, -apple-system, "Helvetica Neue", Arial, sans-serif; color: #111; }
main { max-width: 178mm; margin: 0 auto; }
code, pre { font-family: "JetBrains Mono", ui-monospace, Menlo, monospace; font-size: 8.5pt; }
code { background: #f3f3f3; border-radius: 3px; padding: 0 3px; }
.muted { color: #6b6b6b; font-weight: 400; }
.top { display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 10px; border-bottom: 2px solid #111; margin-bottom: 22px; }
.brand { display: flex; align-items: center; gap: 7px; font-weight: 700; font-size: 15pt; letter-spacing: -.02em; }
.brand svg { width: 22px; height: 22px; fill: #111; }
.doc { text-align: right; font-weight: 600; font-size: 10pt; line-height: 1.35; }
.doc .muted { font-size: 8.5pt; }
h1 { font-size: 20pt; line-height: 1.15; letter-spacing: -.025em; margin: 0 0 4px; }
.repo { margin: 0 0 16px; color: #555; font-size: 10.5pt; }
h2 { font-size: 12pt; letter-spacing: -.01em; margin: 22px 0 8px; }
h3 { font-size: 12pt; margin: 0 0 4px; letter-spacing: -.01em; }
h4 { font-size: 9pt; text-transform: none; color: #444; margin: 12px 0 5px; }
.verdict { border-radius: 8px; padding: 12px 16px; margin: 0 0 18px; border: 1px solid; }
.verdict.bad { background: #fdecec; border-color: #f2b8b8; color: #a3161c; }
.verdict.good { background: #e8f5ec; border-color: #b4dcc0; color: #116329; }
.verdict.neutral { background: #f3f3f3; border-color: #ddd; color: #333; }
.vh { font-size: 15pt; font-weight: 700; letter-spacing: -.02em; margin: 0 0 2px; }
.vs { margin: 0; color: inherit; opacity: .9; }
.cols { display: grid; grid-template-columns: 1.15fr .85fr; gap: 22px; align-items: start; }
.facts { margin: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px; }
.facts div { padding: 5px 0; border-bottom: 1px solid #eee; break-inside: avoid; }
.facts dt { color: #6b6b6b; font-size: 8pt; }
.facts dd { margin: 0; font-weight: 500; overflow-wrap: anywhere; }
.side h2 { margin-top: 0; font-size: 10.5pt; }
.funnel { display: grid; gap: 7px; }
.frow { display: grid; grid-template-columns: 34mm 1fr 8mm; align-items: center; gap: 8px; font-size: 9pt; }
.frow b { text-align: right; }
.bar { height: 8px; background: #efefef; border-radius: 4px; overflow: hidden; }
.bar span { display: block; height: 100%; background: #111; border-radius: 4px; }
.bar.hot span { background: #d93036; }
.note { color: #6b6b6b; font-size: 8.5pt; margin: 8px 0 0; }
table.sum { width: 100%; border-collapse: collapse; font-size: 9pt; margin-bottom: 6px; }
table.sum th { text-align: left; font-weight: 600; color: #555; border-bottom: 1.5px solid #111; padding: 5px 6px; }
table.sum td { border-bottom: 1px solid #eee; padding: 6px; vertical-align: top; }
table.sum tr { break-inside: avoid; }
.num { text-align: right; }
.sev { display: inline-block; font-weight: 600; font-size: 8pt; padding: 0 6px; border-radius: 3px; color: #fff; background: #777; }
.sev.critical { background: #8e24aa; } .sev.high { background: #d93036; } .sev.medium { background: #c56a00; } .sev.low { background: #8a7a00; }
.finding { margin-top: 18px; padding-top: 14px; border-top: 1px solid #ddd; break-inside: auto; }
.fh { display: flex; gap: 12px; align-items: flex-start; break-after: avoid; }
.fnum { flex: none; width: 24px; height: 24px; border-radius: 50%; background: #111; color: #fff; font-weight: 700; display: grid; place-items: center; font-size: 10pt; }
.fmeta { margin: 0; display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: center; font-size: 9pt; color: #444; }
.why { margin: 10px 0 0; color: #444; font-size: 9pt; }
.fixcode { margin: 6px 0 0; padding: 8px 10px; background: #f6f6f6; border-radius: 4px; font-size: 8.5pt; white-space: pre-wrap; }
.brief { margin: 10px 0 0; padding: 10px 12px; border: 1px solid #e3e3e3; border-radius: 6px; break-inside: avoid; }
.brief .bh { margin: 0 0 6px; font-weight: 600; font-size: 11pt; }
.brief dl { margin: 0; display: grid; grid-template-columns: 16mm 1fr; gap: 3px 10px; }
.brief dt { color: #6b6b6b; font-size: 8.5pt; padding-top: 1px; }
.brief dd { margin: 0; }
table.code { width: 100%; border-collapse: collapse; font: 8pt/1.55 "JetBrains Mono", ui-monospace, Menlo, monospace; border: 1px solid #e3e3e3; border-radius: 4px; break-inside: avoid; }
table.code td { padding: 0 6px; white-space: pre-wrap; word-break: break-all; vertical-align: top; }
table.code .ln { width: 1%; color: #999; text-align: right; white-space: nowrap; }
table.code .sg { width: 1%; color: #999; }
table.code tr.add td { background: #eef9f1; }
table.code tr.del td { background: #fdeeee; }
table.code tr.flag td { background: #fde2e2; }
table.code tr.flag td.ln { box-shadow: inset 3px 0 0 #d93036; color: #a3161c; font-weight: 600; }
.fix { margin-top: 12px; padding: 8px 12px 10px; background: #f4f7ff; border-left: 3px solid #0b62d6; border-radius: 0 4px 4px 0; break-inside: avoid; }
.fix h4 { margin-top: 0; color: #0b4fae; }
.fix p { margin: 0; }
.ev { margin: 0 0 8px; break-inside: avoid; }
.ev-h { display: flex; gap: 10px; align-items: baseline; margin: 0 0 3px; font-size: 8.5pt; }
.ev pre { margin: 0; padding: 7px 9px; background: #f7f7f7; border-radius: 4px; white-space: pre-wrap; word-break: break-word; font-size: 7.8pt; line-height: 1.5; }
blockquote.policy { margin: 0 0 8px; padding: 6px 10px; border-left: 3px solid #ccc; color: #333; font-size: 9pt; break-inside: avoid; white-space: pre-line; }
.found-by { color: #6b6b6b; font-size: 8.5pt; margin: 10px 0 0; }
.none { padding: 10px 14px; background: #f6f6f6; border-radius: 6px; }
.appendix { break-inside: auto; }
.appendix h2 { margin-top: 26px; }
.end { margin-top: 28px; padding-top: 10px; border-top: 1px solid #ddd; color: #8a8a8a; font-size: 8pt; }
@media screen { body { background: #e9e9e9; padding: 24px 0; } main { background: #fff; padding: 18mm 16mm; box-shadow: 0 2px 14px rgba(0,0,0,.12); max-width: 210mm; } }
"""


def chrome_path() -> str | None:
    for c in CHROME:
        if Path(c).exists():
            return c
        found = shutil.which(c)
        if found:
            return found
    return None


def report_pdf(page: str) -> bytes:
    """Print the report page to PDF with headless Chrome, in a throwaway profile so the user's Chrome is untouched."""
    chrome = chrome_path()
    if not chrome:
        raise RuntimeError("Chrome is not installed, so the PDF cannot be made. Open the HTML report and print it instead.")
    with tempfile.TemporaryDirectory(prefix="lgtm-report-") as tmp:
        src, out = Path(tmp) / "report.html", Path(tmp) / "report.pdf"
        src.write_text(page, encoding="utf-8")
        proc = subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                               f"--user-data-dir={tmp}/profile", "--no-pdf-header-footer", "--virtual-time-budget=6000",
                               f"--print-to-pdf={out}", src.as_uri()], capture_output=True, text=True, timeout=90)
        if not out.is_file() or out.stat().st_size == 0:
            raise RuntimeError(f"Chrome could not print the report: {(proc.stderr or proc.stdout).strip()[-300:]}")
        return out.read_bytes()


def filename(run: dict) -> str:
    base = f"LGTM-review-{(run.get('repo') or 'repo').split('/')[-1]}"
    if run.get("pr_number"):
        base += f"-PR{run['pr_number']}"
    if run.get("head_sha"):
        base += f"-{run['head_sha'][:7]}"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", base) + ".pdf"

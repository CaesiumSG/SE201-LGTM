"""A stand-in evidence judge: Kev's System One API, answered by Claude on Bedrock.

LGTM's pipeline sends each candidate finding to the judge as ``{"model", "state", "questions"}`` and reads back
``{"answers": {question: {"choice": ...} | {"noul": 0..1}}}``. This server speaks that protocol on
127.0.0.1:8009, so the pipeline needs no change: a review is pointed here instead of at Kev on :8008.

It is not Kev, the judge the project evaluated. Reviews it judges are labelled "Claude judge" in the dashboard
and in reports. Spend goes on the shared Bedrock ledger and stops at the server's cap.
"""

from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import workspace  # ledger_total, prices and ledger path shared with the workspace assistant

PORT = 8009
MODEL = workspace.MODEL
SYSTEM = (
    "You are the evidence judge in a security code review pipeline. Another model has raised a candidate security "
    "finding and cited code (and sometimes policy text) as evidence. Judge strictly from the cited material: a "
    "finding is supported only if the cited code itself shows the flaw, and real only if it is an exploitable "
    "vulnerability of the claimed kind, not a style issue or a hypothetical. Do not trust the claim's wording; check "
    "it against the code. Answer every question by calling the tool once."
)


class ClaudeJudge:
    def __init__(self, key: str | None, budget: float):
        self.key, self.budget = key, budget
        self.calls = 0
        self._client = None
        self._lock = threading.Lock()

    def client(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.AnthropicBedrock(api_key=self.key, aws_region="us-east-1", timeout=60, max_retries=2)
        return self._client

    def answer(self, request: dict) -> dict:
        if not self.key:
            raise RuntimeError("no Bedrock key")
        spent = workspace.ledger_total()
        if spent >= self.budget:
            raise RuntimeError(f"Bedrock spend cap reached (${spent:.2f} of ${self.budget:.2f})")
        questions = request.get("questions") or {}
        props, lines = {}, []
        for qid, q in questions.items():
            if q.get("type") == "choice":
                crit = q.get("criteria") or {}
                props[qid] = {"type": "string", "enum": list(crit), "description": q.get("instructions", "")}
                lines.append(f"## {qid}\n{q.get('instructions', '')}\n" + "\n".join(f"- {k}: {v}" for k, v in crit.items()))
            else:   # "noul": a number from 0 to 1
                props[qid] = {"type": "number", "minimum": 0, "maximum": 1, "description": q.get("instructions", "")}
                lines.append(f"## {qid}\n{q.get('instructions', '')}\nAnswer with a number from 0 (no) to 1 (certainly yes).")
        tool = {"name": "judge", "description": "Record the judge's answers.",
                "input_schema": {"type": "object", "properties": props, "required": list(props)}}
        user = f"<candidate>\n{request.get('state', '')}\n</candidate>\n\nQuestions:\n\n" + "\n\n".join(lines)
        started = time.monotonic()
        msg = self.client().messages.create(model=MODEL, max_tokens=600, system=SYSTEM, tools=[tool],
                                            tool_choice={"type": "tool", "name": "judge"},
                                            messages=[{"role": "user", "content": user}])
        got = next((b.input for b in msg.content if b.type == "tool_use"), None) or {}
        usd = (msg.usage.input_tokens * workspace.PRICE_IN + msg.usage.output_tokens * workspace.PRICE_OUT) / 1e6 * workspace.PRICE_SAFETY
        with workspace._LEDGER_LOCK:
            workspace.LEDGER.parent.mkdir(parents=True, exist_ok=True)
            with workspace.LEDGER.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": MODEL, "usd": round(usd, 6),
                                     "input": msg.usage.input_tokens, "output": msg.usage.output_tokens,
                                     "seconds": round(time.monotonic() - started, 2), "run": "demo:claude-judge"}) + "\n")
        answers = {}
        for qid, q in questions.items():
            v = got.get(qid)
            if q.get("type") == "choice":
                if v not in (q.get("criteria") or {}):
                    raise RuntimeError(f"Claude gave no valid answer to {qid}")
                answers[qid] = {"choice": v}
            else:
                answers[qid] = {"noul": max(0.0, min(1.0, float(v if isinstance(v, (int, float)) else 0.5)))}
        with self._lock:
            self.calls += 1
        return {"answers": answers, "usage": {"input_tokens": msg.usage.input_tokens}, "judge": "claude", "model": MODEL}


def serve(key: str | None, budget: float) -> ClaudeJudge:
    """Start the stand-in judge on 127.0.0.1:8009 in a daemon thread."""
    judge = ClaudeJudge(key, budget)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):   # quiet: the review log records judge outcomes
            pass

        def reply(self, payload, status=HTTPStatus.OK):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") == "/v1/models":
                return self.reply({"models": [{"name": "claude-judge", "description": f"Claude ({MODEL}) answering Kev's questions"}],
                                   "ready": bool(judge.key)})
            self.reply({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self):  # noqa: N802
            if self.path.rstrip("/") != "/v1/systemone":
                return self.reply({"error": "not found"}, HTTPStatus.NOT_FOUND)
            try:
                request = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                self.reply(judge.answer(request))
            except Exception as exc:  # noqa: BLE001 - the pipeline marks this candidate "judge-failed"
                self.reply({"error": str(exc)[:300]}, HTTPStatus.BAD_GATEWAY)

    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, name="claude-judge", daemon=True).start()
    return judge

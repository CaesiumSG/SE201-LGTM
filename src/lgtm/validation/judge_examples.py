"""Synthetic worked examples appended to each judge question's instructions in the few-shot request."""

from __future__ import annotations

EXAMPLES: dict[str, str] = {
    "supported": (
        "Worked examples for the supported question:\n"
        "Example A. Cited code: query = \"SELECT * FROM notes WHERE owner = '\" + owner + \"'\"; "
        "claim: SQL built from the owner parameter. Answer: yes.\n"
        "Example B. Cited code: cur.execute(\"SELECT * FROM notes WHERE owner = %s\", (owner,)); "
        "claim: SQL built from the owner parameter. Answer: no."
    ),
    "verdict": (
        "Worked examples for the verdict question:\n"
        "Example C. A login handler redirects to the address in the next query parameter with no "
        "check on the target host, and the claim names an open redirect. Answer: real.\n"
        "Example D. A login handler redirects only to targets whose host is on a fixed allowlist, "
        "yet the claim names an open redirect. Answer: not_real."
    ),
    "severity": (
        "Worked examples for the severity question:\n"
        "Example E. Any visitor can upload a script of any file type into the web served folder "
        "and have the server run it. Answer: critical.\n"
        "Example F. The session cookie of a site served only over HTTPS is missing the Secure "
        "flag. Answer: low."
    ),
    "provenance_confidence": (
        "Worked examples for the provenance_confidence question:\n"
        "Example G. The cited lines are the function the claim describes and show the flaw. "
        "Answer: yes.\n"
        "Example H. The cited lines are an unrelated import block that never touches the claimed flaw. "
        "Answer: no."
    ),
}

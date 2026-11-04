"""Short authored criteria per CWE, shown to the Kev judge in the short_claim and code_first formats."""

from __future__ import annotations

CWE_CRITERIA: dict[str, str] = {
    "CWE-22": "Flawed when a file path built from untrusted input reaches a file operation without being confined to an intended directory.",
    "CWE-77": "Flawed when untrusted input is placed into a command string that is then interpreted as a command.",
    "CWE-78": "Flawed when untrusted input reaches an operating system command or shell invocation without being passed as separate arguments or neutralized.",
    "CWE-79": "Flawed when untrusted input is written into an HTML page without output encoding or sanitizing.",
    "CWE-89": "Flawed when untrusted input is concatenated or formatted into an SQL statement instead of being passed as bound parameters. Code with no SQL, or with parameterized queries, is not flawed.",
    "CWE-94": "Flawed when untrusted input is evaluated or compiled as code.",
    "CWE-200": "Flawed when sensitive data is returned or logged to a party that is not authorized to see it.",
    "CWE-285": "Flawed when an operation runs without a check that the caller is allowed to perform it.",
    "CWE-287": "Flawed when the identity of a caller is accepted without being proven, or the proof is checked incorrectly.",
    "CWE-306": "Flawed when a sensitive function can be reached without any authentication check.",
    "CWE-352": "Flawed when a state-changing request is accepted without a token or check that the user intended it.",
    "CWE-434": "Flawed when an uploaded file is stored or executed without checking its type, name, and destination.",
    "CWE-502": "Flawed when untrusted data is deserialized with a mechanism that can create arbitrary objects.",
    "CWE-639": "Flawed when a record is fetched by a caller-supplied identifier without checking that the caller owns or may access that record.",
    "CWE-798": "Flawed when a secret, password, or key is written into the source code.",
    "CWE-862": "Flawed when an operation on a resource has no authorization check at all. Code that performs the check is not flawed.",
    "CWE-863": "Flawed when an authorization check exists but is wrong, incomplete, or compares the wrong subject or resource.",
    "CWE-918": "Flawed when a server fetches a URL supplied by the caller without restricting the destination.",
}

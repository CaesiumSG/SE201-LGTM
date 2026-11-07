"""SQL Injection Reviewer Agent.

Reviews the same changed-code sections as the authorization reviewer, for
SQL injection (CWE-89), without waiting for Semgrep to flag a line. Semgrep's
rules only match a few sink shapes; on real pull requests SQL is often built
by helpers, template filters or string formatting that no rule matches, so
SAST-seeded triage alone never looks at it.

Only sections whose code shows a SQL signal (SQL keywords in strings, query
APIs, raw-SQL helpers) are reviewed, so purely non-SQL changes cost nothing.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from lgtm.agents.authz_reviewer import AuthzReviewerAgent, _enclosing_block
from lgtm.agents.tools import AgentToolbox

if TYPE_CHECKING:
    from lgtm.review.sections import Section

# SQL keywords as they appear in hand-written SQL text (upper case).
_SQL_KEYWORDS = re.compile(
    r"\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|WHERE|ORDER\s+BY|"
    r"GROUP\s+BY|JOIN|UNION|EXPLAIN|HAVING|LIMIT|OFFSET|IN\s*\()\b"
)
# Query APIs and helpers that build or run SQL text.
_SQL_APIS = re.compile(
    r"(?i)sql|cursor|\.execute|executemany|query_raw|execute_raw|\.raw\(|rawsql|"
    r"\.extra\(|\btext\(|literal_column|\bwhere|\bquote|\bescape|order_by|sort_by"
)


def needs_sql_review(section: Section, toolbox: AgentToolbox) -> bool:
    """True when the section's code or its enclosing functions show a SQL signal."""
    from lgtm.review.sections import render_section

    text = render_section(section) + "\n" + _enclosing_block(toolbox, section)
    return bool(_SQL_KEYWORDS.search(text) or _SQL_APIS.search(text))


class SQLiReviewerAgent(AuthzReviewerAgent):
    PROMPTS = "sqli_reviewer"
    AGENT = "sqli_reviewer"
    CATEGORY = "sqli"
    DEFAULT_CWE = "CWE-89"

    def _record_name(self, section: Section) -> str:
        return f"sqli:{section.section_id}"

    def _guidance(self) -> str:
        return ""

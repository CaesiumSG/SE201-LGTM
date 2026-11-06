"""The SQL-signal screen that decides which sections get the SQLi pass."""

from lgtm.agents.sqli_reviewer import needs_sql_review
from lgtm.agents.tools import AgentToolbox
from lgtm.review.sections import HunkRef, LineChange, Section


def _section(*added: str) -> Section:
    changes = [LineChange("add", line, None, n) for n, line in enumerate(added, 1)]
    hunk = HunkRef(
        hunk_id="m.py#1", file="m.py", old_start=1, old_count=0, new_start=1,
        new_count=len(added), change="add", changes=changes,
    )
    return Section(section_id="s", origin="investigator", title="t", files=["m.py"], hunks=[hunk], rationale="r")


BOX = AgentToolbox(".", "HEAD")


def test_a_hand_rolled_quoting_helper_is_screened_in():
    # superset GHSA-jfxj-xf67-x723: an IN-list built by string quoting, no SQL keyword in it
    assert needs_sql_review(_section(
        'def where_in(values, mark="\'"):',
        "    def quote(value):",
        "        return f\"{mark}{value}{mark}\"",
        '    return f"({", ".join(quote(v) for v in values)})"',
    ), BOX)


def test_sql_text_built_from_option_names_is_screened_in():
    # django GHSA-w24h-v9qh-8gxj: EXPLAIN options formatted into the prefix
    assert needs_sql_review(_section(
        "    explain_prefix = 'EXPLAIN'",
        "        prefix += ' (%s)' % ', '.join('%s %s' % i for i in extra.items())",
    ), BOX)


def test_a_change_with_no_sql_signal_is_skipped():
    assert not needs_sql_review(_section(
        "@app.route('/profile')",
        "def profile():",
        "    return render_template('profile.html', user=current_user)",
    ), BOX)

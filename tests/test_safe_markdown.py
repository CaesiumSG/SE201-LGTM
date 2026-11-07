"""Tests for safe_markdown in demo/github_app.py."""

from __future__ import annotations

import pytest

from demo.github_app import safe_markdown

WJ = "\u2060"


class TestSafeMarkdownMentions:
    def test_single_user_mention_defanged(self):
        text = "Please review this PR, @alice."
        assert safe_markdown(text, "cyberjj999") == f"Please review this PR, @{WJ}alice."

    def test_org_team_mention_defanged(self):
        text = "Notifying @github/security-team about this issue."
        assert safe_markdown(text, "cyberjj999") == f"Notifying @{WJ}github/security-team about this issue."

    def test_mention_at_start_of_string(self):
        text = "@bob check this out"
        assert safe_markdown(text, "cyberjj999") == f"@{WJ}bob check this out"

    def test_mention_in_parentheses_and_brackets(self):
        text = "pinging (@charlie) and [@david]"
        assert safe_markdown(text, "cyberjj999") == f"pinging (@{WJ}charlie) and [@{WJ}david]"

    def test_email_address_not_treated_as_mention(self):
        text = "Contact support@example.com or user.name+tag@domain.co.uk for assistance."
        assert safe_markdown(text, "cyberjj999") == text

    def test_email_in_parentheses_not_defanged(self):
        text = "Email us (security@company.org) if found."
        assert safe_markdown(text, "cyberjj999") == text


class TestSafeMarkdownCrossRepoReferences:
    def test_cross_repo_issue_reference_defanged(self):
        text = "Related to upstream/repo#42 and other-org/sub.project#101."
        expected = f"Related to upstream/repo#{WJ}42 and other-org/sub.project#{WJ}101."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_cross_repo_commit_sha_defanged(self):
        text = "Introduced in upstream/repo@a1b2c3d."
        expected = f"Introduced in upstream/repo@{WJ}a1b2c3d."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_own_owner_repo_issue_reference_defanged(self):
        # All cross-repo shorthand is defanged to avoid unexpected backlinks
        text = "See cyberjj999/shoply-demo#5."
        expected = f"See cyberjj999/shoply-demo#{WJ}5."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_standalone_issue_and_gh_defanged(self):
        text = "Fixes #123 and GH-456."
        expected = f"Fixes #{WJ}123 and GH-{WJ}456."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_hash_not_followed_by_digits_untouched(self):
        text = "Using C# and #include <stdio.h> or #define DEBUG."
        assert safe_markdown(text, "cyberjj999") == text


class TestSafeMarkdownGitHubLinks:
    def test_link_to_another_owner_removed(self):
        text = "Upstream PR: https://github.com/taigaio/taiga-back/pull/123."
        expected = "Upstream PR: (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_link_to_own_owner_preserved(self):
        text = "Our run: https://github.com/cyberjj999/shoply-demo/actions/runs/999"
        assert safe_markdown(text, "cyberjj999") == text

    def test_http_and_www_links_to_another_owner_removed(self):
        text = "See http://github.com/victim/repo and https://www.github.com/victim/repo/issues/1."
        expected = "See (link removed) and (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_link_inside_parentheses(self):
        text = "Check the docs (https://github.com/other/project)."
        expected = "Check the docs ((link removed))."
        assert safe_markdown(text, "cyberjj999") == expected


class TestSafeMarkdownMarkdownLinks:
    def test_markdown_link_to_external_repo(self):
        text = "Refer to [the upstream advisory](https://github.com/advisories/GHSA-xxxx)."
        expected = "Refer to the upstream advisory (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_markdown_link_with_same_label_and_url(self):
        text = "See [https://github.com/other/repo](https://github.com/other/repo) for details."
        expected = "See (link removed) for details."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_markdown_link_to_own_owner_preserved(self):
        text = "Review [our PR](https://github.com/cyberjj999/shoply-demo/pull/12)."
        assert safe_markdown(text, "cyberjj999") == text

    def test_markdown_link_with_mention_in_label(self):
        text = "Reported by [@maintainer](https://github.com/upstream/project/issues/1)."
        expected = f"Reported by @{WJ}maintainer (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_markdown_link_with_title(self):
        text = 'See [advisory](https://github.com/other/repo "Security Advisory") and [blog](https://github.com/other/repo/blog \'Details\').'
        expected = "See advisory (link removed) and blog (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_markdown_link_with_title_to_own_owner_preserved(self):
        text = 'Review [our PR](https://github.com/cyberjj999/shoply-demo/pull/12 "Internal PR").'
        assert safe_markdown(text, "cyberjj999") == text

    def test_markdown_link_with_title_same_label_and_url(self):
        text = 'Check [https://github.com/other/repo](https://github.com/other/repo "Title").'
        expected = "Check (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected


class TestSafeMarkdownCodeSpansAndBlocks:
    def test_links_inside_inline_code_preserved(self):
        text = "Inspect `https://github.com/other/repo/commit/1234` in the diff."
        assert safe_markdown(text, "cyberjj999") == text

    def test_mentions_and_decorators_inside_inline_code_preserved(self):
        text = "Add `@login_required` or `@app.route('/test')` above the handler."
        assert safe_markdown(text, "cyberjj999") == text

    def test_links_and_decorators_inside_fenced_code_block_preserved(self):
        code_block = (
            "```python\n"
            "# Ref: https://github.com/django/django/pull/999\n"
            "@login_required\n"
            "@permission_required('admin')\n"
            "def view_orders(request):\n"
            "    # fixes #42\n"
            "    pass\n"
            "```"
        )
        text = f"Suggested fix:\n\n{code_block}\n\ncc @alice."
        expected = f"Suggested fix:\n\n{code_block}\n\ncc @{WJ}alice."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_tilde_code_blocks_preserved(self):
        code_block = (
            "~~~bash\n"
            "git clone https://github.com/other/repo\n"
            "~~~\n"
        )
        assert safe_markdown(code_block, "cyberjj999") == code_block

    def test_escaped_backticks_not_treated_as_code_span(self):
        # In CommonMark, backslash-escaped backticks are literal text, not code spans.
        # Mentions inside them render as text on GitHub and must be defanged.
        text1 = r"x \`@alice\` y"
        expected1 = f"x \\`@{WJ}alice\\` y"
        assert safe_markdown(text1, "cyberjj999") == expected1

        text2 = r"x \`@alice` y"
        expected2 = f"x \\`@{WJ}alice` y"
        assert safe_markdown(text2, "cyberjj999") == expected2

    def test_midline_tildes_not_treated_as_code_block(self):
        # Tildes only open a fence at the start of a line (up to 3 spaces).
        # Mid-line ~~~ is text/strikethrough on GitHub, so @mentions and cross-repo refs must be defanged.
        text = "strike ~~~ @alice ~~~ end and other/repo#123"
        expected = f"strike ~~~ @{WJ}alice ~~~ end and other/repo#{WJ}123"
        assert safe_markdown(text, "cyberjj999") == expected

    def test_code_span_split_by_blank_line_not_treated_as_code(self):
        # In CommonMark, code spans cannot contain blank lines.
        # Backtick fences must start a line; mid-line ``` does not open a fence.
        text_fence = "Type ``` to open a fence.\n\n@alice\n\nclose with ```"
        expected_fence = f"Type ``` to open a fence.\n\n@{WJ}alice\n\nclose with ```"
        assert safe_markdown(text_fence, "cyberjj999") == expected_fence

        text_span = "Type ` to open\n\n@alice\n\nclose `"
        expected_span = f"Type ` to open\n\n@{WJ}alice\n\nclose `"
        assert safe_markdown(text_span, "cyberjj999") == expected_span

        text_inline = "`before\n\n@alice\n\nafter`"
        expected_inline = f"`before\n\n@{WJ}alice\n\nafter`"
        assert safe_markdown(text_inline, "cyberjj999") == expected_inline

    def test_escaped_backslash_before_backtick_allows_code_span(self):
        # Two backslashes mean an escaped backslash, so the backtick is unescaped and forms a valid code span.
        text = r"x \\`@alice` y"
        assert safe_markdown(text, "cyberjj999") == text

    def test_code_span_across_single_newline_preserved(self):
        # A single newline without a blank line is valid within a CommonMark code span.
        text = "Code: `@login_required\n@permission_required`."
        assert safe_markdown(text, "cyberjj999") == text


class TestSafeMarkdownEdgeCases:
    def test_empty_string(self):
        assert safe_markdown("", "cyberjj999") == ""

    def test_plain_text_without_special_tokens(self):
        text = "This is a safe markdown report without any links or mentions."
        assert safe_markdown(text, "cyberjj999") == text

    def test_mixed_complex_document(self):
        text = (
            "Review from LGTM for @reviewer:\n"
            "- Upstream issue: other/repo#88\n"
            "- Contact author: brian@example.com\n"
            "- See [advisory](https://github.com/other/repo/security/advisories/GHSA-123)\n"
            "- Internal PR: https://github.com/cyberjj999/shoply-demo/pull/1\n"
            "```python\n"
            "@app.route('/debug')\n"
            "# see https://github.com/other/repo\n"
            "def debug(): pass\n"
            "```\n"
            "Follow-up with @cyberjj999 in `#general`."
        )
        expected = (
            f"Review from LGTM for @{WJ}reviewer:\n"
            f"- Upstream issue: other/repo#{WJ}88\n"
            "- Contact author: brian@example.com\n"
            "- See advisory (link removed)\n"
            "- Internal PR: https://github.com/cyberjj999/shoply-demo/pull/1\n"
            "```python\n"
            "@app.route('/debug')\n"
            "# see https://github.com/other/repo\n"
            "def debug(): pass\n"
            "```\n"
            f"Follow-up with @{WJ}cyberjj999 in `#general`."
        )
        assert safe_markdown(text, "cyberjj999") == expected

    def test_markdown_link_with_query_and_fragment(self):
        text = "See [query link](https://github.com/other/repo?tab=readme-ov-file#installation)."
        expected = "See query link (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_trailing_punctuation_varieties(self):
        text = (
            "Links: https://github.com/other/r1, https://github.com/other/r2; "
            "https://github.com/other/r3: https://github.com/other/r4."
        )
        expected = "Links: (link removed), (link removed); (link removed): (link removed)."
        assert safe_markdown(text, "cyberjj999") == expected

    def test_unclosed_backtick(self):
        text = "Check `https://github.com/other/repo in diff"
        # Since it's not a closed code span, the URL is still safely removed
        assert "(link removed)" in safe_markdown(text, "cyberjj999")


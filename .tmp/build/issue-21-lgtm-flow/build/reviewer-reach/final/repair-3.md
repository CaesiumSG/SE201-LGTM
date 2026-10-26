# Repair 3 (final-01, final-02)

src/lgtm/agents/authz_reviewer.py: _enclosing_block gives every function a hunk touches its own definition; added lines from the PR snapshot, removed lines from the base snapshot; each snapshot file parsed once per hunk. _hunk_anchor/_enclosing_function replaced by _hunk_lines/_enclosing_functions. Dedup by (label, rel, start); a base function is skipped when a same-named PR function in the same file is included. With strip_comments, each definition goes through sanitize_file_diff (local import; sanitizer imports lgtm.agents.base). Header line numbers refer to the original file.

Known limit: base dedup by name only; two same-named functions (methods of different classes) in one file — a removed-only one is hidden when the other has a PR edit.

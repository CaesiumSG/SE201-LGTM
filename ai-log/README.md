# AI use logs

Each team member keeps their own AI use log here, as required by the SE201
AI Use Disclosure Policy (v1.00). One file per member, named after them.
Edit only your own file.

| Member | Log |
|---|---|
| Lye Jia Jun | [lye-jia-jun.md](lye-jia-jun.md) |
| Brian Sng | [brian-sng.md](brian-sng.md) |
| Hsu Yati Ko | [hsu-yati-ko.md](hsu-yati-ko.md) |
| Lee Jin Rae | [lee-jin-rae.md](lee-jin-rae.md) |
| Loh Kai Zhe | [loh-kai-zhe.md](loh-kai-zhe.md) |

The team-level summary by area of work is in
[`docs/ai-use-log.md`](../docs/ai-use-log.md) and Appendix A of the
checkpoint report.

## How to log

1. Copy [`docs/project-overview/your-name.md`](../docs/project-overview/your-name.md)
   to `ai-log/<your-name>.md` and delete its example entry.
2. Add one entry per task in which an AI tool produced or substantially
   shaped work you submit: a heading with the date and a short title, the
   three fields (Tool (model), Files, Outcome: Kept, Changed or Rejected),
   and the three short sections. **How I checked it** matters most.
3. Commit each entry together with the work it describes.
4. Put an attribution trailer on every commit that contains AI-assisted
   work. Either form is accepted:

   ```text
   Assisted-by: Claude Code (Claude Opus 5.5)
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   ```

Spelling and grammar checkers, single-line editor completion, and ordinary
tools (compilers, linters, formatters, debuggers, git) are exempt. If in
doubt, log it.

## Team declaration

**Tools and what we used them for.**

- **Claude Code** (Anthropic; Claude Fable 5, Fable 5.1, Opus 5.5 and
  Sonnet 5.5): the initial LGTM pipeline, the Shoply benchmark and its test
  suite, the real-world CVE and real-PR benchmark tooling, the section and
  SQLi reviewers, later bug fixes, the demo GitHub App and dashboard, the
  final-evaluation scripts, and drafts of our documentation.
- **GitHub Copilot**: the Slurm job and deploy scripts for the GPU model
  server.
- **Google Antigravity** (Gemini Flash 3.8): prompt-injection red-teaming and
  its mitigations, and the `safe_markdown` tests and fixes in the demo App.
- **Evaluation material.** Claude Opus 5.5 labels benchmark findings under
  [`docs/kev-labeling-criteria.md`](../docs/kev-labeling-criteria.md) and
  drafted the component benchmark's gold labels, which the team has not
  fully reviewed (we report those figures as provisional). Candidate
  advisories for the real-PR sets were found with AI-assisted search; every
  advisory, commit and file was then checked against GitHub. Leads from the
  live hunt were checked against the project source by separate AI agents,
  and we reviewed their verdicts.
- **Slides**: the presentation deck was drafted with Claude from our
  committed results; its figures are taken from
  [`docs/deck-numbers.md`](../docs/deck-numbers.md), which names the run file
  behind each one.

The models LGTM itself runs at review time (Qwen3.8 27B, Kev-4B, and the
Bedrock models in the comparison) are part of the product, not development
tools; their risks are covered in the slides and in
[`docs/prompt-injection.md`](../docs/prompt-injection.md).

**How we checked the output.** Most AI-generated code reached `main` through
a pull request, the test suite was run before merging (on GitHub Actions
from 26 Oct; 3,289 tests at the final evaluation commit), and every number we report was copied from
committed benchmark run files by script rather than from AI output. Not every
change had a second reviewer: the initial implementation and the checkpoint
documents (10–18 Oct) were pushed directly to `main`, and 15 of 34 merged
pull requests were merged by their author without a recorded GitHub review.
Details are in each member's file in this folder, and AI-assisted commits
carry an `Assisted-by` or `Co-Authored-By` trailer.

## Final submission checklist

- [ ] Every member has a file here, with entries up to the final commit
      (as of 9 Nov only Lye Jia Jun's is filled in; Brian's is in PR #34)
- [x] Team declaration above updated (9 Nov); **each member to confirm it
      matches their own use before submission**, then copy it into the
      final deliverables
- [ ] Each member's reflection, added at the end of their own file: what
      they learned about using the tools effectively, where the tools were
      strong and weak, and what went wrong and what they would do differently

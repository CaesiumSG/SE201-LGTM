# AI use logs

Each team member keeps their own AI use log here, as required by the SE201
AI Use Disclosure Policy (v1.00). One file per member, named after them.
Edit only your own file.

| Member | Log |
|---|---|
| Jayce Lye | [jayce-lye.md](jayce-lye.md) |
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

We used Claude Code (Anthropic; Claude Fable 5, Fable 5.1, Opus 5.5 and
Sonnet 5.5) to generate the initial LGTM pipeline, the Shoply benchmark and
its test suite, the real-world CVE benchmark tooling, later bug fixes, and
drafts of our documentation; GitHub Copilot to write the Slurm and deploy
scripts for the GPU model server; and Google Antigravity (Gemini Flash 3.8)
for prompt-injection red-teaming and its mitigations. All AI-generated code
went through a pull request reviewed by at least one team member, the test
suite was run before merging, and every number we report was copied from
committed benchmark run files rather than from AI output. Details are in
each member's file in this folder.

## Final submission checklist

- [ ] Every member has a file here, with entries up to the final commit
- [ ] Team declaration above updated and copied into the final deliverables
- [ ] Each member's reflection: what they learned about using the tools
      effectively, where the tools were strong and weak, and what went wrong
      and what they would do differently

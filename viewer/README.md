# Report viewer

One HTML file that shows the benchmark results. It opens offline in any
browser: no server, no Ollama, no GPU.

```
python viewer/build_viewer.py          # writes viewer/lgtm-viewer.html
open viewer/lgtm-viewer.html           # or double-click it
```

The page has three levels:

- **All results:** precision, recall, F1, false alarms on safe PRs and time
  per PR for each mode of each benchmark, read from the runs' `summary.json`.
- **A benchmark:** every case with its outcome in each mode (TP, FP, FN, TN or
  ERROR). "Only cases where the modes disagree" lists the cases where LGTM and
  a baseline differ.
- **A case:** the PR diff with each finding pinned under the line it cites,
  the cited lines highlighted, the Kev judge's verdict and confidence, the
  evidence (code and policy), the suggested fix, and the agent's tool calls in
  order. The tabs switch between modes on the same PR.

`viewer/runs.json` lists the runs that go in: one directory per mode, each
holding per-case JSON and a `summary.json`. A directory that doesn't exist yet
is skipped. Diffs come from the Shoply patch files (via `labels.json`) or, for
the real-world benchmarks, from the clone cache that `fetch.py` writes; without
the cache the case page lists the findings without the diff.

The page renders run data as text only (`textContent`, never `innerHTML`),
because diffs and model output come from third-party repositories.

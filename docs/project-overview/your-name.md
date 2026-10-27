# AI Use Log: Your Name

<!--
Copy this file to ai-log/<your-name>.md in your team repository
(for example ai-log/wei-ling.md). Edit only your own file.

Add one entry per task in which an AI tool produced or substantially
shaped work you submit. Add entries as you work, and commit each entry
together with the work it describes.

Outcome is one of: Kept, Changed, Rejected.
Delete the example entry below before your first commit.
-->

## YYYY-MM-DD · Short title of the task
- **Tool (model):** 
- **Files:** 
- **Outcome:** 

### What I asked for


### How I checked it


### What I kept or changed



<!-- Example entry: delete before your first commit -->

## 2026-10-12 · Retrieval pipeline skeleton
- **Tool (model):** Claude Code (Claude Sonnet 4.5)
- **Files:** src/retrieval/pipeline.py, tests/test_chunking.py
- **Outcome:** Changed

### What I asked for
A skeleton for the retrieval pipeline: document loading, chunking,
embedding and a top-k query function.

### How I checked it
Ran the unit tests, which passed. Reviewing the chunking logic by hand
showed that the overlap was measured in characters rather than tokens,
so chunks near the limit were silently cut short.

### What I kept or changed
Kept the structure and the loader. Rewrote the chunk-overlap handling to
count tokens, and added a test for chunks at the size limit.

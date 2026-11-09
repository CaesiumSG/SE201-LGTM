#!/usr/bin/env bash
# Build the SE201 final submission zip (spec v1.02, "Project Presentation and
# Deliverables"): slides, a repository link and snapshot, supporting
# documents, and the AI use disclosure log.
#
#   scripts/make_submission.sh --slides deck.pdf [--slides deck.pptx] \
#       [--doc supporting.pdf] [--ref v-final] [--video demo.mp4] [--out dist]
#
# The snapshot is `git archive` of a committed ref, so untracked and ignored
# files (.env, .venv, local run caches, the withheld field-trial records)
# can never end up in it. Run it from any directory inside the repository.
set -euo pipefail

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ref="HEAD"
out="dist"
slides=()
videos=()
docs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --slides) slides+=("$2"); shift 2 ;;
    --doc) docs+=("$2"); shift 2 ;;
    --video) videos+=("$2"); shift 2 ;;
    --ref) ref="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown argument: $1" >&2; usage 2 ;;
  esac
done

root="$(git rev-parse --show-toplevel)"
cd "$root"

if [ ${#slides[@]} -eq 0 ]; then
  echo "error: pass the exported deck with --slides (PDF and/or PPTX)" >&2
  exit 2
fi
for f in "${slides[@]}" "${videos[@]+"${videos[@]}"}" "${docs[@]+"${docs[@]}"}"; do
  [ -f "$f" ] || { echo "error: file not found: $f" >&2; exit 2; }
done

sha="$(git rev-parse --verify "$ref^{commit}")"
short="${sha:0:7}"
remote="$(git remote get-url origin 2>/dev/null | sed -E 's#^git@github.com:#https://github.com/#; s#\.git$##')"

# Warnings: things the AI use policy requires that are still missing at $ref.
warn=0
for f in $(git ls-tree --name-only "$sha" ai-log/ | grep -v README.md); do
  body="$(git show "$sha:$f")"
  if grep -q 'YYYY-MM-DD' <<<"$body"; then
    echo "WARNING: $f is still the empty template" >&2; warn=1
  fi
  if ! grep -qi 'reflection' <<<"$body"; then
    echo "WARNING: $f has no reflection section" >&2; warn=1
  fi
done
if [ -n "$(git status --porcelain --untracked-files=no)" ] && [ "$ref" = "HEAD" ]; then
  echo "WARNING: uncommitted changes are NOT in the snapshot (it is built from $short)" >&2
fi

name="SE201-LGTM-submission-$short"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
dir="$stage/$name"
mkdir -p "$dir/1-slides" "$dir/2-repository" "$dir/3-supporting-documents" "$dir/4-ai-use-disclosure"

# 1. Slides (and optional demo videos)
cp "${slides[@]}" "$dir/1-slides/"
for v in "${videos[@]+"${videos[@]}"}"; do
  mkdir -p "$dir/3-supporting-documents/videos"
  cp "$v" "$dir/3-supporting-documents/videos/"
done

# 2. Repository link and snapshot
git archive --format=zip --prefix="SE201-LGTM-$short/" -o "$dir/2-repository/SE201-LGTM-$short.zip" "$sha"
cat > "$dir/2-repository/REPOSITORY.txt" <<EOF
Repository: ${remote:-"(no origin remote)"}
Commit:     $sha
Ref given:  $ref
Snapshot:   SE201-LGTM-$short.zip (git archive of that commit)

Setup instructions and runnable examples: README.md at the top of the
snapshot (sections "Setup" and "Usage").
EOF

# 3. Supporting documents: results, run logs, and material cut from the slides
sup="$dir/3-supporting-documents"
copy_from_ref() {  # copy_from_ref <path in repo> <destination dir>
  if git cat-file -e "$sha:$1" 2>/dev/null; then
    mkdir -p "$2"
    git show "$sha:$1" > "$2/$(basename "$1")"
  else
    echo "WARNING: $1 not found at $short" >&2
  fi
}
for f in RESULTS.md RUNLOG.md results.json; do
  copy_from_ref "benchmark/runs/final-2026-11/$f" "$sup/final-evaluation"
done
for f in deck-numbers.md deck-numbers.json real-prs-eval.md evaluation-log.md \
         real-world-eval.md field-trial.md prompt-injection.md component-bench.md \
         component-bench-results.md gpu-model-eval.md agents.md responsible-ai.md architecture.svg \
         project-proposal.md checkpoint.pdf; do
  copy_from_ref "docs/$f" "$sup/docs"
done

# 4. AI use disclosure: the ai-log folder (team declaration in its README,
#    one log per member with their reflection) and the team-level summary
mkdir -p "$dir/4-ai-use-disclosure"
git archive "$sha" ai-log | tar -x -C "$dir/4-ai-use-disclosure"
copy_from_ref "docs/ai-use-log.md" "$dir/4-ai-use-disclosure"

for d in "${docs[@]+"${docs[@]}"}"; do
  cp "$d" "$sup/"
done

demo_video="https://www.youtube.com/watch?v=wGdx2J-7w2A"
printf 'LGTM demo video: %s\n' "$demo_video" > "$sup/DEMO-VIDEO.txt"

cat > "$dir/README.txt" <<EOF
SE201 AI-Driven Software Engineering, AY2026-27 Term 1
Team "wo men ai AI": LGTM, a context-aware pull request security agent

Demo video: $demo_video

1-slides/                 presentation slides
2-repository/             repository link (REPOSITORY.txt) and snapshot of commit $short
3-supporting-documents/   final evaluation results and run log, benchmark write-ups,
                          evaluation history, the source of each number on the slides,
                          and the demo video link (DEMO-VIDEO.txt).
                          Material cut from the presentation: docs/deck-numbers.md
                          ("Extras": failure analysis, re-runs, caveats) and any
                          technical supporting document at the top of this folder.
4-ai-use-disclosure/      ai-log/ (team declaration in ai-log/README.md, one log and
                          reflection per member) and the team-level summary
EOF

mkdir -p "$out"
zip_path="$(cd "$out" && pwd)/$name.zip"
rm -f "$zip_path"
(cd "$stage" && zip -qr "$zip_path" "$name")

# Last check: no secrets or local paths in what we are about to submit.
secret_re='(^|/)\.env$|bedrock-spend|id_ed25519|/field_trial/[^/]+/[^/]+\.json$'
if { unzip -l "$zip_path"; unzip -l "$dir/2-repository/SE201-LGTM-$short.zip" | grep -v '/archive/field_trial/'; } \
    | awk '{print $NF}' | grep -E "$secret_re" >/dev/null; then
  echo "error: the zip contains a secret-looking file; not submitting this" >&2
  rm -f "$zip_path"; exit 1
fi

echo "Wrote $zip_path ($(du -h "$zip_path" | cut -f1))"
[ "$warn" -eq 0 ] || echo "There are warnings above: fix them before you submit." >&2

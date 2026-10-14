# Sourced by the sbatch scripts. LLM_SERVE_ROOT and LLM_SERVE_APP come from
# `sbatch --export` (deploy/lib.sh); the rest from cluster.env (deploy/sync.sh).

# Lmod's shell functions reference unset variables, so nounset is enabled after module setup.
set -eo pipefail
source "$LLM_SERVE_ROOT/cluster.env"
module purge
module load "$PYTHON_MODULE"
set -u

# Compute-node /tmp is node-local and not cleaned for us; keep temp data in scratch.
export TMPDIR="$SCRATCH_DIR/tmp/$SLURM_JOB_ID"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

echo "job $SLURM_JOB_ID on $SLURMD_NODENAME, release $(readlink -f "$LLM_SERVE_APP")"

# Executes a notebook's code cells as one script so output streams into the job
# log and blocking cells (serve_forever) behave as they do in a kernel. The
# notebooks therefore avoid IPython magics.
run_notebook() {
  local notebook=$1
  cd "$(dirname "$notebook")"
  python3 -c '
import json, sys
cells = json.load(open(sys.argv[1]))["cells"]
print("\n\n".join("".join(c["source"]) for c in cells if c["cell_type"] == "code"))
' "$notebook" | python3 -u -
}

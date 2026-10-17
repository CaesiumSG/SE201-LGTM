#!/bin/bash -l
#SBATCH --job-name=llm-notebook
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --gres=gpu:3090:1
#SBATCH --time=06:00:00

# Usage: notebook.sbatch <notebook path relative to model/>
source "$LLM_SERVE_APP/jobs/lib.sh"

notebook="$LLM_SERVE_APP/$1"
[[ -f "$notebook" ]] || { echo "notebook not found: $notebook" >&2; exit 1; }
run_notebook "$notebook"

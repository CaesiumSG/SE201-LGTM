#!/bin/bash -l
#SBATCH --job-name=llm-serve
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --gres=gpu:3090:1
#SBATCH --time=08:00:00

# Usage: serve.sbatch [model]   (default: DEFAULT_MODEL from cluster.env)
source "$LLM_SERVE_APP/jobs/lib.sh"

export SERVE_HEADLESS=1
[[ -n "${1:-}" ]] && export SERVE_MODEL=$1
run_notebook "$LLM_SERVE_APP/src/serve_model.ipynb"

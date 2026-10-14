#!/bin/bash -l
#SBATCH --job-name=llm-provision
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --time=02:00:00

source "$LLM_SERVE_APP/jobs/lib.sh"
run_notebook "$LLM_SERVE_APP/src/pull_models.ipynb"

#!/bin/bash -l
#SBATCH --job-name=aegis-sft
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Builds M1 training examples from the train and development cases (never test) into sft/.
set -euo pipefail
source "$HOME/aegis-sec/hpc/engine.sh"
uv run --no-sync python -m aegisbench sft --root "$DATA" --es-url "$ES_URL"

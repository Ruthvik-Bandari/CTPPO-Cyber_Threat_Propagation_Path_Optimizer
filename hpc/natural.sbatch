#!/bin/bash -l
#SBATCH --job-name=aegis-natural
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Mines SigmaHQ history for natural maintenance faults (reports/natural-mining.json) and verifies
# every pair against the global pool of verified positives (reports/natural-verified.json, ids only).
# Run before hpc/review_split.sbatch so verified rules join the split; hpc/variants.sbatch then
# writes the natural cases.
set -euo pipefail
source "$HOME/aegis-sec/hpc/engine.sh"
uv run --no-sync python -m aegisbench natural-mine --root "$DATA"
uv run --no-sync python -m aegisbench natural-verify --root "$DATA" --es-url "$ES_URL"

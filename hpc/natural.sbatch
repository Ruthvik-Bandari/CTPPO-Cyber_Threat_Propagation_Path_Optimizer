#!/bin/bash -l
#SBATCH --job-name=aegis-natural
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Mines SigmaHQ history for natural maintenance faults (shareable reports/natural-mining.json),
# then verifies them on a job-scoped pinned engine and writes natural cases (private). Uses the
# frozen split, else pass a manifest:  sbatch hpc/natural.sbatch reports/split-preview.json
set -euo pipefail
source "$HOME/aegis-sec/hpc/engine.sh"
uv run --no-sync python -m aegisbench natural-mine --root "$DATA"
ARGS=()
[ $# -ge 1 ] && ARGS=(--manifest "$DATA/$1")
uv run --no-sync python -m aegisbench natural-build --root "$DATA" --es-url "$ES_URL" "${ARGS[@]}"

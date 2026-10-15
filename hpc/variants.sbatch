#!/bin/bash -l
#SBATCH --job-name=aegis-variants
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Generates and verifies the impairment cases for every root in the split (benchmark/cases/, private)
# and writes reports/variants.json. Uses the frozen split when it exists, else pass a manifest:
#   sbatch hpc/variants.sbatch reports/split-preview.json
set -euo pipefail
source "$HOME/aegis-sec/hpc/engine.sh"
ARGS=()
[ $# -ge 1 ] && ARGS=(--manifest "$DATA/$1")
uv run --no-sync python -m aegisbench variants --root "$DATA" --es-url "$ES_URL" "${ARGS[@]}"

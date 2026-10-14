#!/bin/bash -l
#SBATCH --job-name=aegis-acquire-qc
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Download the pinned public sources (aegisbench/sources.py) and write QC reports.
set -euo pipefail
module load python/3.13.5
export PATH="$HOME/.local/bin:$PATH"
DATA="/scratch/$USER/aegis-sec/data"
mkdir -p "$DATA"
uv sync --frozen --no-dev
uv run --no-sync python -m aegisbench acquire --root "$DATA"
uv run --no-sync python -m aegisbench qc --root "$DATA"
ls -l "$DATA/manifests" "$DATA/reports"

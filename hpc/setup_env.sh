#!/bin/bash
# Run on the login node (Rocky 9, same as the compute nodes) after cloning or pulling:
#   ssh explorer 'cd ~/aegis-sec && bash hpc/setup_env.sh'       # CPU jobs
#   ssh explorer 'cd ~/aegis-sec && bash hpc/setup_env.sh gpu'   # adds torch/transformers for B2/M1
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
if [ "${1:-}" = "gpu" ]; then
  uv sync --frozen --no-dev --group gpu
else
  uv sync --frozen --no-dev
fi

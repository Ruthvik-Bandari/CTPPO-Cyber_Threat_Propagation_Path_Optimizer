#!/bin/bash
# Run once on the login node (Rocky 9, same as the compute nodes) after cloning or pulling:
#   ssh explorer 'cd ~/aegis-sec && bash hpc/setup_env.sh'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
uv sync --frozen --no-dev

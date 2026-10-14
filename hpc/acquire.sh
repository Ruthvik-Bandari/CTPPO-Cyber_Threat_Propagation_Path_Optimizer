#!/bin/bash
# Run on the transfer node (compute nodes have no internet):
#   ssh explorer-xfer 'cd ~/aegis-sec && bash hpc/acquire.sh'
# Syncs the locked environment and fetches the pinned sources with their manifests.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
DATA="/scratch/$USER/aegis-sec/data"
mkdir -p "$DATA" "/scratch/$USER/aegis-sec/logs"
uv sync --frozen --no-dev
uv run --no-sync python -m aegisbench acquire --root "$DATA"

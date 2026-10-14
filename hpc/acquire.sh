#!/bin/bash
# Run on the transfer node (compute nodes have no internet; the transfer node is CentOS 7, so it
# uses a uv-managed Python and the standard-library-only acquire step, not the project venv):
#   ssh explorer-xfer 'cd ~/aegis-sec && bash hpc/acquire.sh'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
DATA="/scratch/$USER/aegis-sec/data"
mkdir -p "$DATA" "/scratch/$USER/aegis-sec/logs"
PYTHONPATH=src uv run --no-project --python 3.12 python -m aegisbench acquire --root "$DATA"

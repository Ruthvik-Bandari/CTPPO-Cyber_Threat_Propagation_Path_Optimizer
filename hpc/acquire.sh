#!/bin/bash -l
# Run on the transfer node (compute nodes have no internet; the transfer node is CentOS 7, so it
# uses a uv-managed Python and the standard-library-only acquire step, not the project venv):
#   ssh explorer-xfer 'cd ~/aegis-sec && bash -l hpc/acquire.sh'
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
module load git/2.19.0  # system git there is 1.8
DATA="/scratch/$USER/aegis-sec/data"
mkdir -p "$DATA" "/scratch/$USER/aegis-sec/logs"
PYTHONPATH=src uv run --no-project --python 3.12 python -m aegisbench acquire --root "$DATA"

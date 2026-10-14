# HPC runbook (Northeastern Explorer)

## Access

Add an `explorer` host alias to `~/.ssh/config` pointing at `login.explorer.northeastern.edu`, and
install a key with `ssh-copy-id`. The repository is cloned at `$HOME/aegis-sec`; data lives under
`/scratch/$USER/aegis-sec/`. `uv` is installed per user (`python3 -m pip install --user uv` after
`module load python/3.13.5`).

## Jobs

| Job | Partition | Resources | Purpose |
| --- | --- | --- | --- |
| `hpc/smoke_gpu.sbatch` | `gpu-short` | 1 GPU, 5 min | Record GPU, driver, CUDA and Python |
| `hpc/acquire.sh` | transfer node | n/a | Sync the locked environment, fetch pinned sources, write manifests |
| `hpc/qc.sbatch` | `short` | 2 CPU, 8 GB, 1 h | Offline: verify manifests, write aggregate QC reports |

Compute nodes have no internet access. Anything that downloads (git, `uv sync`, model or
dataset fetches) runs on the transfer node, `xfer.discovery.neu.edu`, which shares `/home` and
`/scratch` with Explorer: `ssh explorer-xfer 'cd ~/aegis-sec && bash hpc/acquire.sh'`. Jobs then
run offline. Submit them from the repository root on the login node with `sbatch hpc/<job>.sbatch`.
Logs go to `/scratch/$USER/aegis-sec/logs/`.

## Choosing hardware by task

| Task | Hardware | Partition |
| --- | --- | --- |
| Download | transfer node | n/a |
| QC, cleaning, variant generation, Elasticsearch replay | CPU | `short` (48 h), `sharing` (1 h) |
| Smoke tests, B1 retrieval, small B2 inference | V100 32 GB or T4 | `gpu-short` (2 h), `gpu` (8 h) |
| M1 LoRA/QLoRA on a 7B to 14B model | A100 | `gpu` with `--gres=gpu:a100:1` |
| 24B to 32B comparison, long contexts, or A100 throughput measured too low | H200 (B200 if offered) | `gpu` with `--gres=gpu:h200:1` |

Always measure peak memory and throughput on a short run first, then request the smallest GPU
that fits. Measured on 2026-10-14: the `gpu` partitions expose V100 (PCIe and SXM2), T4, A100 and
H200 nodes; the smoke job ran on a Tesla V100-SXM2-32GB, driver 545.23.08, with modules
`cuda/12.8.0` and `python/3.13.5` available.

## Constraints

- No work on login nodes. Jobs only, via Slurm.
- `/scratch` is purged on the first Tuesday of each month, and the cluster is unavailable during
  that maintenance. Sources are re-fetchable from pins; anything that must survive goes to `/work`.
- Batch scripts start with `#!/bin/bash -l` so `module` is available.

Policy context: `docs/data/policy.md`, `docs/data/compliance.md`.

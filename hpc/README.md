# HPC jobs (Northeastern Explorer)

Run from a clone of this repository on the cluster at `$HOME/aegis-sec`. Data and outputs live
under `/scratch/$USER/aegis-sec/` (never inside the repository). Submit from the repo root:

```bash
sbatch hpc/smoke_gpu.sbatch     # GPU, driver and CUDA check (gpu-short, 5 min)
sbatch hpc/acquire_qc.sbatch    # pinned source download + QC reports (CPU, short)
```

GPU choice follows task size: CPU partitions for download, QC, cleaning and replay; V100/T4 on
`gpu-short` for smoke tests and small evaluations; A100 for 7B to 14B LoRA/QLoRA; H200 only for
larger models, long contexts or when measured A100 throughput is insufficient. Request the
smallest GPU that fits the measured memory.

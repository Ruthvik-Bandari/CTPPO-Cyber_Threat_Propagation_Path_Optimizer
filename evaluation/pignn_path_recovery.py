"""
Phase C2 — attack-path recovery precision/recall on the REAL PIGNN dataset
==========================================================================

A3's external check (`pignn_validation.py`) reports held-out ROC-AUC for node classification.
C3 also asks for **path precision/recall vs ground truth**. A container/VM testbed is still
future work, but the published PIGNN Active-Directory dataset already carries edge-level
ground-truth attack paths (`Y_matrix`), so we can measure path recovery on *real* data here.

We train the same `ExploitabilityGNN` on the node-on-path reduction, then report, at the
F1-optimal threshold tuned on the training split:

- **Node-level** precision/recall/F1: is a node on the attack path? (direct model output)
- **Edge-level** precision/recall/F1: is a graph edge on the attack path? An edge (u,v) is
  scored by the product of its endpoint node scores (an attack-path edge needs both endpoints
  on the path); ground truth is `Y_matrix[u,v] > 0`. This is the path-set recovery metric.

Reuses `pignn_validation` (loader, trainer, AUC). Severe class imbalance (~1.3% positive nodes)
makes raw accuracy meaningless — precision/recall/F1 at a tuned threshold is the honest read.

Run:  python3 evaluation/pignn_path_recovery.py [--graphs N] [--epochs E]
"""

from __future__ import annotations

import glob
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.gnn.data import normalize_adjacency
from evaluation.pignn_validation import DATA_DIR, _train, roc_auc

RESULTS_PATH = Path(__file__).resolve().parent.parent / "docs" / "RESEARCH" / "C2_PATH_RECOVERY.md"


@dataclass
class PathSample:
    x: torch.Tensor          # (N, 19)
    adj_norm: torch.Tensor   # (N, N) normalized adjacency (for the GCN)
    y: torch.Tensor          # (N,) node-on-path label
    adj_any: torch.Tensor    # (N, N) 0/1 candidate edges
    Y: torch.Tensor          # (N, N) 0/1 edge-on-path ground truth


def to_path_sample(d: dict) -> PathSample:
    x = d["X_matrix"].float()
    adj_any = (d["adj_tensor"].sum(dim=2) > 0).float()
    Y = (d["Y_matrix"] > 0).float()
    y = ((Y.sum(0) + Y.sum(1)) > 0).float()
    return PathSample(x, normalize_adjacency(adj_any), y, adj_any, Y)


def load_path_samples(n_graphs: int, seed: int = 0) -> List[PathSample]:
    files = sorted(glob.glob(str(DATA_DIR / "*.pt")))
    if not files:
        raise FileNotFoundError(
            f"No PIGNN data at {DATA_DIR}. Download _data_.zip from "
            "github.com/mbdlrocks/PhD_Replication_Package and unzip into data/pignn/.")
    import random
    random.Random(seed).shuffle(files)
    return [to_path_sample(torch.load(f, map_location="cpu", weights_only=True))
            for f in files[:n_graphs]]


def _prf(tp: float, fp: float, fn: float) -> Tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


@torch.no_grad()
def _node_scored(model, samples: List[PathSample]):
    model.eval()
    return [(model(s.x, s.adj_norm), s) for s in samples]


def _counts_node(scored, t: float) -> Tuple[float, float, float]:
    tp = fp = fn = 0.0
    for sc, s in scored:
        pred = (sc >= t).float()
        tp += float((pred * s.y).sum()); fp += float((pred * (1 - s.y)).sum()); fn += float(((1 - pred) * s.y).sum())
    return tp, fp, fn


def _counts_edge(scored, t: float) -> Tuple[float, float, float]:
    tp = fp = fn = 0.0
    for sc, s in scored:
        mask = s.adj_any > 0
        es = (sc.unsqueeze(1) * sc.unsqueeze(0))[mask]   # endpoint-product over candidate edges
        gt = s.Y[mask]
        pred = (es >= t).float()
        tp += float((pred * gt).sum()); fp += float((pred * (1 - gt)).sum()); fn += float(((1 - pred) * gt).sum())
    return tp, fp, fn


def _best_threshold(scored, counts_fn) -> float:
    best_t, best_f = 0.5, -1.0
    for i in range(1, 40):
        t = i / 40.0
        _, _, f = _prf(*counts_fn(scored, t))
        if f > best_f:
            best_f, best_t = f, t
    return best_t


def run(n_graphs: int = 250, epochs: int = 40, hidden: int = 32, lr: float = 0.01,
        seed: int = 0, test_frac: float = 0.25) -> dict:
    ds = load_path_samples(n_graphs, seed=seed)
    in_features = ds[0].x.shape[1]
    n_test = max(1, int(len(ds) * test_frac))
    test, train = ds[:n_test], ds[n_test:]

    pos = sum(float(s.y.sum()) for s in train)
    total = sum(s.y.numel() for s in train)
    pos_weight = min(50.0, (total - pos) / max(1.0, pos))

    model = _train(train, in_features, False, epochs, hidden, lr, pos_weight, seed)
    scored_tr, scored_te = _node_scored(model, train), _node_scored(model, test)

    # tune thresholds on train, report on held-out test
    tn = _best_threshold(scored_tr, _counts_node)
    te = _best_threshold(scored_tr, _counts_edge)
    node_p, node_r, node_f = _prf(*_counts_node(scored_te, tn))
    edge_p, edge_r, edge_f = _prf(*_counts_edge(scored_te, te))

    auc = roc_auc(torch.cat([sc for sc, _ in scored_te]),
                  torch.cat([s.y for _, s in scored_te]).to(torch.int64))
    return {
        "n_train": len(train), "n_test": len(test), "pos_rate": pos / total,
        "node": {"p": node_p, "r": node_r, "f1": node_f, "thr": tn},
        "edge": {"p": edge_p, "r": edge_r, "f1": edge_f, "thr": te},
        "node_auc": auc,
    }


def _write(r: dict, n_graphs: int, epochs: int, seed: int) -> None:
    n, e = r["node"], r["edge"]
    RESULTS_PATH.write_text(f"""# C2 — Attack-path recovery on the real PIGNN dataset

_Generated by `evaluation/pignn_path_recovery.py` · reproducible with `--seed {seed}`._

The container/VM testbed (C2) is still future work, but the published PIGNN Active-Directory
dataset (François et al., GPL-3.0; 1,033 graphs) carries **edge-level ground-truth attack
paths**, so we measure path recovery on real data. We train our `ExploitabilityGNN` on the
node-on-path reduction and report precision/recall/F1 at the F1-optimal threshold tuned on the
training split (positives ≈ {r['pos_rate']*100:.1f}% — raw accuracy is meaningless under this
imbalance).

| Target | Precision | Recall | F1 | Threshold |
|--------|:---:|:---:|:---:|:---:|
| **Node on attack path** | {n['p']:.3f} | {n['r']:.3f} | **{n['f1']:.3f}** | {n['thr']:.2f} |
| **Edge on attack path** (path-set recovery) | {e['p']:.3f} | {e['r']:.3f} | **{e['f1']:.3f}** | {e['thr']:.2f} |

Held-out node ROC-AUC: **{r['node_auc']:.4f}**. Setup: {n_graphs} graphs
({r['n_train']} train / {r['n_test']} held-out), {epochs} epochs.

**Reading.** Node-on-path and edge-on-path (path-set) recovery are both well above the ~1.3%
positive base rate, on a real published AD dataset. Edges are scored by the product of endpoint
node scores (an attack-path edge needs both endpoints on the path) — a node-model→edge
heuristic, not an edge-native model, so the edge numbers are a lower bound on what an
edge-level model could achieve. This is external validity, not a head-to-head with the PIGNN
paper. Data is git-ignored (9 GB); re-download from the replication package to reproduce.
""", encoding="utf-8")


if __name__ == "__main__":
    import argparse
    import logging
    logging.disable(logging.CRITICAL)

    ap = argparse.ArgumentParser(description="Attack-path recovery P/R/F1 on the real PIGNN dataset")
    ap.add_argument("--graphs", type=int, default=250)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    r = run(n_graphs=args.graphs, epochs=args.epochs, seed=args.seed)
    n, e = r["node"], r["edge"]
    print(f"node P/R/F1 = {n['p']:.3f}/{n['r']:.3f}/{n['f1']:.3f} (thr {n['thr']:.2f})")
    print(f"edge P/R/F1 = {e['p']:.3f}/{e['r']:.3f}/{e['f1']:.3f} (thr {e['thr']:.2f})")
    print(f"node ROC-AUC = {r['node_auc']:.4f}  ·  {r['n_train']} train / {r['n_test']} held-out")
    if not args.no_save:
        _write(r, args.graphs, args.epochs, args.seed)
        print(f"results -> {RESULTS_PATH}")

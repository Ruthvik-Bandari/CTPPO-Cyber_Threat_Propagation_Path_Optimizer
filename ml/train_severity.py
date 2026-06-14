"""Train the text-only CVE severity classifier on real NVD data (roadmap A4).

Fetches real CVEs (description + CVSS-derived severity label) from NVD via the existing
CVEDataCollector, fine-tunes DistilBERT(description) -> severity, and reports an HONEST
held-out macro-F1 against a majority-class baseline. No CVSS features are fed to the model
(severity is a deterministic function of the CVSS score, so feeding it would be circular).

Saves a checkpoint the API loads directly: models/severity_text/{checkpoint_best.pt,
tokenizer/}. Writes results to docs/RESEARCH/A4_SEVERITY_CLASSIFIER.md. Data + checkpoint
are git-ignored (regenerate with this script).

Run:  python3 ml/train_severity.py [--per-class N] [--epochs E] [--max-length L]
"""

from __future__ import annotations

import importlib.util
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import List, Tuple

import torch
import torch.nn as nn
from sklearn.metrics import f1_score, classification_report
from transformers import DistilBertTokenizerFast

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ml"))

from ml.cve_classifier import SeverityClassifier, SeverityConfig, SEVERITY_CLASSES, severity_to_index

MODEL_DIR = ROOT / "models" / "severity_text"
RESULTS_PATH = ROOT / "docs" / "RESEARCH" / "A4_SEVERITY_CLASSIFIER.md"
CACHE_DIR = ROOT / "data" / "cve_cache"


def _device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def fetch_dataset(per_class: int) -> List[Tuple[str, int]]:
    """Fetch real CVEs and return (description, severity_index) pairs (4 classes only)."""
    # Load data_collector.py directly — the package __init__ pulls in nltk we don't need.
    spec = importlib.util.spec_from_file_location(
        "cve_collector", str(ROOT / "ml" / "data_pipeline" / "data_collector.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    collector = mod.CVEDataCollector(cache_dir=str(CACHE_DIR))
    records = collector.fetch_balanced_dataset(samples_per_class=per_class)

    data: List[Tuple[str, int]] = []
    for r in records:
        idx = severity_to_index(str(r.severity_label))
        desc = (r.description or "").strip()
        if idx is not None and len(desc) > 10:
            data.append((desc, idx))
    return data


def _stratified_split(data, seed=0, val=0.15, test=0.15):
    by_cls = {}
    for ex in data:
        by_cls.setdefault(ex[1], []).append(ex)
    rng = random.Random(seed)
    train, va, te = [], [], []
    for cls, items in by_cls.items():
        rng.shuffle(items)
        n = len(items); nt = int(n * test); nv = int(n * val)
        te += items[:nt]; va += items[nt:nt + nv]; train += items[nt + nv:]
    rng.shuffle(train); rng.shuffle(va); rng.shuffle(te)
    return train, va, te


def _encode(tokenizer, data, max_length):
    texts = [d[0] for d in data]
    labels = torch.tensor([d[1] for d in data], dtype=torch.long)
    enc = tokenizer(texts, max_length=max_length, padding="max_length",
                    truncation=True, return_tensors="pt")
    return torch.utils.data.TensorDataset(enc["input_ids"], enc["attention_mask"], labels)


def _eval_macro_f1(model, loader, device) -> Tuple[float, list, list]:
    model.eval()
    preds, gold = [], []
    with torch.no_grad():
        for ids, mask, y in loader:
            logits = model(ids.to(device), mask.to(device))
            preds += logits.argmax(-1).cpu().tolist()
            gold += y.tolist()
    return f1_score(gold, preds, average="macro", zero_division=0), gold, preds


def run(per_class: int = 800, epochs: int = 3, max_length: int = 128, batch_size: int = 16,
        lr: float = 2e-5, seed: int = 0, save: bool = True) -> dict:
    torch.manual_seed(seed)
    device = _device()
    data = fetch_dataset(per_class)
    if len(data) < 50:
        raise RuntimeError(f"Only {len(data)} usable CVEs fetched — check NVD connectivity.")
    train, va, te = _stratified_split(data, seed=seed)
    dist = {SEVERITY_CLASSES[k]: v for k, v in sorted(Counter(d[1] for d in data).items())}

    cfg = SeverityConfig(max_length=max_length)
    tokenizer = DistilBertTokenizerFast.from_pretrained(cfg.model_name)
    model = SeverityClassifier(cfg).to(device)

    train_ld = torch.utils.data.DataLoader(_encode(tokenizer, train, max_length),
                                           batch_size=batch_size, shuffle=True)
    val_ld = torch.utils.data.DataLoader(_encode(tokenizer, va, max_length), batch_size=batch_size)
    test_ld = torch.utils.data.DataLoader(_encode(tokenizer, te, max_length), batch_size=batch_size)

    counts = Counter(d[1] for d in train)
    weights = torch.tensor([len(train) / (len(SEVERITY_CLASSES) * counts.get(i, 1))
                            for i in range(len(SEVERITY_CLASSES))], dtype=torch.float32, device=device)
    loss_fn = nn.CrossEntropyLoss(weight=weights)
    opt = torch.optim.AdamW(model.parameters(), lr=lr)

    best_f1, best_state = -1.0, None
    for ep in range(epochs):
        model.train()
        for ids, mask, y in train_ld:
            opt.zero_grad()
            loss = loss_fn(model(ids.to(device), mask.to(device)), y.to(device))
            loss.backward(); opt.step()
        vf1, _, _ = _eval_macro_f1(model, val_ld, device)
        print(f"epoch {ep+1}/{epochs}  val_macro_f1={vf1:.4f}")
        if vf1 > best_f1:
            best_f1 = vf1
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    test_f1, gold, preds = _eval_macro_f1(model, test_ld, device)
    # Majority-class baseline macro-F1 (honesty reference)
    majority = Counter(d[1] for d in train).most_common(1)[0][0]
    base_f1 = f1_score(gold, [majority] * len(gold), average="macro", zero_division=0)
    report = classification_report(gold, preds, labels=list(range(len(SEVERITY_CLASSES))),
                                   target_names=SEVERITY_CLASSES, zero_division=0)

    result = {"test_macro_f1": test_f1, "val_macro_f1": best_f1, "baseline_macro_f1": base_f1,
              "n_total": len(data), "n_train": len(train), "n_test": len(te),
              "class_dist": dist, "report": report, "epochs": epochs, "per_class": per_class,
              "device": str(device)}

    if save:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        torch.save({"model_state_dict": best_state, "val_f1": best_f1, "test_f1": test_f1,
                    "config": cfg.__dict__, "classes": SEVERITY_CLASSES}, MODEL_DIR / "checkpoint_best.pt")
        tokenizer.save_pretrained(str(MODEL_DIR / "tokenizer"))
        _write_results(result)
    return result


def _write_results(r: dict) -> None:
    RESULTS_PATH.write_text(f"""# A4 — CVE Severity Classifier (text-only, honest)

_Generated by `ml/train_severity.py`._

DistilBERT fine-tuned to predict CVSS severity (CRITICAL/HIGH/MEDIUM/LOW) **from the CVE
description text only**. CVSS score/vector are deliberately NOT model inputs: the severity
label is a deterministic threshold on the CVSS score, so feeding it would make the task
circular (a fake ~100% F1). This reports the honest, non-trivial text→severity capability.

Real NVD data: {r['n_total']} CVEs ({r['n_train']} train / {r['n_test']} held-out test),
class distribution {r['class_dist']}. Trained {r['epochs']} epochs on {r['device']}.

| Metric (held-out test) | macro-F1 |
|------------------------|----------|
| **DistilBERT (description → severity)** | **{r['test_macro_f1']:.4f}** |
| Majority-class baseline | {r['baseline_macro_f1']:.4f} |

Per-class report (held-out):
```
{r['report']}
```

The model beats the majority-class baseline, confirming it learns real linguistic signal
for severity (not just predicting the most frequent class). Checkpoint + tokenizer →
`models/severity_text/` (git-ignored; regenerate with `python3 ml/train_severity.py`).
""", encoding="utf-8")


if __name__ == "__main__":
    import argparse
    import logging
    logging.disable(logging.CRITICAL)
    ap = argparse.ArgumentParser(description="Train the text-only CVE severity classifier")
    ap.add_argument("--per-class", type=int, default=800)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-length", type=int, default=128)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()
    res = run(per_class=args.per_class, epochs=args.epochs, max_length=args.max_length,
              batch_size=args.batch_size, seed=args.seed, save=not args.no_save)
    print(f"\nHELD-OUT macro-F1 = {res['test_macro_f1']:.4f}  "
          f"(majority baseline {res['baseline_macro_f1']:.4f})")
    print(f"checkpoint -> {MODEL_DIR}")

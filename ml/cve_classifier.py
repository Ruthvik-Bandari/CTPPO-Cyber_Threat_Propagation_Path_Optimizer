"""Text-only CVE severity classifier (DistilBERT) — shared by the trainer and the API.

Predicts CVSS severity (CRITICAL/HIGH/MEDIUM/LOW) from a vulnerability *description*.

Why text-only: the severity label is a deterministic threshold on the CVSS base score,
which is itself computed from the CVSS vector. Feeding CVSS score/vector as model inputs
would make the task circular (the model just inverts the threshold → a meaningless ~100%
F1). The honest, useful task is description → severity, which is what this model does and
what its reported F1 reflects. (Roadmap A4; supersedes the multi-modal CVSS-fed classifier.)

This is the single source of truth for the architecture so the trained checkpoint loads
into `api/server_secure.py` unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
from transformers import DistilBertModel, DistilBertTokenizerFast

# Index order IS the label encoding: CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3.
SEVERITY_CLASSES: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_CLASSES)}


def severity_to_index(label: str) -> Optional[int]:
    """Map a severity name (any case) to its class index, or None if not one of the four."""
    return _SEVERITY_INDEX.get(str(label).upper().split(".")[-1])  # handles 'Severity.HIGH'


@dataclass
class SeverityConfig:
    model_name: str = "distilbert-base-uncased"
    num_classes: int = len(SEVERITY_CLASSES)
    dropout: float = 0.3
    max_length: int = 256


class SeverityClassifier(nn.Module):
    """DistilBERT -> [CLS] -> dropout -> 256 -> ReLU -> dropout -> num_classes."""

    def __init__(self, config: Optional[SeverityConfig] = None):
        super().__init__()
        self.config = config or SeverityConfig()
        self.bert = DistilBertModel.from_pretrained(self.config.model_name)
        hidden = self.bert.config.hidden_size  # 768
        self.classifier = nn.Sequential(
            nn.Dropout(self.config.dropout),
            nn.Linear(hidden, 256),
            nn.ReLU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(256, self.config.num_classes),
        )

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        cls = self.bert(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state[:, 0, :]
        return self.classifier(cls)


def load_classifier(model_dir: str | Path,
                    device: Optional[torch.device] = None
                    ) -> Optional[Tuple[SeverityClassifier, DistilBertTokenizerFast, float]]:
    """Load (model, tokenizer, val_f1) from ``model_dir``; None if no checkpoint there.

    Expects ``checkpoint_best.pt`` ({'model_state_dict', 'val_f1'}) and a ``tokenizer/`` dir.
    """
    model_dir = Path(model_dir)
    ckpt_path = model_dir / "checkpoint_best.pt"
    if not ckpt_path.exists():
        return None
    device = device or torch.device("cpu")
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    cfg = SeverityConfig(**ckpt["config"]) if "config" in ckpt else SeverityConfig()
    model = SeverityClassifier(cfg)
    model.load_state_dict(ckpt["model_state_dict"])
    model.to(device).eval()
    tok_path = model_dir / "tokenizer"
    tokenizer = DistilBertTokenizerFast.from_pretrained(
        str(tok_path) if tok_path.exists() else cfg.model_name)
    return model, tokenizer, float(ckpt.get("val_f1", 0.0))


@torch.no_grad()
def predict_severity(model: SeverityClassifier, tokenizer, description: str,
                     device: Optional[torch.device] = None) -> Tuple[str, float, Dict[str, float]]:
    """Return (predicted_severity, confidence, {class: prob}) for one description."""
    device = device or torch.device("cpu")
    enc = tokenizer(description, max_length=model.config.max_length, padding="max_length",
                    truncation=True, return_tensors="pt")
    logits = model(enc["input_ids"].to(device), enc["attention_mask"].to(device))
    probs = torch.softmax(logits, dim=-1)[0]
    pred = int(probs.argmax())
    return (SEVERITY_CLASSES[pred], round(float(probs[pred]), 4),
            {SEVERITY_CLASSES[i]: round(float(probs[i]), 4) for i in range(len(SEVERITY_CLASSES))})

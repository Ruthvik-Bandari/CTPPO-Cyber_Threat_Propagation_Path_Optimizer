"""Tests for the text-only CVE severity classifier (roadmap A4).

The label-mapping tests are pure/fast. The predict test is guarded: it runs only when a
trained checkpoint exists at models/severity_text (git-ignored, ~266 MB) — so the suite
passes on a fresh clone without the artifact. Regenerate it with ml/train_severity.py.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logging.disable(logging.CRITICAL)

import torch  # noqa: E402

from ml.cve_classifier import (  # noqa: E402
    SEVERITY_CLASSES, severity_to_index, load_classifier, predict_severity,
)

_MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "severity_text"


def test_severity_classes_order():
    # Index order IS the label encoding the trainer + API rely on.
    assert SEVERITY_CLASSES == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_severity_to_index_mapping():
    assert severity_to_index("CRITICAL") == 0
    assert severity_to_index("low") == 3                 # case-insensitive
    assert severity_to_index("Severity.HIGH") == 1       # handles the enum repr from NVD
    assert severity_to_index("UNKNOWN") is None          # not one of the four -> dropped
    assert severity_to_index("NONE") is None


def test_predict_with_trained_checkpoint():
    if not (_MODEL_DIR / "checkpoint_best.pt").exists():
        print("  (skip: no trained checkpoint — run ml/train_severity.py)")
        return
    loaded = load_classifier(_MODEL_DIR, device=torch.device("cpu"))
    assert loaded is not None
    model, tokenizer, val_f1 = loaded
    assert 0.0 <= val_f1 <= 1.0
    sev, conf, probs = predict_severity(
        model, tokenizer,
        "Remote attackers can execute arbitrary code without authentication via a crafted request.",
        torch.device("cpu"))
    assert sev in SEVERITY_CLASSES
    assert 0.0 <= conf <= 1.0
    assert abs(sum(probs.values()) - 1.0) < 1e-3        # valid probability distribution
    assert set(probs) == set(SEVERITY_CLASSES)


if __name__ == "__main__":
    test_severity_classes_order()
    test_severity_to_index_mapping()
    test_predict_with_trained_checkpoint()
    print("3 tests passed.")

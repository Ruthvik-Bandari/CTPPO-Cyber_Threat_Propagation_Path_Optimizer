> ⚠️ **Historical / superseded.** This document predates the open-source, local-first conversion and may reference retired features (RL, subscriptions, enterprise, the "276K CVEs / 97.6%" prototype). Authoritative sources: `README.md`, `OVERVIEW.md`, `docs/RESEARCH/METRICS.md`.

# 🛡️ CTPPO Project Summary
## Cyber Threat Prioritization and Path Optimization

**Author:** Ruthvik Bandari (bandari.ru@northeastern.edu)  
**Institution:** Northeastern University - MS Applied AI  
**Last Updated:** January 27, 2026  
**Status:** Phase 3 - Data Quality Improvement

---

## 📋 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Development Timeline](#2-development-timeline)
3. [Phase 1: Initial Model (v1)](#3-phase-1-initial-model-v1)
4. [Phase 2: Multi-Modal Model (v2)](#4-phase-2-multi-modal-model-v2)
5. [Phase 3: Data Quality Improvement (v3)](#5-phase-3-data-quality-improvement-v3---current)
6. [Current Status](#6-current-status)
7. [Next Steps](#7-next-steps)
8. [File Structure](#8-file-structure)
9. [Key Learnings](#9-key-learnings)
10. [Technical Specifications](#10-technical-specifications)

---

## 1. Project Overview

### 1.1 What is CTPPO?

CTPPO is an ML-powered cybersecurity tool that:
1. **Classifies CVE severity** (CRITICAL/HIGH/MEDIUM/LOW) using multi-modal deep learning
2. **Finds optimal attack paths** using NAMOA* multi-objective optimization
3. **Provides explainable predictions** with attention visualization and PDF reports

### 1.2 Problem Statement

Security teams face 20,000+ new CVEs annually. Manual prioritization is:
- Time-consuming
- Inconsistent
- Error-prone

CTPPO automates severity classification to help teams focus on critical threats.

### 1.3 Unique Value Proposition

| Feature | Most Tools | CTPPO |
|---------|------------|-------|
| Input | Text only | Multi-modal (text + CVSS + CWE + metadata) |
| Explainability | Black box | Attention + domain knowledge |
| Attack paths | Single path | ALL Pareto-optimal paths (NAMOA*) |
| Labels | NVD labels (inconsistent) | CVSS-score derived (consistent) |

---

## 2. Development Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  JANUARY 25-27, 2026                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Day 1 (Jan 25): Initial Setup                                             │
│  ├── Diagnosed existing CTPPO codebase issues                              │
│  ├── Fetched NVD data (329K CVEs)                                          │
│  ├── Initial EDA and preprocessing                                         │
│  └── Found 30K+ duplicates in data                                         │
│                                                                             │
│  Day 2 (Jan 26): Text-Only Model                                           │
│  ├── Trained DistilBERT text classifier                                    │
│  ├── Achieved 73.4% Val F1 (on dirty data)                                │
│  ├── Discovered duplicates inflating score                                 │
│  └── Started multi-modal model design                                      │
│                                                                             │
│  Day 3 (Jan 27): Multi-Modal + Data Quality                                │
│  ├── Trained multi-modal model (70.8% Val F1)                             │
│  ├── Test evaluation (70.55% Test F1)                                      │
│  ├── Identified need for CVSS components                                   │
│  ├── Fetched NEW data with ALL CVSS fields (189K CVEs)                    │
│  ├── Completed comprehensive EDA                                           │
│  └── Ready for clean data training → Target 78-82%                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Phase 1: Initial Model (v1)

### 3.1 Approach
- Text-only DistilBERT classifier
- NVD severity labels (as-is)
- 306K CVEs (with duplicates)

### 3.2 Results
- **Val F1:** 73.77%
- **Test F1:** 73.44%

### 3.3 Issues Discovered
- 30,531 duplicate CVEs (inflated scores)
- Inconsistent NVD labels
- Missing CVSS component features

### 3.4 Lesson Learned
> **High accuracy on dirty data is meaningless. Data quality matters more than model complexity.**

---

## 4. Phase 2: Multi-Modal Model (v2)

### 4.1 Improvements
- Removed duplicates (276K clean CVEs)
- Added multi-modal features:
  - Text (DistilBERT)
  - CWE embeddings (225 CWEs)
  - CWE category mapping
  - Reference count
  - Exploit indicators
  - Publication metadata
- Focal Loss for class imbalance
- Cosine LR schedule with warmup

### 4.2 Training Details
- **Device:** MPS (Apple Silicon)
- **Epochs:** 10
- **Training Time:** ~18.5 hours
- **Parameters:** 66.9M

### 4.3 Results
| Metric | Validation | Test |
|--------|------------|------|
| Accuracy | 70.65% | 70.10% |
| F1 (Weighted) | 71.12% | 70.55% |
| F1 (Macro) | - | 65.14% |

### 4.4 Per-Class Performance
| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|-----|---------|
| CRITICAL | 56.8% | 72.1% | 63.5% | 3,537 |
| HIGH | 67.7% | 69.5% | 68.6% | 10,313 |
| MEDIUM | 81.9% | 70.8% | 76.0% | 12,506 |
| LOW | 45.4% | 62.2% | 52.5% | 1,246 |

### 4.5 Key Insight
> **Test ≈ Validation (70.55% vs 71.12%) means NO OVERFITTING. Model generalizes well.**

### 4.6 Limitation Identified
- Using only `cvss_score` (single number)
- Not using 8 CVSS v3 components (attackVector, complexity, etc.)
- These components are DIRECT INDICATORS of severity!

---

## 5. Phase 3: Data Quality Improvement (v3) - CURRENT

### 5.1 Motivation
```
Old data: cvss_score = 6.1 (just a number)

New data: cvss_v3 = {
    "attackVector": "NETWORK",           ← Direct feature!
    "attackComplexity": "LOW",           ← Direct feature!
    "privilegesRequired": "NONE",        ← Direct feature!
    "userInteraction": "REQUIRED",       ← Direct feature!
    "scope": "CHANGED",                  ← Direct feature!
    "confidentialityImpact": "LOW",      ← Direct feature!
    "integrityImpact": "LOW",            ← Direct feature!
    "availabilityImpact": "NONE",        ← Direct feature!
    "exploitabilityScore": 2.8,
    "impactScore": 2.7
}
```

### 5.2 New Data Fetched
```
Year      CVEs
─────────────────
2020      19,222
2021      21,950
2022      26,431
2023      30,949
2024      40,704
2025      49,972
─────────────────
TOTAL    189,228
```

### 5.3 EDA Results (New Data)

#### Data Quality
| Metric | Value | Status |
|--------|-------|--------|
| Total CVEs | 189,228 | ✅ |
| Duplicates | 0 | ✅ Perfect |
| Empty descriptions | 0 | ✅ Perfect |
| CVSS v3 coverage | 93.3% | ✅ Excellent |
| CWE coverage | 93.4% | ✅ Excellent |
| Has exploit info | 24.7% | ✅ Good signal |

#### Missing Values
| Field | Missing | Action |
|-------|---------|--------|
| cvss_score | 12,653 (6.7%) | REMOVE |
| cvss_v3 components | 12,646 (6.7%) | Same as above |
| cwe_ids | 12,411 (6.6%) | Use "UNKNOWN" |
| references | 8,728 (4.6%) | Set count=0 |

#### Severity Distribution
```
CRITICAL:  ███████████ 11.4% (20,098)
HIGH:      ████████████████████████████████████ 36.9% (65,220)
MEDIUM:    ███████████████████████████████████████████████ 47.6% (84,125)
LOW:       ████ 4.0% (7,132)
```

#### CVSS Component Coverage
All 8 components available for 93.3% of records:
- attackVector: 71% NETWORK, 24% LOCAL
- attackComplexity: 91% LOW
- privilegesRequired: 52% NONE
- userInteraction: 68% NONE
- scope: 78% UNCHANGED
- confidentialityImpact: 48% HIGH
- integrityImpact: 40% HIGH
- availabilityImpact: 48% HIGH

### 5.4 Cleaning Strategy
```
Input: 189,228 CVEs

REMOVE (12,653):
└── CVEs without CVSS score (can't determine label)

KEEP & HANDLE:
├── No CWE (12,411): Use "CWE-UNKNOWN"
├── No references (8,728): Set count=0
└── Short descriptions (6,931): Keep (text model handles)

Output: ~176,575 clean CVEs with full CVSS features
```

---

## 6. Current Status

### 6.1 Completed ✅
```
[✅] Phase 1: Initial model (73.4% - dirty data)
[✅] Phase 2: Multi-modal model (70.55% - clean data, honest eval)
[✅] Fetched new data with CVSS components (189K CVEs)
[✅] Comprehensive EDA
[✅] Verified data structure compatibility
[✅] No duplicates, no empty descriptions
```

### 6.2 In Progress 🔄
```
[🔄] Clean and label new data (03_clean_and_label.py)
```

### 6.3 Pending ⏳
```
[⏳] Create stratified train/val/test splits
[⏳] Train v3 model with CVSS features
[⏳] Evaluate on test set
[⏳] Generate explainability reports
[⏳] Test NAMOA* attack path analyzer
```

---

## 7. Next Steps

### 7.1 Immediate (Today)
```bash
# Step 1: Clean and label data
python ml/03_clean_and_label.py --input data/nvd_complete/nvd_complete.jsonl --output data/clean_v3

# Step 2: Verify splits
ls -la data/clean_v3/splits/
head -1 data/clean_v3/splits/train.jsonl | python -m json.tool
```

### 7.2 Short-term (This Week)
```bash
# Step 3: Train v3 model with CVSS features
python ml/04_train_v3.py --data-dir data/clean_v3/splits --epochs 10

# Step 4: Evaluate on test set
python ml/05_evaluate_v3.py --model-dir models/severity_v3

# Step 5: Test explainability
python ml/explainable_inference.py --model-dir models/severity_v3

# Step 6: Test attack path analyzer
python ml/attack_path_analyzer.py --demo
```

### 7.3 Medium-term (Next Week)
- Train on Google Cloud (faster with GPU credits)
- Hyperparameter tuning
- Build REST API (FastAPI)
- Create web dashboard

### 7.4 Long-term
- Integration with real vulnerability scanners
- Continuous model updates with new CVEs
- Production deployment

---

## 8. File Structure

```
ctppo/
├── data/
│   ├── nvd_complete/              # NEW: Raw fetched data with CVSS
│   │   ├── nvd_2020.jsonl
│   │   ├── nvd_2021.jsonl
│   │   ├── nvd_2022.jsonl
│   │   ├── nvd_2023.jsonl
│   │   ├── nvd_2024.jsonl
│   │   ├── nvd_2025.jsonl
│   │   ├── nvd_complete.jsonl     # Combined (189K CVEs)
│   │   └── eda_stats.json
│   ├── clean_v3/                  # NEXT: Cleaned data
│   │   ├── splits/
│   │   │   ├── train.jsonl
│   │   │   ├── val.jsonl
│   │   │   └── test.jsonl
│   │   ├── clean_data.jsonl
│   │   ├── cleaning_stats.json
│   │   └── feature_encodings.json
│   └── fixed_splits/              # OLD: v2 data
│
├── ml/
│   ├── 01_fetch_nvd_final.py      # Data fetcher (with quarterly chunks)
│   ├── 02_eda_complete.py         # EDA script
│   ├── 03_clean_and_label.py      # Cleaning script
│   ├── 04_train_multimodal_v2.py  # v2 training script
│   ├── 06_evaluate_multimodal.py  # v2 evaluation
│   ├── attack_path_analyzer.py    # NAMOA* implementation
│   └── explainable_inference.py   # Explainability
│
├── models/
│   └── severity_multimodal_v2/    # Trained v2 model
│       ├── checkpoint_best.pt
│       ├── tokenizer/
│       ├── cwe_vocab.json
│       └── test_results.json
│
├── docs/
│   ├── ML_DEVELOPMENT_GUIDELINES.md   # General ML best practices
│   └── PROJECT_SUMMARY.md             # This file
│
└── reports/                       # Generated reports
```

---

## 9. Key Learnings

### 9.1 Data Quality
```
❌ Wrong: Train first, clean later
✅ Right: Clean first, understand data, then train

❌ Wrong: More data = better model
✅ Right: Quality data > quantity data

❌ Wrong: Trust provided labels
✅ Right: Verify labels, use computed labels when possible
```

### 9.2 Model Development
```
❌ Wrong: Jump to complex models
✅ Right: Start simple, add complexity if needed

❌ Wrong: Only look at accuracy
✅ Right: Check per-class metrics, confusion matrix

❌ Wrong: Trust validation score alone
✅ Right: Always evaluate on held-out test set
```

### 9.3 Debugging
```
❌ Wrong: Assume data is correct
✅ Right: Verify at every step (EDA, duplicates, missing values)

❌ Wrong: Train for many epochs hoping it improves
✅ Right: Monitor train vs val loss, early stop if overfitting
```

---

## 10. Technical Specifications

### 10.1 Hardware Used
- MacBook Pro (Apple Silicon M-series)
- Device: MPS (Metal Performance Shaders)
- Training time: ~2 hours/epoch

### 10.2 Software Stack
```
Python 3.10+
PyTorch 2.0+
Transformers 4.35+
scikit-learn 1.3+
```

### 10.3 Model Architecture (v2)
```
Input:
├── Text → DistilBERT → 768-dim → Linear → 512-dim
├── CWE ID → Embedding(225, 64) → 64-dim
├── CWE Category → Embedding(10, 32) → 32-dim
└── Numeric (8 features) → Linear → 32-dim

Fusion:
├── Metadata concat → 128-dim → LayerNorm → ReLU
└── Text + Metadata concat → 640-dim

Classification:
└── 640 → 256 → 128 → 4 (CRITICAL/HIGH/MEDIUM/LOW)

Total Parameters: 66.9M
```

### 10.4 Expected v3 Architecture
```
Input:
├── Text → DistilBERT → 768-dim → Linear → 512-dim
├── CWE ID → Embedding → 64-dim
├── CWE Category → Embedding → 32-dim
├── CVSS Components (8 categorical) → Embeddings → 64-dim  ← NEW!
├── exploitabilityScore → Numeric → 16-dim                 ← NEW!
├── impactScore → Numeric → 16-dim                         ← NEW!
└── has_exploit, has_patch → Boolean → 8-dim               ← NEW!

Expected improvement: 70.55% → 78-82%
```

---

## 📞 Contact

**Ruthvik Bandari**  
Email: bandari.ru@northeastern.edu  
GitHub: [Your GitHub]  
LinkedIn: [Your LinkedIn]

---

## 📝 Quick Resume Points

```
CTPPO: Cyber Threat Prioritization and Path Optimization
────────────────────────────────────────────────────────
• Built multi-modal deep learning model for CVE severity classification
• Achieved 70.55% F1 on clean dataset (no data leakage)
• Processed 189K+ CVEs with 8 CVSS feature components
• Implemented NAMOA* multi-objective optimization for attack path analysis
• Target accuracy: 78-82% with full CVSS features

Technologies: Python, PyTorch, Transformers, DistilBERT, scikit-learn
```

---

*Last updated: January 27, 2026 - Ready for Phase 3 training*

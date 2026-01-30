# 🛡️ CTPPO Project Development Summary
## Cyber Threat Prioritization and Path Optimization

**Author:** Ruthvik Bandari (bandari.ru@northeastern.edu)  
**Institution:** Northeastern University - MS Applied AI  
**Last Updated:** January 27, 2026  
**Status:** Phase 3 - Ready for Data Cleaning & Training v3 Model

---

## 📋 Quick Context (For New Chat Sessions)

**CTPPO** is a cybersecurity ML project that:
1. **Classifies CVE severity** (CRITICAL/HIGH/MEDIUM/LOW) using multi-modal deep learning
2. **Finds optimal attack paths** using NAMOA* multi-objective optimization
3. **Provides explainable predictions** with attention visualization

**Current Goal:** Achieve 78-82% F1 by adding CVSS component features to the model.

---

## 🎯 Project Objective

**Problem:** 20,000+ new CVEs annually → Security teams can't manually prioritize all

**Solution:** ML model that automatically classifies CVE severity based on:
- Vulnerability description (text)
- CVSS v3 components (8 categorical features)
- CWE weakness type
- Exploit/patch indicators
- Reference metadata

---

## 📈 Development Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  DEVELOPMENT PHASES                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: Initial Model (COMPLETED)                                         │
│  ├── Text-only DistilBERT classifier                                        │
│  ├── 306K CVEs (with 30K duplicates!)                                       │
│  ├── Result: 73.4% F1 (INFLATED due to duplicates)                         │
│  └── Lesson: Data quality > model complexity                                │
│                                                                             │
│  PHASE 2: Multi-Modal Model (COMPLETED)                                     │
│  ├── Removed duplicates → 276K clean CVEs                                   │
│  ├── Added: CWE embeddings, reference counts, exploit indicators           │
│  ├── Result: 70.55% F1 (HONEST evaluation)                                 │
│  └── Lesson: Clean data gives real (lower but honest) results              │
│                                                                             │
│  PHASE 3: CVSS Feature Enhancement (CURRENT)                                │
│  ├── Fetched NEW data with ALL CVSS components (189K CVEs)                 │
│  ├── Completed comprehensive EDA                                            │
│  ├── Verified data quality (0 duplicates, 0 empty descriptions)            │
│  └── Ready for: Cleaning → Training v3 → Target 78-82% F1                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✅ What's Been Completed

### Phase 1: Initial Development
- [x] Diagnosed existing CTPPO codebase issues
- [x] Fetched NVD data via API
- [x] Built text-only DistilBERT classifier
- [x] Discovered 30K+ duplicates inflating scores

### Phase 2: Multi-Modal Model
- [x] Removed duplicates (276K clean CVEs)
- [x] Built multi-modal architecture (text + metadata)
- [x] Trained for 10 epochs (~18.5 hours on MPS)
- [x] Achieved 70.55% Test F1 (honest evaluation)
- [x] Integrated NAMOA* attack path analyzer
- [x] Built explainability pipeline (attention viz, PDF reports)

### Phase 3: Data Quality Improvement (Current)
- [x] Identified missing CVSS component features
- [x] Fetched NEW data with ALL CVSS fields (189,228 CVEs from 2020-2025)
- [x] Comprehensive EDA completed
- [x] Verified data structure compatibility
- [x] Confirmed: 0 duplicates, 0 empty descriptions
- [x] Identified cleaning strategy

---

## 📊 Current Data Status

### New Data Fetched (data/nvd_complete/)
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

### Data Quality (from EDA)
| Metric | Value | Status |
|--------|-------|--------|
| Total CVEs | 189,228 | ✅ |
| Duplicates | 0 | ✅ Perfect |
| Empty descriptions | 0 | ✅ Perfect |
| CVSS v3 coverage | 93.3% (176,582) | ✅ Excellent |
| CWE coverage | 93.4% (176,817) | ✅ Excellent |
| Has exploit info | 24.7% (46,773) | ✅ Good signal |
| Has patch info | 22.2% (42,064) | ✅ Good signal |

### Missing Values Analysis
| Field | Missing | Action |
|-------|---------|--------|
| cvss_score | 12,653 (6.7%) | **REMOVE** - can't determine label |
| cvss_v3 components | 12,646 (6.7%) | Same records |
| cwe_ids | 12,411 (6.6%) | **KEEP** - use "CWE-UNKNOWN" |
| references | 8,728 (4.6%) | **KEEP** - set count=0 |
| Very short desc | 6,931 (3.7%) | **KEEP** - model can handle |

### After Cleaning (Expected)
```
Input:  189,228 CVEs
Remove: 12,653 (no CVSS)
Output: ~176,575 clean CVEs with full CVSS features
```

### Severity Distribution
```
CRITICAL:  ███████████ 11.4% (20,098)
HIGH:      ████████████████████████████████████ 36.9% (65,220)
MEDIUM:    ███████████████████████████████████████████████ 47.6% (84,125)
LOW:       ████ 4.0% (7,132)
```

---

## 🆕 New Features in v3 Data

### Old Data (v2) - Missing Components!
```json
{
    "cvss_score": 6.1,
    "cvss_version": "3.1"
    // Just a number! No components!
}
```

### New Data (v3) - Full CVSS Components!
```json
{
    "cvss_v3": {
        "version": "3.1",
        "baseScore": 6.1,
        "baseSeverity": "MEDIUM",
        "attackVector": "NETWORK",           // ← NEW!
        "attackComplexity": "LOW",           // ← NEW!
        "privilegesRequired": "NONE",        // ← NEW!
        "userInteraction": "REQUIRED",       // ← NEW!
        "scope": "CHANGED",                  // ← NEW!
        "confidentialityImpact": "LOW",      // ← NEW!
        "integrityImpact": "LOW",            // ← NEW!
        "availabilityImpact": "NONE",        // ← NEW!
        "exploitabilityScore": 2.8,          // ← NEW!
        "impactScore": 2.7                   // ← NEW!
    },
    "has_exploit": true,
    "has_patch": false
}
```

### CVSS Component Distributions (Validated)
```
✅ attackVector: NETWORK (71%), LOCAL (25%), ADJACENT (3%), PHYSICAL (1%)
✅ attackComplexity: LOW (91%), HIGH (9%)
✅ privilegesRequired: NONE (52%), LOW (38%), HIGH (10%)
✅ userInteraction: NONE (68%), REQUIRED (32%)
✅ scope: UNCHANGED (78%), CHANGED (22%)
✅ confidentialityImpact: HIGH (48%), LOW (28%), NONE (24%)
✅ integrityImpact: HIGH (40%), LOW (30%), NONE (30%)
✅ availabilityImpact: HIGH (48%), NONE (38%), LOW (14%)
```

---

## 🚀 Next Steps (Immediate)

### Step 1: Clean & Label Data
```bash
python ml/03_clean_and_label.py \
    --input data/nvd_complete/nvd_complete.jsonl \
    --output data/clean_v3
```

This will:
1. Remove 12,653 records without CVSS
2. Encode all 8 CVSS components as integers
3. Create consistent severity labels from CVSS scores
4. Handle missing CWE with "UNKNOWN"
5. Create stratified train/val/test splits (80/10/10)
6. Save to `data/clean_v3/splits/`

### Step 2: Verify Cleaned Data
```bash
# Check splits exist
ls -la data/clean_v3/splits/

# Verify data structure
head -1 data/clean_v3/splits/train.jsonl | python -m json.tool

# Check distribution
python -c "
import json
from collections import Counter
train = [json.loads(l) for l in open('data/clean_v3/splits/train.jsonl')]
print(f'Train: {len(train):,}')
print(Counter(r['severity'] for r in train))
"
```

### Step 3: Create & Train v3 Model
```bash
# Create new training script with CVSS features
python ml/04_train_v3.py --data-dir data/clean_v3/splits --epochs 10
```

### Step 4: Evaluate on Test Set
```bash
python ml/05_evaluate_v3.py --model-dir models/severity_v3
```

---

## 📁 Project File Structure

```
ctppo/
├── data/
│   ├── nvd_complete/                 # ← NEW FETCHED DATA
│   │   ├── nvd_2020.jsonl
│   │   ├── nvd_2021.jsonl
│   │   ├── nvd_2022.jsonl
│   │   ├── nvd_2023.jsonl
│   │   ├── nvd_2024.jsonl
│   │   ├── nvd_2025.jsonl
│   │   ├── nvd_complete.jsonl        # Combined (189K CVEs)
│   │   └── eda_stats.json            # EDA results
│   │
│   ├── clean_v3/                     # ← TO BE CREATED
│   │   ├── splits/
│   │   │   ├── train.jsonl
│   │   │   ├── val.jsonl
│   │   │   └── test.jsonl
│   │   ├── cleaning_stats.json
│   │   └── feature_encodings.json
│   │
│   └── fixed_splits/                 # OLD v2 data
│
├── ml/
│   ├── 01_fetch_nvd_final.py         # Data fetcher (quarterly chunks)
│   ├── 02_eda_complete.py            # EDA script
│   ├── 03_clean_and_label.py         # Cleaning script ← RUN NEXT
│   ├── 04_train_multimodal_v2.py     # v2 training (old)
│   ├── 04_train_v3.py                # v3 training (TO CREATE)
│   ├── 06_evaluate_multimodal.py     # Evaluation script
│   ├── attack_path_analyzer.py       # NAMOA* implementation
│   └── explainable_inference.py      # Explainability
│
├── models/
│   └── severity_multimodal_v2/       # Trained v2 model
│       ├── checkpoint_best.pt
│       └── test_results.json
│
└── docs/
    ├── ML_MODEL_DEVELOPMENT_GUIDE.md # General ML best practices
    └── PROJECT_SUMMARY.md            # This file
```

---

## 🎯 Expected Results

### Current (v2 Model)
- **Test F1:** 70.55%
- **Features:** Text + CWE + basic metadata
- **Missing:** CVSS components!

### Target (v3 Model)
- **Test F1:** 78-82%
- **Features:** Text + CWE + 8 CVSS components + exploit/patch
- **Why better:** CVSS components are DIRECT severity indicators

### Feature Comparison
| Feature | v2 | v3 |
|---------|----|----|
| Text (DistilBERT) | ✅ | ✅ |
| CWE embedding | ✅ | ✅ |
| CWE category | ✅ | ✅ |
| Reference count | ✅ | ✅ |
| cvss_score | ✅ | ✅ |
| attackVector | ❌ | ✅ NEW |
| attackComplexity | ❌ | ✅ NEW |
| privilegesRequired | ❌ | ✅ NEW |
| userInteraction | ❌ | ✅ NEW |
| scope | ❌ | ✅ NEW |
| confidentialityImpact | ❌ | ✅ NEW |
| integrityImpact | ❌ | ✅ NEW |
| availabilityImpact | ❌ | ✅ NEW |
| exploitabilityScore | ❌ | ✅ NEW |
| impactScore | ❌ | ✅ NEW |
| has_exploit | ⚠️ partial | ✅ FULL |
| has_patch | ⚠️ partial | ✅ FULL |

---

## 📝 Key Learnings from This Project

### 1. Data Quality > Model Complexity
```
73.4% on dirty data (30K duplicates) → MEANINGLESS
70.5% on clean data → HONEST baseline
```

### 2. Collect ALL Available Features
```
Old: Just cvss_score (single number)
New: All 8 CVSS components + scores + indicators
Impact: Expected +8-12% F1 improvement
```

### 3. EDA Before Everything
```
Always check:
- Duplicates (found 30K in v1!)
- Missing values (12.6K need removal)
- Label distribution (4% LOW = need focal loss)
- Feature coverage (93% have CVSS v3)
```

### 4. Stratified Splits
```
Maintain class distribution across train/val/test
Prevents biased evaluation
```

### 5. Honest Evaluation
```
Test set is SACRED
Only use ONCE at the end
Report results even if disappointing
```

---

## 🔧 Technical Specifications

### Hardware
- MacBook Pro (Apple Silicon M-series)
- Device: MPS (Metal Performance Shaders)
- Training time: ~2 hours/epoch

### Software Stack
```
Python 3.10+
PyTorch 2.0+
Transformers 4.35+
scikit-learn 1.3+
```

### Model Architecture (v3 - Planned)
```
Text Input → DistilBERT → [CLS] → 768-dim → 512-dim
                                      ↓
CVSS Components (8) → Embeddings → 64-dim total
                                      ↓
CWE ID → Embedding(732, 64) → 64-dim
                                      ↓
Numeric (exploit/impact scores) → 32-dim
                                      ↓
                        CONCATENATE (512 + 64 + 64 + 32 = 672)
                                      ↓
                        Classifier → 4 classes
```

---

## 📞 Contact

**Ruthvik Bandari**  
Email: bandari.ru@northeastern.edu  
Institution: Northeastern University - MS Applied AI

---

## 🎯 One-Line Summary

> **CTPPO v3:** Multi-modal CVE severity classifier with full CVSS components, targeting 78-82% F1 on 176K clean CVEs from 2020-2025.

---

## ⚡ Quick Commands Reference

```bash
# CURRENT: Clean and prepare data
python ml/03_clean_and_label.py --input data/nvd_complete/nvd_complete.jsonl --output data/clean_v3

# NEXT: Train v3 model
python ml/04_train_v3.py --data-dir data/clean_v3/splits --epochs 10

# THEN: Evaluate
python ml/05_evaluate_v3.py --model-dir models/severity_v3
```

---

*Last updated: January 27, 2026 - Ready for Phase 3 training*

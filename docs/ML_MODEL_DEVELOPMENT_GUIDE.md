# 🎯 Machine Learning Model Development Guide
## Complete Methodology for Building Production-Quality ML Models

**Author:** Ruthvik Bandari  
**Date:** January 2026  
**Purpose:** Reference guide for developing high-quality ML models

---

## 📚 Table of Contents
1. [Core Principles](#1-core-principles)
2. [Data Pipeline](#2-data-pipeline)
3. [Model Development](#3-model-development)
4. [Training Best Practices](#4-training-best-practices)
5. [Evaluation & Metrics](#5-evaluation--metrics)
6. [Common Pitfalls](#6-common-pitfalls)
7. [Production Considerations](#7-production-considerations)

---

## 1. Core Principles

### 🎯 The Golden Rule
```
Good Data → Good Model → Good Results
Garbage Data → Garbage Model → Garbage Results

ALWAYS prioritize data quality over model complexity!
```

### 📊 ML Development Workflow
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CORRECT ML WORKFLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. UNDERSTAND THE PROBLEM                                                  │
│     └── What are we predicting? Why? What's the business value?            │
│                                                                             │
│  2. COLLECT DATA                                                            │
│     └── Get ALL available fields, not just what you think you need         │
│                                                                             │
│  3. EXPLORATORY DATA ANALYSIS (EDA)                                        │
│     └── NEVER skip this! Understand data before modeling                   │
│                                                                             │
│  4. CLEAN & PREPROCESS                                                      │
│     └── Handle missing values, duplicates, inconsistencies                 │
│                                                                             │
│  5. FEATURE ENGINEERING                                                     │
│     └── Create meaningful features from raw data                           │
│                                                                             │
│  6. SPLIT DATA                                                              │
│     └── Train/Val/Test with stratification (no data leakage!)              │
│                                                                             │
│  7. TRAIN MODEL                                                             │
│     └── Start simple, add complexity only if needed                        │
│                                                                             │
│  8. EVALUATE HONESTLY                                                       │
│     └── Test set is sacred - only use once at the end!                     │
│                                                                             │
│  9. ITERATE                                                                 │
│     └── Based on error analysis, not random guessing                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Pipeline

### 2.1 Data Collection

**Key Principles:**
- Collect ALL available fields (you can drop later, can't add what you don't have)
- Document data sources and collection date
- Understand API rate limits and pagination
- Handle errors gracefully with retries

**Example: NVD API Fetching**
```python
# Key learnings:
# 1. APIs have rate limits (NVD: 5 req/30s without key, 50 with key)
# 2. APIs have date range limits (NVD: 120 days max)
# 3. Use params dict for proper URL encoding
# 4. Chunk large requests into smaller pieces

params = {
    'pubStartDate': '2024-01-01T00:00:00.000',
    'pubEndDate': '2024-03-31T23:59:59.999',  # 90 days, not 365!
    'resultsPerPage': 2000
}
response = requests.get(BASE_URL, params=params)  # Proper encoding!
```

### 2.2 Exploratory Data Analysis (EDA)

**NEVER SKIP EDA! Always check:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  EDA CHECKLIST                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  □ Basic Statistics                                                         │
│    ├── Total records                                                        │
│    ├── Date/time distribution                                               │
│    └── Data source breakdown                                                │
│                                                                             │
│  □ Missing Values (per field)                                               │
│    ├── Count and percentage                                                 │
│    ├── Pattern (random vs systematic?)                                      │
│    └── Strategy for handling                                                │
│                                                                             │
│  □ Duplicates                                                               │
│    ├── Exact duplicates                                                     │
│    ├── Near-duplicates (same ID, different values)                         │
│    └── Impact on training                                                   │
│                                                                             │
│  □ Label Distribution                                                       │
│    ├── Class balance/imbalance                                              │
│    ├── Label quality (inconsistencies?)                                     │
│    └── Need for resampling/weighting?                                      │
│                                                                             │
│  □ Feature Distributions                                                    │
│    ├── Categorical: value counts                                            │
│    ├── Numerical: min, max, mean, outliers                                 │
│    └── Text: length distribution, quality                                  │
│                                                                             │
│  □ Feature Correlations                                                     │
│    ├── Feature-to-label correlation                                        │
│    └── Feature-to-feature (redundancy)                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Example: What we found in CTPPO**
```
✅ Duplicates: 0 (clean!)
✅ Empty descriptions: 0 (clean!)
⚠️  Missing CVSS: 12,653 (6.7%) → REMOVE
⚠️  Missing CWE: 12,411 (6.6%) → Use "UNKNOWN"
⚠️  Class imbalance: LOW=4%, MEDIUM=48% → Use focal loss
```

### 2.3 Data Cleaning

**Cleaning Strategy Template:**
```python
CLEANING_RULES = {
    # Field: (action, reason)
    'no_label': ('REMOVE', "Can't train without target"),
    'no_features': ('REMOVE', "No signal for model"),
    'duplicates': ('REMOVE', "Inflates metrics, causes leakage"),
    'missing_optional': ('IMPUTE', "Use default/unknown category"),
    'outliers': ('CLIP_OR_REMOVE', "Depends on domain knowledge"),
    'inconsistent_labels': ('RECOMPUTE', "Use consistent formula"),
}
```

**Key Insight: Label Consistency**
```python
# BAD: Using inconsistent human-assigned labels
label = record['human_severity']  # Varies by annotator!

# GOOD: Computing labels from objective scores
score = record['cvss_score']
if score >= 9.0: label = 'CRITICAL'
elif score >= 7.0: label = 'HIGH'
elif score >= 4.0: label = 'MEDIUM'
else: label = 'LOW'
```

### 2.4 Data Splitting

**CRITICAL: Prevent Data Leakage!**

```python
# WRONG: Random split can leak information
train, test = random_split(data)  # ❌ Duplicates might span both!

# RIGHT: Split AFTER deduplication, with stratification
data = remove_duplicates(data)
train, val, test = stratified_split(data, 
    ratios=[0.8, 0.1, 0.1],
    stratify_by='label'
)

# Verify stratification
for split_name, split_data in [('train', train), ('val', val), ('test', test)]:
    distribution = Counter(d['label'] for d in split_data)
    print(f"{split_name}: {distribution}")
    # Should be similar proportions in all splits!
```

---

## 3. Model Development

### 3.1 Feature Engineering

**Types of Features:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  FEATURE TYPES                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TEXT FEATURES:                                                             │
│  ├── Transformer embeddings (BERT, DistilBERT)                             │
│  ├── TF-IDF (simpler, interpretable)                                       │
│  └── Word counts, n-grams                                                   │
│                                                                             │
│  CATEGORICAL FEATURES:                                                      │
│  ├── One-hot encoding (few categories)                                     │
│  ├── Label encoding + embedding (many categories)                          │
│  └── Target encoding (careful of leakage!)                                 │
│                                                                             │
│  NUMERICAL FEATURES:                                                        │
│  ├── Normalize to [0,1] or standardize to N(0,1)                          │
│  ├── Log transform for skewed distributions                                │
│  └── Binning for non-linear relationships                                  │
│                                                                             │
│  DERIVED FEATURES:                                                          │
│  ├── Domain-specific combinations                                          │
│  ├── Temporal features (day, month, recency)                               │
│  └── Aggregations (counts, averages)                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Example: CVSS Component Encoding**
```python
CVSS_ENCODINGS = {
    'attackVector': {'NETWORK': 0, 'ADJACENT_NETWORK': 1, 'LOCAL': 2, 'PHYSICAL': 3},
    'attackComplexity': {'LOW': 0, 'HIGH': 1},
    'privilegesRequired': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
    # ... etc
}

# Use -1 for missing values (model learns to handle)
encoded = CVSS_ENCODINGS['attackVector'].get(value, -1)
```

### 3.2 Model Architecture

**Multi-Modal Fusion Pattern:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MULTI-MODAL ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TEXT INPUT                     METADATA INPUT                              │
│      │                              │                                       │
│      ▼                              ▼                                       │
│  ┌─────────┐                   ┌─────────┐                                 │
│  │DistilBERT│                   │Embeddings│ (CWE, categories)              │
│  └────┬────┘                   └────┬────┘                                 │
│       │                              │                                       │
│       ▼                              ▼                                       │
│  ┌─────────┐                   ┌─────────┐                                 │
│  │ Pooling │                   │  Linear │                                 │
│  │ (mean)  │                   │ + ReLU  │                                 │
│  └────┬────┘                   └────┬────┘                                 │
│       │                              │                                       │
│       ▼                              ▼                                       │
│  ┌─────────┐                   ┌─────────┐                                 │
│  │Text Proj│                   │Meta Proj│                                 │
│  │ 768→512 │                   │ 128→128 │                                 │
│  └────┬────┘                   └────┬────┘                                 │
│       │                              │                                       │
│       └──────────┬───────────────────┘                                       │
│                  │                                                           │
│                  ▼                                                           │
│            ┌──────────┐                                                     │
│            │ CONCAT   │  (512 + 128 = 640)                                  │
│            └────┬─────┘                                                     │
│                 │                                                            │
│                 ▼                                                            │
│            ┌──────────┐                                                     │
│            │Classifier│  640 → 256 → 128 → num_classes                     │
│            └────┬─────┘                                                     │
│                 │                                                            │
│                 ▼                                                            │
│              OUTPUT                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Training Best Practices

### 4.1 Loss Functions

**For Imbalanced Classification:**

```python
# Standard CrossEntropy - BAD for imbalanced data
loss = nn.CrossEntropyLoss()

# Weighted CrossEntropy - BETTER
class_weights = compute_class_weights(train_labels)  # Inverse frequency
loss = nn.CrossEntropyLoss(weight=class_weights)

# Focal Loss - BEST for imbalanced
class FocalLoss(nn.Module):
    def __init__(self, gamma=2.0, alpha=None):
        # gamma: focuses on hard examples
        # alpha: class weights
        
    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss
        return focal_loss.mean()
```

### 4.2 Regularization Techniques

**Preventing Overfitting:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  REGULARIZATION TECHNIQUES                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. DROPOUT                                                                 │
│     └── Randomly zeros neurons during training                              │
│     └── Typical values: 0.1-0.5                                            │
│     └── Higher = more regularization                                        │
│                                                                             │
│  2. WEIGHT DECAY (L2 Regularization)                                       │
│     └── Penalizes large weights: Loss += λ * ||W||²                        │
│     └── Typical values: 0.01-0.1                                           │
│     └── Built into optimizer: AdamW(weight_decay=0.01)                     │
│                                                                             │
│  3. EARLY STOPPING                                                          │
│     └── Stop when validation loss stops improving                          │
│     └── Patience: wait N epochs before stopping                            │
│     └── Save best model checkpoint!                                        │
│                                                                             │
│  4. LABEL SMOOTHING                                                         │
│     └── Soft labels: [0, 0, 1, 0] → [0.025, 0.025, 0.925, 0.025]          │
│     └── Prevents overconfidence                                            │
│     └── Typical values: 0.1                                                │
│                                                                             │
│  5. DATA AUGMENTATION                                                       │
│     └── For text: synonym replacement, back-translation                    │
│     └── For images: rotation, flipping, cropping                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Learning Rate Scheduling

```python
# Cosine annealing with warmup - RECOMMENDED
def get_cosine_schedule_with_warmup(optimizer, warmup_steps, total_steps):
    def lr_lambda(step):
        if step < warmup_steps:
            return step / warmup_steps  # Linear warmup
        progress = (step - warmup_steps) / (total_steps - warmup_steps)
        return 0.5 * (1 + math.cos(math.pi * progress))  # Cosine decay
    return LambdaLR(optimizer, lr_lambda)

# Usage
scheduler = get_cosine_schedule_with_warmup(
    optimizer,
    warmup_steps=len(train_loader),  # 1 epoch warmup
    total_steps=len(train_loader) * num_epochs
)
```

### 4.4 Detecting Overfitting

```
OVERFITTING SIGNS:
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  Train Loss: 0.40 (very low - memorizing!)                │
│  Val Loss:   1.34 (high - not generalizing!)              │
│  Gap:        0.94 (too large!)                            │
│                                                            │
│  What to do:                                               │
│  1. Increase dropout (0.3 → 0.5)                          │
│  2. Increase weight decay (0.01 → 0.05)                   │
│  3. Add label smoothing (0.1)                             │
│  4. Reduce model capacity                                  │
│  5. Get more data / data augmentation                     │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## 5. Evaluation & Metrics

### 5.1 Loss Function vs Metrics

**CRITICAL DISTINCTION:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   LOSS FUNCTION = How the MODEL learns                                      │
│   └── Must be DIFFERENTIABLE (for backpropagation)                         │
│   └── Examples: CrossEntropy, Focal Loss, MSE                              │
│                                                                             │
│   METRICS = How WE evaluate                                                 │
│   └── NOT differentiable (discrete counting)                               │
│   └── Examples: Accuracy, F1, Precision, Recall                            │
│                                                                             │
│   Both need labeled data, but serve different purposes!                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Classification Metrics

```python
# For imbalanced data, DON'T rely only on accuracy!

# Accuracy: Can be misleading
# If 90% of data is class A, predicting all A gives 90% accuracy!

# Better metrics:
from sklearn.metrics import classification_report, f1_score

# F1 Score (balance of precision and recall)
f1_weighted = f1_score(y_true, y_pred, average='weighted')  # Weighted by support
f1_macro = f1_score(y_true, y_pred, average='macro')  # Equal weight per class

# Per-class analysis
print(classification_report(y_true, y_pred, target_names=class_names))

# Confusion matrix for error analysis
cm = confusion_matrix(y_true, y_pred)
```

### 5.3 Honest Evaluation

**Test Set Rules:**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│  TEST SET IS SACRED!                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ✅ DO:                                                                     │
│  └── Use test set ONLY ONCE at the very end                                │
│  └── Use validation set for all tuning decisions                           │
│  └── Report test metrics honestly (even if disappointing)                  │
│                                                                             │
│  ❌ DON'T:                                                                  │
│  └── Tune hyperparameters on test set                                      │
│  └── Run test multiple times and report best                               │
│  └── Peek at test set during development                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Common Pitfalls

### 6.1 Data Leakage

```python
# LEAKAGE TYPE 1: Duplicates across splits
# BAD
all_data = load_data()  # Contains duplicates
train, test = split(all_data)  # Same record in both!

# GOOD
all_data = load_data()
all_data = remove_duplicates(all_data)  # FIRST dedupe
train, test = split(all_data)  # THEN split

# LEAKAGE TYPE 2: Target leakage (feature reveals target)
# BAD: Using CVSS score as feature to predict severity
# (Severity IS derived from CVSS score!)

# LEAKAGE TYPE 3: Preprocessing on full data
# BAD
scaler.fit(all_data)  # Learns from test data!
train = scaler.transform(train_data)
test = scaler.transform(test_data)

# GOOD
scaler.fit(train_data)  # Only train!
train = scaler.transform(train_data)
test = scaler.transform(test_data)
```

### 6.2 Inflated Baseline

```
Our experience:
- Old model: 73.4% F1 on DIRTY data (30K duplicates)
- New model: 70.8% F1 on CLEAN data

First reaction: "New model is worse!"
Reality: Old model was inflated by duplicates

ALWAYS compare models on SAME clean data!
```

### 6.3 Class Imbalance

```python
# Problem: Uneven class distribution
# CRITICAL: 11%, HIGH: 37%, MEDIUM: 48%, LOW: 4%

# Solution 1: Class weights
weights = compute_class_weight('balanced', classes=unique_classes, y=y_train)
loss_fn = CrossEntropyLoss(weight=torch.tensor(weights))

# Solution 2: Focal Loss (focuses on hard examples)
loss_fn = FocalLoss(gamma=2.0)

# Solution 3: Resampling (SMOTE, undersampling)
# Be careful: can introduce artifacts
```

---

## 7. Production Considerations

### 7.1 Model Serving Checklist

```
□ Model serialization (save weights + config)
□ Tokenizer/preprocessing pipeline saved
□ Feature encodings documented and saved
□ Inference API (FastAPI, Flask)
□ Input validation
□ Error handling
□ Logging and monitoring
□ Latency requirements met
□ Memory footprint acceptable
```

### 7.2 Documentation Requirements

```
□ Data sources and collection process
□ Preprocessing steps
□ Feature engineering decisions
□ Model architecture
□ Training hyperparameters
□ Evaluation metrics
□ Known limitations
□ Example usage
```

### 7.3 Continuous Improvement

```
1. Monitor predictions in production
2. Collect feedback / corrections
3. Retrain on new data periodically
4. A/B test new models
5. Track model drift
```

---

## 📝 Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ML MODEL DEVELOPMENT QUICK REFERENCE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  DATA:                                                                      │
│  ✓ Collect ALL fields                                                       │
│  ✓ EDA before ANYTHING else                                                │
│  ✓ Check duplicates, missing values                                        │
│  ✓ Stratified splits AFTER deduplication                                   │
│                                                                             │
│  FEATURES:                                                                  │
│  ✓ Text → Transformer embeddings                                           │
│  ✓ Categorical → Embeddings or one-hot                                     │
│  ✓ Numerical → Normalize to [0,1]                                          │
│  ✓ Handle missing with -1 or "UNKNOWN"                                     │
│                                                                             │
│  TRAINING:                                                                  │
│  ✓ Focal loss for imbalanced data                                          │
│  ✓ Dropout (0.3-0.5) + Weight decay (0.01-0.05)                           │
│  ✓ Cosine LR schedule with warmup                                          │
│  ✓ Early stopping with patience                                            │
│  ✓ Save best checkpoint (by val F1)                                        │
│                                                                             │
│  EVALUATION:                                                                │
│  ✓ F1 weighted/macro for imbalanced                                        │
│  ✓ Per-class metrics                                                       │
│  ✓ Confusion matrix for error analysis                                     │
│  ✓ Test set ONLY at the end                                                │
│                                                                             │
│  OVERFITTING FIXES:                                                         │
│  ✓ Increase dropout                                                        │
│  ✓ Increase weight decay                                                   │
│  ✓ Add label smoothing                                                     │
│  ✓ More data / augmentation                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

**Remember:** Good ML is 80% data, 15% features, 5% model!

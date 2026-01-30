# CTPPO v2.0: Step-by-Step Execution Guide

## Quick Start Commands

```bash
# Navigate to project
cd /home/claude/ctppo

# Install dependencies
pip install requests nltk numpy pandas scikit-learn torch transformers tqdm --break-system-packages

# Run the interactive guide
python ml/step_by_step_guide.py
```

---

## Understanding the File Structure

```
ctppo/
├── ml/
│   ├── data_pipeline/           # NEW: Fixed data pipeline
│   │   ├── __init__.py          
│   │   ├── data_collector.py    # Stage 1: Fetch CVEs with GROUND TRUTH
│   │   ├── data_cleaner.py      # Stage 2: Clean text properly
│   │   ├── feature_engineer.py  # Stage 3: Rich feature extraction
│   │   ├── data_splitter.py     # Stage 4: Stratified splitting
│   │   └── dataset.py           # Stage 5: PyTorch datasets
│   │
│   ├── training_pipeline.py     # Complete training (all stages combined)
│   ├── step_by_step_guide.py    # Interactive learning guide
│   │
│   ├── data_preprocessor.py     # OLD: Broken (has data leakage)
│   └── train_severity_classifier.py  # OLD: Uses broken preprocessor
│
├── docs/
│   ├── MISTAKES_AND_FIXES.md    # Detailed analysis of errors
│   └── ML_PIPELINE_GUIDE.md     # Educational ML guide
│
└── data/
    └── cache/                   # Cached API responses
```

---

## Step-by-Step: What Each File Does

### STEP 1: Data Collection (`data_collector.py`)

**Purpose:** Fetch CVE data with GROUND TRUTH labels

**Key Code:**
```python
from ml.data_pipeline.data_collector import CVEDataCollector

# Create collector
collector = CVEDataCollector(api_key=None)  # Optional API key

# Fetch CVEs
records = collector.fetch_cves(keyword="apache", limit=100)

# Each record has:
# - cve_id: "CVE-2021-44228"
# - description: "A vulnerability in..."
# - cvss_score: 10.0  ← THIS IS GROUND TRUTH!
# - severity_label: CRITICAL  ← DERIVED FROM CVSS (not model prediction!)
```

**What changed from your old code:**
```python
# OLD (WRONG) - data_preprocessor.py line 250
severity = self.predict_severity(descriptions)  # Model prediction as label!

# NEW (CORRECT) - data_collector.py
severity = cvss_to_severity(cvss_score)  # Ground truth from CVSS!
```

---

### STEP 2: Data Cleaning (`data_cleaner.py`)

**Purpose:** Clean text and extract metadata

**Key Code:**
```python
from ml.data_pipeline.data_cleaner import TextCleaner, CVECleaner

cleaner = CVECleaner(TextCleaner())

# Clean a record
cleaned = cleaner.clean_record(record)

# Returns:
# - cleaned_description: Clean text for model
# - text_metadata:
#   - extracted_urls: ["https://..."]
#   - extracted_cves: ["CVE-2021-3449"]
#   - has_exploit_mention: True
#   - has_patch_mention: False
```

**Cleaning Pipeline:**
```
Raw: "A vulnerability in &lt;script&gt; OpenSSL v1.1.1k allows..."
  ↓ HTML decode
  ↓ Remove HTML tags
  ↓ Extract URLs (store count)
  ↓ Extract CVE references
  ↓ Normalize versions
  ↓ Lowercase
  ↓ Tokenize & lemmatize
Clean: "vulnerability openssl version allow remote code execution"
```

---

### STEP 3: Feature Engineering (`feature_engineer.py`)

**Purpose:** Create rich features for model

**Key Code:**
```python
from ml.data_pipeline.feature_engineer import FeatureEngineer

engineer = FeatureEngineer()
feature_sets = engineer.engineer_batch(cleaned_records)

# Each FeatureSet contains:
# - text: Cleaned description
# - numerical_features: 40+ features
# - severity_label: Ground truth
# - feature_vector: numpy array
```

**Features Created:**

| Category | Features | Your Old Code |
|----------|----------|---------------|
| Text | length, word_count, avg_word_length | ✓ Had some |
| CVSS Vector | av_score, ac_score, pr_score, ui_score, scope_score, c_impact, i_impact, a_impact | ❌ Missing! |
| Derived | ease_of_exploit, total_impact | ❌ Missing! |
| Binary | is_network_attack, requires_no_privs, has_exploit_mention | ❌ Missing! |
| Temporal | days_since_published, is_recent | ❌ Missing! |
| References | reference_count, has_patch_ref | ❌ Missing! |

---

### STEP 4: Data Splitting (`data_splitter.py`)

**Purpose:** Split data properly with stratification

**Key Code:**
```python
from ml.data_pipeline.data_splitter import DataSplitter

splitter = DataSplitter(random_state=42)  # Reproducible!

split = splitter.stratified_split(
    data=data,
    labels=labels,
    test_size=0.15,   # 15% test
    val_size=0.15     # 15% validation
)

# Returns:
# - train_indices, train_labels (70%)
# - val_indices, val_labels (15%)
# - test_indices, test_labels (15%)
```

**Why Stratified?**
```
Original: CRITICAL=5%, HIGH=20%, MEDIUM=50%, LOW=25%

Random Split (BAD):
  Train: CRITICAL=3%, HIGH=22%...  ← Different distribution!
  Val:   CRITICAL=8%, HIGH=18%...  ← Misleading evaluation!

Stratified Split (GOOD):
  Train: CRITICAL=5%, HIGH=20%, MEDIUM=50%, LOW=25%  ✓
  Val:   CRITICAL=5%, HIGH=20%, MEDIUM=50%, LOW=25%  ✓
  Test:  CRITICAL=5%, HIGH=20%, MEDIUM=50%, LOW=25%  ✓
```

---

### STEP 5: Class Balancing (`data_splitter.py`)

**Purpose:** Handle imbalanced data

**Key Code:**
```python
class_weights = splitter.compute_class_weights(train_labels, method='balanced')

# Result: {0: 0.8, 1: 0.4, 2: 1.0, 3: 2.5}
#         LOW   MED   HIGH  CRITICAL
#
# CRITICAL has weight 2.5 = penalize mistakes 2.5x more!
```

**Why It Matters:**
```
Without weights:
  Model predicts "MEDIUM" for everything → 50% accuracy
  But misses ALL critical vulnerabilities!

With weights:
  Model penalized heavily for missing CRITICAL
  Learns to identify rare but important classes
```

---

### STEP 6: Create Datasets (`dataset.py`)

**Purpose:** PyTorch datasets for training

**Key Code:**
```python
from ml.data_pipeline.dataset import CVEDataset

train_dataset = CVEDataset(
    texts=train_texts,
    labels=train_labels,       # GROUND TRUTH labels!
    tokenizer=tokenizer,       # BERT tokenizer
    feature_vectors=features   # Numerical features
)

# Usage in training loop:
for batch in DataLoader(train_dataset, batch_size=16):
    input_ids = batch['input_ids']
    attention_mask = batch['attention_mask']
    labels = batch['labels']  # 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
    features = batch['features']
```

---

## Running the Complete Pipeline

### Option 1: Interactive Guide (Recommended for Learning)

```bash
cd /home/claude/ctppo
python ml/step_by_step_guide.py
```

This walks you through each stage interactively, showing outputs at each step.

### Option 2: Full Training Pipeline

```bash
cd /home/claude/ctppo
python ml/training_pipeline.py --samples 1000 --epochs 5
```

This runs the complete training with all fixes.

### Option 3: Test Individual Components

```python
# Test data collection
from ml.data_pipeline.data_collector import CVEDataCollector
collector = CVEDataCollector()
records = collector.fetch_cves(keyword="linux", limit=10)
print(f"Got {len(records)} CVEs")
for r in records[:3]:
    print(f"  {r.cve_id}: CVSS={r.cvss_score} → {r.severity_label.value}")
```

```python
# Test cleaning
from ml.data_pipeline.data_cleaner import TextCleaner
cleaner = TextCleaner()
result = cleaner.clean("A <script>XSS</script> vulnerability in v1.2.3...")
print(f"Cleaned: {result.cleaned_text}")
print(f"Versions: {result.extracted_versions}")
```

```python
# Test splitting
from ml.data_pipeline.data_splitter import DataSplitter
import numpy as np

splitter = DataSplitter(random_state=42)
labels = np.array(['CRITICAL']*50 + ['HIGH']*200 + ['MEDIUM']*500 + ['LOW']*250)
dist = splitter.get_class_distribution(labels)
print(f"Imbalance ratio: {dist['imbalance_ratio']}")
```

---

## Checklist: Before Training

- [ ] Dependencies installed (`pip install transformers torch sklearn nltk`)
- [ ] NLTK data downloaded (automatic on first run)
- [ ] Optional: NVD API key set (`export NVD_API_KEY="your-key"`)
- [ ] Understand each pipeline stage
- [ ] Know why CVSS is ground truth (not model predictions)
- [ ] Know why stratified splitting matters
- [ ] Know why class weights are needed

---

## Common Issues & Solutions

### Issue: "No module named 'transformers'"
```bash
pip install transformers --break-system-packages
```

### Issue: "Rate limit exceeded" from NVD
- Without API key: 6 second delay between requests
- Get free API key: https://nvd.nist.gov/developers/request-an-api-key

### Issue: "Not enough samples for splitting"
- Increase `limit` when fetching CVEs
- For real training, use 5000+ samples

### Issue: NLTK download fails
```python
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
```

---

## Next Steps After Understanding Pipeline

1. **Run full training** with `training_pipeline.py`
2. **Add experiment tracking** (MLflow integration)
3. **Build RL continuous learning** system
4. **Integrate GNN** for attack path prediction
5. **Create unified architecture** (BERT + GNN + RL)

Ready to proceed to the RL system?

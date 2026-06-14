# CTPPO v2.0 - Complete Setup and Training Guide

## 📁 What You Downloaded vs What's In The Project

### Downloaded Files (Documentation - READ THESE)
| File | Purpose |
|------|---------|
| `MISTAKES_AND_FIXES.md` | Explains all the mistakes in your old code |
| `ML_PIPELINE_GUIDE.md` | Educational guide on proper ML pipelines |
| `STEP_BY_STEP_GUIDE.md` | Step-by-step instructions |

**These are for READING, not running!**

### Project Files (Code - RUN THESE)
```
ctppo/
├── ml/
│   ├── fetch_all_cves.py        # ← Step 1: Fetch ALL CVE data
│   ├── train_full_dataset.py    # ← Step 2: Prepare data for training
│   ├── training_pipeline.py     # ← Step 3: Train the model
│   │
│   ├── data_pipeline/           # Core pipeline modules
│   │   ├── data_collector.py    # Fetches CVEs with GROUND TRUTH
│   │   ├── data_cleaner.py      # Cleans text properly
│   │   ├── feature_engineer.py  # Extracts 40+ features
│   │   ├── data_splitter.py     # Stratified splitting
│   │   └── dataset.py           # PyTorch datasets
│   │
│   ├── offline_demo.py          # Demo without network
│   └── step_by_step_guide.py    # Interactive learning
│
├── data/
│   ├── nvd_full/                # Raw CVE data (after fetching)
│   │   ├── all_cves.jsonl       # All CVEs in JSON Lines format
│   │   └── fetch_stats.json     # Fetch statistics
│   │
│   └── prepared/                # Prepared train/val/test splits
│       ├── train.jsonl
│       ├── val.jsonl
│       ├── test.jsonl
│       └── dataset_summary.json
│
└── docs/
    ├── MISTAKES_AND_FIXES.md
    ├── ML_PIPELINE_GUIDE.md
    └── STEP_BY_STEP_GUIDE.md
```

---

## 🚀 Complete Workflow (Follow These Steps!)

### Step 0: Get an NVD API Key (HIGHLY RECOMMENDED!)

**Without API key:** 6 seconds between requests = ~14 days for full database
**With API key:** 0.6 seconds between requests = ~1.5 days for full database

Get your FREE key at: https://nvd.nist.gov/developers/request-an-api-key

```bash
# Set your API key as environment variable
export NVD_API_KEY="your-api-key-here"
```

---

### Step 1: Fetch ALL CVE Data

```bash
cd /path/to/ctppo

# Option A: Fetch ALL CVEs (200,000+) - Takes ~1.5 days with API key
python ml/fetch_all_cves.py --api-key $NVD_API_KEY

# Option B: Fetch last 2 years only (faster for testing)
python ml/fetch_all_cves.py --api-key $NVD_API_KEY --days 730

# Option C: Fetch specific date range
python ml/fetch_all_cves.py --api-key $NVD_API_KEY --start-date 2020-01-01 --end-date 2024-12-31

# If interrupted, resume with:
python ml/fetch_all_cves.py --api-key $NVD_API_KEY --resume
```

**What this does:**
- Fetches CVE data from NVD API
- Saves to `data/nvd_full/all_cves.jsonl`
- Checkpoints progress (can resume if interrupted)
- Extracts CVSS scores as **GROUND TRUTH** labels

---

### Step 2: Analyze and Prepare Dataset

```bash
# Analyze what you downloaded
python ml/train_full_dataset.py --analyze

# Prepare full dataset for training
python ml/train_full_dataset.py

# Or prepare a balanced subset (equal samples per class)
python ml/train_full_dataset.py --balanced --samples-per-class 20000

# Or limit total samples for quick testing
python ml/train_full_dataset.py --max-samples 50000
```

**What this does:**
- Loads all CVEs from `data/nvd_full/all_cves.jsonl`
- Filters out invalid records (no CVSS, short descriptions)
- Performs **STRATIFIED** train/val/test split (70/15/15)
- Computes class weights for imbalanced data
- Saves to `data/prepared/train.jsonl`, `val.jsonl`, `test.jsonl`

---

### Step 3: Train the Model

```bash
# Install dependencies first
pip install torch transformers scikit-learn nltk pandas numpy tqdm

# Train on prepared data
python ml/training_pipeline.py --data-dir data/prepared --epochs 5

# Or train with specific settings
python ml/training_pipeline.py \
    --data-dir data/prepared \
    --epochs 10 \
    --batch-size 32 \
    --learning-rate 2e-5 \
    --output-dir models/severity_v2
```

**What this does:**
- Loads prepared train/val/test data
- Cleans text with full pipeline
- Engineers 40+ features
- Trains DistilBERT with class weights
- Uses early stopping to prevent overfitting
- Saves best model and metrics

---

## 📊 Expected Results

### With Full Dataset (200,000+ CVEs)

| Metric | Expected Range |
|--------|----------------|
| Overall Accuracy | 75-85% |
| CRITICAL F1 | 70-80% |
| HIGH F1 | 70-80% |
| MEDIUM F1 | 75-85% |
| LOW F1 | 65-75% |

**Why not 98%?** Because 98% was FAKE due to data leakage. Real performance on real security data is 75-85%.

---

## 🔑 Key Concepts To Remember

### 1. Ground Truth
```
WRONG:  labels = model.predict(descriptions)  # Data leakage!
RIGHT:  labels = cvss_to_severity(cvss_scores)  # From NVD experts!
```

### 2. Stratified Splitting
```
WRONG:  train, val = random_split(data, [0.8, 0.2])
RIGHT:  train, val, test = stratified_split(data, stratify=labels)
```

### 3. Class Weights
```
WRONG:  loss = CrossEntropyLoss()  # All classes equal
RIGHT:  loss = CrossEntropyLoss(weight=[0.8, 0.4, 1.0, 2.5])
```

### 4. Proper Evaluation
```
WRONG:  print(f"Accuracy: {accuracy}")
RIGHT:  print(classification_report(y_true, y_pred))
        print(confusion_matrix(y_true, y_pred))
```

---

## ❓ FAQ

### Q: How long does fetching take?
- **With API key:** ~1.5 days for full database, ~2-4 hours for last year
- **Without API key:** ~14 days for full database (10x slower!)

### Q: Can I resume if it gets interrupted?
Yes! Run with `--resume` flag.

### Q: How much disk space do I need?
- Raw data: ~2-3 GB for full database
- Prepared data: ~500 MB for train/val/test splits

### Q: What if I just want to test the pipeline?
Use `--days 30` to fetch only last 30 days (~5000 CVEs).

---

## 📈 Next Steps After Basic Training

1. **Hyperparameter Tuning** - Use Optuna to find best learning rate, batch size
2. **Cross-Validation** - Run k-fold CV for more robust evaluation
3. **RL Continuous Learning** - Add reinforcement learning for real-time updates
4. **GNN Integration** - Build attack graph prediction

Ready for RL? Let me know and we'll build the continuous learning system!

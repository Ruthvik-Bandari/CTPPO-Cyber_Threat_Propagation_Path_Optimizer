# Complete ML Pipeline Guide: From Data to Deployment

## What You Did Wrong vs What You Should Do

This document explains every mistake in your CTPPO project and teaches the proper ML pipeline methodology.

---

## Part 1: The Mistakes You Made

### Mistake #1: Data Leakage (CRITICAL)

**What happened in your code:**

```python
# data_preprocessor.py lines 248-252
if self.severity_model and self.tokenizer:
    predicted_severities = self.predict_severity(df['cleaned_description'].tolist())
    df['severity_class'] = predicted_severities  # ← LEAKAGE!
```

**The Problem:**
- You loaded an existing model (even untrained DistilBERT)
- Used it to PREDICT severity labels from text
- Then trained on those predicted labels as "ground truth"
- The model learned to replicate its own predictions = fake 98% accuracy

**Visual Explanation:**

```
WRONG (What you did):
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Model     │─────▶│  Predict    │─────▶│   Labels    │
│ (untrained) │      │  Severity   │      │  (FAKE!)    │
└─────────────┘      └─────────────┘      └──────┬──────┘
                                                  │
                     ┌─────────────┐              │
                     │   Train     │◀─────────────┘
                     │   Model     │
                     └─────────────┘
                           │
                           ▼
                    98% Accuracy (MEANINGLESS!)

CORRECT (What you should do):
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   NVD API   │─────▶│ CVSS Score  │─────▶│   Labels    │
│ (Real Data) │      │ (0-10)      │      │  (REAL!)    │
└─────────────┘      └─────────────┘      └──────┬──────┘
                                                  │
                     ┌─────────────┐              │
                     │   Train     │◀─────────────┘
                     │   Model     │
                     └─────────────┘
                           │
                           ▼
                    Real Accuracy (MEANINGFUL!)
```

---

### Mistake #2: No Train/Validation/Test Split Strategy

**What happened:**
```python
# train_severity_classifier.py lines 64-66
train_size = int(0.8 * len(dataset))
val_size = len(dataset) - train_size
train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
```

**Problems:**
1. No TEST set - you can't evaluate generalization
2. Random split ignores class distribution (stratification)
3. No temporal consideration (newer CVEs might differ from older ones)

**Correct Approach:**
```
Dataset: 10,000 samples
    │
    ├── Train: 70% (7,000) - Model learns from this
    ├── Validation: 15% (1,500) - Tune hyperparameters
    └── Test: 15% (1,500) - Final evaluation (NEVER touch during training)
```

---

### Mistake #3: Ignoring Class Imbalance

**The Reality of CVE Severity Distribution:**
```
CRITICAL: 5%   ████
HIGH:     20%  ████████████████
MEDIUM:   50%  ████████████████████████████████████████████████
LOW:      25%  ████████████████████████
```

**What happens without handling:**
- Model predicts MEDIUM for everything → 50% accuracy
- Model never learns to identify CRITICAL vulnerabilities
- This is dangerous in cybersecurity!

**Solutions:**
1. Class weights in loss function
2. Oversampling minority classes (SMOTE)
3. Undersampling majority class
4. Stratified splitting

---

### Mistake #4: No Data Cleaning Pipeline

**Raw CVE descriptions contain:**
- HTML entities: `&lt;script&gt;`
- URLs: `https://example.com/exploit.php`
- Version numbers: `v1.2.3-beta`
- CVE references: `See CVE-2021-44228`
- Special characters: `\x00\xff`
- Inconsistent casing: `SQL injection`, `sql INJECTION`

**Your cleaning was minimal:**
```python
# Only basic cleaning
text = text.lower()
text = re.sub(r'https?://\S+|www\.\S+', '', text)
text = re.sub(r'\S+@\S+', '', text)
```

**Missing:**
- HTML decoding
- Version number normalization
- CVE ID extraction
- Attack pattern recognition
- Noise removal

---

### Mistake #5: No Feature Engineering

**What you extracted:**
- `desc_length` - Character count
- `num_words` - Word count
- Keyword presence (overflow, injection, etc.)

**What you missed:**
- CVSS vector components (AV, AC, PR, UI, S, C, I, A)
- Temporal features (CVE publish date, patch availability date)
- Vendor/product embeddings
- Attack complexity indicators
- Reference count (more references = more serious)
- CWE category encoding

---

### Mistake #6: No Experiment Tracking

**You had no way to:**
- Compare different model configurations
- Reproduce results
- Track what hyperparameters worked
- Version your datasets
- Log training metrics over time

---

## Part 2: The Correct ML Pipeline

### Stage 1: Data Collection

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA COLLECTION                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Sources:                                                       │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│   │   NVD    │  │  MITRE   │  │  ExploitDB│  │  GitHub  │       │
│   │   API    │  │  ATT&CK  │  │           │  │ Advisory │       │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│        │             │             │             │               │
│        └─────────────┴─────────────┴─────────────┘               │
│                          │                                       │
│                          ▼                                       │
│                  ┌──────────────┐                                │
│                  │  Raw Dataset │                                │
│                  │  (JSON/CSV)  │                                │
│                  └──────────────┘                                │
│                                                                  │
│   Key Fields:                                                    │
│   - CVE ID (unique identifier)                                   │
│   - Description (text)                                           │
│   - CVSS Score (0-10) ← GROUND TRUTH                            │
│   - CVSS Vector (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)          │
│   - Published Date                                               │
│   - Modified Date                                                │
│   - References (URLs to advisories, patches)                     │
│   - CWE IDs (weakness classification)                           │
│   - Affected Products (CPE strings)                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Code Example:**
```python
def fetch_ground_truth_labels(cve_data):
    """
    Extract REAL severity labels from CVSS scores.
    This is the GROUND TRUTH - never predict this!
    """
    labels = []
    for cve in cve_data:
        cvss = cve.get('cvss_v3_score', 0)
        
        # NVD official severity thresholds
        if cvss >= 9.0:
            labels.append('CRITICAL')
        elif cvss >= 7.0:
            labels.append('HIGH')
        elif cvss >= 4.0:
            labels.append('MEDIUM')
        else:
            labels.append('LOW')
    
    return labels
```

---

### Stage 2: Data Cleaning

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA CLEANING                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Input: Raw text                                                │
│   "A vulnerability in <script>alert('xss')</script> the         │
│    OpenSSL library v1.1.1k allows REMOTE attackers to           │
│    execute arbitrary code via CVE-2021-3449. See                │
│    https://openssl.org/news/secadv/20210325.txt"                │
│                                                                  │
│   Step 1: HTML Decoding                                          │
│   ────────────────────                                           │
│   &lt; → <                                                       │
│   &gt; → >                                                       │
│   &amp; → &                                                      │
│                                                                  │
│   Step 2: Remove HTML Tags                                       │
│   ────────────────────────                                       │
│   <script>...</script> → ""                                      │
│                                                                  │
│   Step 3: Extract & Remove URLs                                  │
│   ─────────────────────────────                                  │
│   https://... → [URL_EXTRACTED]                                  │
│   Store URLs separately for reference counting                   │
│                                                                  │
│   Step 4: Normalize Version Numbers                              │
│   ─────────────────────────────────                              │
│   v1.1.1k → VERSION_TOKEN                                        │
│   1.2.3-beta → VERSION_TOKEN                                     │
│                                                                  │
│   Step 5: Extract CVE References                                 │
│   ─────────────────────────────                                  │
│   CVE-2021-3449 → [CVE_EXTRACTED]                               │
│   Store for relationship mapping                                 │
│                                                                  │
│   Step 6: Normalize Case                                         │
│   ──────────────────────                                         │
│   REMOTE → remote                                                │
│   OpenSSL → openssl                                              │
│                                                                  │
│   Step 7: Remove Special Characters                              │
│   ─────────────────────────────────                              │
│   Keep alphanumeric, spaces, and meaningful punctuation          │
│                                                                  │
│   Step 8: Tokenization                                           │
│   ────────────────────                                           │
│   "allows remote attackers" → ["allows", "remote", "attackers"]  │
│                                                                  │
│   Step 9: Lemmatization (NOT Stemming)                          │
│   ─────────────────────────────────────                          │
│   "attackers" → "attacker"                                       │
│   "executing" → "execute"                                        │
│                                                                  │
│   Output: Clean text                                             │
│   "vulnerability openssl library VERSION_TOKEN allow remote      │
│    attacker execute arbitrary code"                              │
│                                                                  │
│   + Metadata:                                                    │
│   - url_count: 1                                                 │
│   - cve_references: ["CVE-2021-3449"]                           │
│   - has_version: True                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Why Each Step Matters:**

| Step | Why It's Important |
|------|-------------------|
| HTML Decoding | Raw data often has encoded entities |
| Remove HTML | Prevents model learning from markup |
| Extract URLs | URL count can indicate severity (more = serious) |
| Version Normalization | "v1.2.3" and "1.2.3" should be treated same |
| CVE Extraction | Builds relationship graph between vulnerabilities |
| Case Normalization | "SQL" and "sql" are the same concept |
| Lemmatization | Reduces vocabulary, improves generalization |

---

### Stage 3: Exploratory Data Analysis (EDA)

**Before training, ALWAYS analyze your data:**

```
┌─────────────────────────────────────────────────────────────────┐
│                 EXPLORATORY DATA ANALYSIS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Class Distribution                                          │
│   ─────────────────────                                          │
│                                                                  │
│   CRITICAL ████████                           8%                 │
│   HIGH     ████████████████████              20%                 │
│   MEDIUM   ████████████████████████████████████████████ 47%     │
│   LOW      ████████████████████████████     25%                 │
│                                                                  │
│   → IMBALANCED! Need stratification + class weights              │
│                                                                  │
│   2. Text Length Distribution                                    │
│   ───────────────────────────                                    │
│                                                                  │
│   Mean: 245 chars | Median: 198 chars | Max: 4521 chars         │
│                                                                  │
│   │    ╭──╮                                                      │
│   │   ╭╯  ╰╮                                                     │
│   │  ╭╯    ╰╮                                                    │
│   │ ╭╯      ╰──────────────────────                              │
│   └─────────────────────────────────                             │
│     0   200   400   600   800   1000+ chars                      │
│                                                                  │
│   → Right-skewed, consider truncation at 512 tokens              │
│                                                                  │
│   3. Missing Values                                              │
│   ─────────────────                                              │
│                                                                  │
│   description:  0.1% missing                                     │
│   cvss_score:   15% missing  ← IMPORTANT!                        │
│   cwe_id:       8% missing                                       │
│   vendor:       2% missing                                       │
│                                                                  │
│   → Need imputation strategy for CVSS                            │
│                                                                  │
│   4. Correlation Analysis                                        │
│   ────────────────────────                                       │
│                                                                  │
│   desc_length ↔ severity: 0.23 (weak positive)                  │
│   url_count ↔ severity: 0.41 (moderate positive)                │
│   has_exploit ↔ severity: 0.67 (strong positive)                │
│                                                                  │
│   5. Temporal Analysis                                           │
│   ─────────────────────                                          │
│                                                                  │
│   CVEs per year:                                                 │
│   2020: ████████████████ 18,362                                 │
│   2021: ████████████████████ 20,171                             │
│   2022: ██████████████████████████ 25,084                       │
│   2023: ████████████████████████████████ 28,902                 │
│                                                                  │
│   → Consider temporal train/test split                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 4: Feature Engineering

```
┌─────────────────────────────────────────────────────────────────┐
│                   FEATURE ENGINEERING                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A. TEXT FEATURES (for NLP model)                              │
│   ─────────────────────────────────                              │
│   • Cleaned description text → BERT tokenization                 │
│   • Input IDs + Attention Mask                                   │
│                                                                  │
│   B. NUMERICAL FEATURES                                          │
│   ─────────────────────────                                      │
│   • desc_length: Length of description                           │
│   • word_count: Number of words                                  │
│   • url_count: Number of references                              │
│   • cve_ref_count: Related CVE count                            │
│   • days_since_published: Age of vulnerability                   │
│   • vendor_vuln_count: Historical vulns for vendor              │
│                                                                  │
│   C. CATEGORICAL FEATURES (One-Hot Encoded)                      │
│   ──────────────────────────────────────────                     │
│   • attack_vector: [NETWORK, ADJACENT, LOCAL, PHYSICAL]         │
│   • attack_complexity: [LOW, HIGH]                               │
│   • privileges_required: [NONE, LOW, HIGH]                       │
│   • user_interaction: [NONE, REQUIRED]                           │
│   • scope: [UNCHANGED, CHANGED]                                  │
│                                                                  │
│   D. DERIVED FEATURES                                            │
│   ────────────────────                                           │
│   • is_remote: 1 if attack_vector == NETWORK                    │
│   • is_easy: 1 if complexity == LOW && privs == NONE            │
│   • has_exploit: 1 if exploit_db reference exists               │
│   • has_patch: 1 if patch URL in references                     │
│                                                                  │
│   E. KEYWORD FEATURES                                            │
│   ─────────────────────                                          │
│   • has_rce: "remote code execution" in text                    │
│   • has_sqli: "sql injection" in text                           │
│   • has_xss: "cross-site scripting" in text                     │
│   • has_overflow: "buffer overflow" in text                      │
│   • has_dos: "denial of service" in text                        │
│   • has_auth_bypass: "authentication bypass" in text            │
│                                                                  │
│   F. GRAPH FEATURES (for GNN)                                    │
│   ───────────────────────────                                    │
│   • node_degree: Connections in attack graph                     │
│   • betweenness_centrality: Bridge node importance              │
│   • pagerank: Influence score                                    │
│   • cluster_coefficient: Local connectivity                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 5: Data Splitting

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA SPLITTING                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   WRONG: Random Split                                            │
│   ───────────────────                                            │
│   train, val = random_split(data, [0.8, 0.2])                   │
│                                                                  │
│   Problems:                                                      │
│   • Ignores class distribution                                   │
│   • No test set                                                  │
│   • No reproducibility                                           │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   CORRECT: Stratified Split with Test Set                        │
│   ────────────────────────────────────────                       │
│                                                                  │
│   Full Dataset (10,000 samples)                                  │
│   ┌────────────────────────────────────────────────────────┐    │
│   │ CRITICAL: 800 │ HIGH: 2000 │ MEDIUM: 4700 │ LOW: 2500 │    │
│   └────────────────────────────────────────────────────────┘    │
│                          │                                       │
│                          ▼                                       │
│              Stratified Split (preserve ratios)                  │
│                          │                                       │
│          ┌───────────────┼───────────────┐                      │
│          ▼               ▼               ▼                      │
│   ┌────────────┐  ┌────────────┐  ┌────────────┐               │
│   │   TRAIN    │  │    VAL     │  │    TEST    │               │
│   │    70%     │  │    15%     │  │    15%     │               │
│   │   7,000    │  │   1,500    │  │   1,500    │               │
│   ├────────────┤  ├────────────┤  ├────────────┤               │
│   │ CRIT: 560  │  │ CRIT: 120  │  │ CRIT: 120  │               │
│   │ HIGH: 1400 │  │ HIGH: 300  │  │ HIGH: 300  │               │
│   │ MED: 3290  │  │ MED: 705   │  │ MED: 705   │               │
│   │ LOW: 1750  │  │ LOW: 375   │  │ LOW: 375   │               │
│   └────────────┘  └────────────┘  └────────────┘               │
│                                                                  │
│   Code:                                                          │
│   ```python                                                      │
│   from sklearn.model_selection import train_test_split          │
│                                                                  │
│   # First split: separate test set                               │
│   train_val, test = train_test_split(                           │
│       data, test_size=0.15,                                      │
│       stratify=labels,  # ← CRUCIAL                              │
│       random_state=42   # ← Reproducibility                      │
│   )                                                              │
│                                                                  │
│   # Second split: train and validation                           │
│   train, val = train_test_split(                                │
│       train_val, test_size=0.176,  # 0.15/0.85 ≈ 0.176          │
│       stratify=train_val_labels,                                 │
│       random_state=42                                            │
│   )                                                              │
│   ```                                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 6: Handling Class Imbalance

```
┌─────────────────────────────────────────────────────────────────┐
│                 HANDLING CLASS IMBALANCE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Method 1: Class Weights in Loss Function                       │
│   ─────────────────────────────────────────                      │
│                                                                  │
│   Intuition: Penalize mistakes on minority classes more          │
│                                                                  │
│   ```python                                                      │
│   from sklearn.utils.class_weight import compute_class_weight   │
│                                                                  │
│   class_weights = compute_class_weight(                         │
│       'balanced',                                                │
│       classes=np.unique(labels),                                │
│       y=labels                                                   │
│   )                                                              │
│   # Result: [2.5, 1.0, 0.4, 0.8] for [CRIT, HIGH, MED, LOW]    │
│                                                                  │
│   criterion = nn.CrossEntropyLoss(                              │
│       weight=torch.tensor(class_weights)                        │
│   )                                                              │
│   ```                                                            │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Method 2: Oversampling (SMOTE)                                 │
│   ──────────────────────────────                                 │
│                                                                  │
│   Before:          After SMOTE:                                  │
│   CRITICAL: 100    CRITICAL: 500 (synthetic samples)            │
│   HIGH: 300        HIGH: 500                                     │
│   MEDIUM: 500      MEDIUM: 500                                   │
│   LOW: 400         LOW: 500                                      │
│                                                                  │
│   ```python                                                      │
│   from imblearn.over_sampling import SMOTE                      │
│                                                                  │
│   smote = SMOTE(random_state=42)                                │
│   X_resampled, y_resampled = smote.fit_resample(X, y)          │
│   ```                                                            │
│                                                                  │
│   ⚠️ Only apply to TRAINING data, never validation/test!        │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Method 3: Focal Loss                                           │
│   ────────────────────                                           │
│                                                                  │
│   Focuses on hard-to-classify examples                          │
│                                                                  │
│   ```python                                                      │
│   class FocalLoss(nn.Module):                                   │
│       def __init__(self, alpha=1, gamma=2):                     │
│           super().__init__()                                     │
│           self.alpha = alpha                                     │
│           self.gamma = gamma                                     │
│                                                                  │
│       def forward(self, inputs, targets):                       │
│           ce_loss = F.cross_entropy(inputs, targets, reduce=False)│
│           pt = torch.exp(-ce_loss)                              │
│           focal_loss = self.alpha * (1-pt)**self.gamma * ce_loss│
│           return focal_loss.mean()                              │
│   ```                                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 7: Model Training

```
┌─────────────────────────────────────────────────────────────────┐
│                     MODEL TRAINING                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Training Loop Components:                                      │
│                                                                  │
│   1. Forward Pass                                                │
│      inputs → model → predictions                                │
│                                                                  │
│   2. Loss Calculation                                            │
│      loss = criterion(predictions, ground_truth)                │
│                                                                  │
│   3. Backward Pass                                               │
│      loss.backward() → compute gradients                        │
│                                                                  │
│   4. Optimizer Step                                              │
│      optimizer.step() → update weights                          │
│                                                                  │
│   5. Learning Rate Scheduling                                    │
│      scheduler.step() → adjust learning rate                    │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Key Techniques:                                                │
│                                                                  │
│   A. Gradient Clipping (prevent exploding gradients)            │
│   ```python                                                      │
│   torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)│
│   ```                                                            │
│                                                                  │
│   B. Learning Rate Warmup                                        │
│   ```python                                                      │
│   scheduler = get_linear_schedule_with_warmup(                  │
│       optimizer,                                                 │
│       num_warmup_steps=100,                                      │
│       num_training_steps=total_steps                            │
│   )                                                              │
│   ```                                                            │
│                                                                  │
│   C. Early Stopping                                              │
│   ```python                                                      │
│   if val_loss < best_val_loss:                                  │
│       best_val_loss = val_loss                                  │
│       patience_counter = 0                                       │
│       save_checkpoint(model)                                     │
│   else:                                                          │
│       patience_counter += 1                                      │
│       if patience_counter >= patience:                          │
│           print("Early stopping!")                               │
│           break                                                  │
│   ```                                                            │
│                                                                  │
│   D. Mixed Precision Training (faster on GPU)                   │
│   ```python                                                      │
│   from torch.cuda.amp import autocast, GradScaler              │
│                                                                  │
│   scaler = GradScaler()                                         │
│   with autocast():                                               │
│       outputs = model(inputs)                                    │
│       loss = criterion(outputs, labels)                         │
│   scaler.scale(loss).backward()                                 │
│   scaler.step(optimizer)                                        │
│   scaler.update()                                                │
│   ```                                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 8: Evaluation Metrics

```
┌─────────────────────────────────────────────────────────────────┐
│                   EVALUATION METRICS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   DON'T just use Accuracy!                                       │
│   ─────────────────────────                                      │
│                                                                  │
│   Problem: 90% of data is "MEDIUM" severity                     │
│   Model predicts "MEDIUM" for everything → 90% accuracy         │
│   But it's USELESS for finding critical vulnerabilities!        │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   USE THESE METRICS:                                             │
│                                                                  │
│   1. Precision (per class)                                       │
│      "Of all predicted CRITICAL, how many were actually CRITICAL?"│
│      Precision = TP / (TP + FP)                                 │
│                                                                  │
│   2. Recall (per class)                                          │
│      "Of all actual CRITICAL, how many did we find?"            │
│      Recall = TP / (TP + FN)                                    │
│                                                                  │
│   3. F1 Score (harmonic mean)                                   │
│      F1 = 2 * (Precision * Recall) / (Precision + Recall)       │
│                                                                  │
│   4. Macro F1 (average across classes)                          │
│      Treats all classes equally - good for imbalanced data      │
│                                                                  │
│   5. Weighted F1 (weighted by class support)                    │
│      Accounts for class frequency                                │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Confusion Matrix (ESSENTIAL for understanding errors):         │
│                                                                  │
│                    Predicted                                     │
│                CRIT  HIGH  MED   LOW                            │
│           ┌─────────────────────────┐                           │
│      CRIT │  85    10    4     1   │ ← 85% recall for CRITICAL │
│   A  HIGH │   5   180   12    3   │                            │
│   c  MED  │   2    15  420   63   │                            │
│   t  LOW  │   0     5   30  215  │                            │
│           └─────────────────────────┘                           │
│                                                                  │
│   What this tells us:                                            │
│   • CRITICAL vulns sometimes misclassified as HIGH (10 cases)   │
│   • Model confuses MEDIUM ↔ LOW (63 + 30 = 93 errors)          │
│   • Almost never misses CRITICAL as LOW (only 1 case)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 9: Cross-Validation

```
┌─────────────────────────────────────────────────────────────────┐
│                    CROSS-VALIDATION                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Why? Single train/val split can be lucky or unlucky           │
│                                                                  │
│   K-Fold Cross-Validation (K=5):                                │
│                                                                  │
│   Fold 1: [VAL] [TRAIN] [TRAIN] [TRAIN] [TRAIN]                │
│   Fold 2: [TRAIN] [VAL] [TRAIN] [TRAIN] [TRAIN]                │
│   Fold 3: [TRAIN] [TRAIN] [VAL] [TRAIN] [TRAIN]                │
│   Fold 4: [TRAIN] [TRAIN] [TRAIN] [VAL] [TRAIN]                │
│   Fold 5: [TRAIN] [TRAIN] [TRAIN] [TRAIN] [VAL]                │
│                                                                  │
│   Results:                                                       │
│   Fold 1: F1 = 0.82                                             │
│   Fold 2: F1 = 0.79                                             │
│   Fold 3: F1 = 0.84                                             │
│   Fold 4: F1 = 0.81                                             │
│   Fold 5: F1 = 0.80                                             │
│   ─────────────────                                              │
│   Mean:   F1 = 0.812 ± 0.018                                    │
│                                                                  │
│   This gives you CONFIDENCE in your model's performance!        │
│                                                                  │
│   ```python                                                      │
│   from sklearn.model_selection import StratifiedKFold           │
│                                                                  │
│   skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)│
│   scores = []                                                    │
│                                                                  │
│   for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)): │
│       model = create_model()                                     │
│       train_model(model, X[train_idx], y[train_idx])            │
│       score = evaluate(model, X[val_idx], y[val_idx])           │
│       scores.append(score)                                       │
│                                                                  │
│   print(f"Mean F1: {np.mean(scores):.3f} ± {np.std(scores):.3f}")│
│   ```                                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Stage 10: Hyperparameter Tuning

```
┌─────────────────────────────────────────────────────────────────┐
│                 HYPERPARAMETER TUNING                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Key Hyperparameters:                                           │
│   ─────────────────────                                          │
│   • learning_rate: [1e-5, 2e-5, 3e-5, 5e-5]                    │
│   • batch_size: [8, 16, 32]                                     │
│   • dropout_rate: [0.1, 0.2, 0.3]                               │
│   • warmup_steps: [0, 100, 500]                                 │
│   • weight_decay: [0.0, 0.01, 0.1]                              │
│   • max_seq_length: [128, 256, 512]                             │
│                                                                  │
│   Method 1: Grid Search (exhaustive but slow)                   │
│   ────────────────────────────────────────────                   │
│   Try ALL combinations                                           │
│   4 × 3 × 3 × 3 × 3 × 3 = 972 experiments!                      │
│                                                                  │
│   Method 2: Random Search (faster, often as good)               │
│   ───────────────────────────────────────────────                │
│   Try N random combinations                                      │
│   Usually 50-100 experiments sufficient                          │
│                                                                  │
│   Method 3: Bayesian Optimization (smart search)                │
│   ──────────────────────────────────────────────                 │
│   Uses past results to guide future experiments                  │
│   Tools: Optuna, Ray Tune                                        │
│                                                                  │
│   ```python                                                      │
│   import optuna                                                  │
│                                                                  │
│   def objective(trial):                                          │
│       lr = trial.suggest_loguniform('lr', 1e-5, 1e-3)          │
│       dropout = trial.suggest_uniform('dropout', 0.1, 0.5)      │
│       batch_size = trial.suggest_categorical('batch', [8,16,32])│
│                                                                  │
│       model = create_model(dropout=dropout)                     │
│       train_model(model, lr=lr, batch_size=batch_size)         │
│       return evaluate_f1(model)                                  │
│                                                                  │
│   study = optuna.create_study(direction='maximize')             │
│   study.optimize(objective, n_trials=100)                       │
│   ```                                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 3: Overfitting vs Underfitting

```
┌─────────────────────────────────────────────────────────────────┐
│              OVERFITTING vs UNDERFITTING                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   UNDERFITTING                    GOOD FIT                       │
│   ─────────────                   ────────                       │
│   Train Loss: High               Train Loss: Low                 │
│   Val Loss: High                 Val Loss: Low                   │
│   Gap: Small                     Gap: Small                      │
│                                                                  │
│   Model too simple               Model learned well              │
│   Not enough capacity                                            │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   OVERFITTING                                                    │
│   ───────────                                                    │
│   Train Loss: Very Low                                           │
│   Val Loss: High (and increasing)                               │
│   Gap: Large                                                     │
│                                                                  │
│   Model memorized training data                                  │
│   Won't generalize to new data                                   │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Visual:                                                        │
│                                                                  │
│   Loss                                                           │
│    │                                                             │
│    │   ╭─────────────────── Validation (overfitting)            │
│    │  ╱                                                          │
│    │ ╱  ────────────────── Validation (good)                    │
│    │╱                                                            │
│    │ ─────────────────────── Training                           │
│    └───────────────────────────────────────▶ Epochs             │
│              ↑                                                   │
│         Stop here!                                               │
│       (early stopping)                                           │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   How to PREVENT Overfitting:                                    │
│                                                                  │
│   1. More data (always helps)                                    │
│   2. Data augmentation (create variations)                       │
│   3. Dropout (randomly disable neurons)                          │
│   4. Weight decay / L2 regularization                           │
│   5. Early stopping (stop when val loss increases)              │
│   6. Reduce model complexity                                     │
│   7. Cross-validation                                            │
│                                                                  │
│   How to FIX Underfitting:                                       │
│                                                                  │
│   1. More complex model                                          │
│   2. More features                                               │
│   3. Less regularization                                         │
│   4. Train longer                                                │
│   5. Higher learning rate (initially)                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 4: Your 98% Accuracy Explained

```
┌─────────────────────────────────────────────────────────────────┐
│           WHY YOUR MODEL SHOWED 98% ACCURACY                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   The Chain of Events:                                           │
│                                                                  │
│   1. DataPreprocessor loads DistilBERT model                    │
│                                                                  │
│   2. For each CVE description, model predicts severity          │
│      (even though model is untrained, it outputs SOMETHING)     │
│                                                                  │
│   3. These predictions become your "labels"                     │
│                                                                  │
│   4. Training script uses these labels as ground truth          │
│                                                                  │
│   5. Model learns to replicate its own output patterns          │
│                                                                  │
│   6. By Epoch 2, it's memorized the pattern → 98% accuracy     │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Why it LOOKED real:                                            │
│   • Loss decreased (model was learning SOMETHING)               │
│   • Accuracy increased (matching its own predictions)           │
│   • Validation also improved (same leaked labels)               │
│                                                                  │
│   Why it's FAKE:                                                 │
│   • Ground truth was never real CVE severity                    │
│   • Model learned arbitrary patterns, not security knowledge    │
│   • On real test data with CVSS labels, it would fail          │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   The Smoking Gun in your logs:                                  │
│                                                                  │
│   INFO:data_preprocessor:Found trained severity classifier model.│
│   INFO:data_preprocessor:Predicting severity from text descriptions...│
│                      ↑                                           │
│           This should NEVER happen during training!              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Summary: The Complete ML Pipeline Checklist

```
□ Data Collection
  □ Use authoritative sources (NVD, MITRE)
  □ Extract ground truth labels (CVSS scores)
  □ Document data version and collection date

□ Data Cleaning
  □ Handle missing values
  □ Remove duplicates
  □ Clean text (HTML, URLs, normalization)
  □ Validate data integrity

□ Exploratory Data Analysis
  □ Check class distribution
  □ Analyze feature distributions
  □ Identify correlations
  □ Detect outliers

□ Feature Engineering
  □ Create meaningful features
  □ Handle categorical variables
  □ Scale numerical features
  □ Document feature meanings

□ Data Splitting
  □ Use stratified split
  □ Create train/val/test sets
  □ Never touch test set during development
  □ Set random seed for reproducibility

□ Handle Class Imbalance
  □ Calculate class weights
  □ Consider oversampling (train only)
  □ Use appropriate loss function

□ Model Training
  □ Use gradient clipping
  □ Implement learning rate scheduling
  □ Add early stopping
  □ Save best checkpoint

□ Evaluation
  □ Use multiple metrics (F1, precision, recall)
  □ Generate confusion matrix
  □ Perform cross-validation
  □ Compare to baseline

□ Hyperparameter Tuning
  □ Define search space
  □ Use systematic search method
  □ Track all experiments
  □ Select based on validation performance

□ Final Evaluation
  □ Evaluate on held-out test set
  □ Report confidence intervals
  □ Document limitations
  □ Compare to prior work
```

---

*This guide was created to help you understand proper ML methodology. Now let's implement it correctly in CTPPO v2.0!*

# CTPPO: Complete Analysis of Mistakes and How to Fix Them

## Executive Summary

Your model showed **98.3% accuracy** which seems amazing but is **completely meaningless** due to fundamental ML pipeline violations. Here's why and how to fix it.

---

## 🚨 MISTAKE #1: DATA LEAKAGE (CRITICAL)

### Where It Happens

```python
# data_preprocessor.py - Lines 248-252

if self.severity_model and self.tokenizer:
    predicted_severities = self.predict_severity(df['cleaned_description'].tolist())
    df['severity_class'] = predicted_severities  # ← FATAL ERROR!
    df['severity_source'] = 'model'
```

### What This Does (WRONG)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         YOUR BROKEN PIPELINE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Step 1: Load DistilBERT Model (untrained/random weights)                  │
│                    │                                                         │
│                    ▼                                                         │
│   Step 2: Feed CVE descriptions to model                                    │
│           "buffer overflow in apache..." → Model predicts "HIGH"            │
│           "sql injection allows..." → Model predicts "CRITICAL"             │
│                    │                                                         │
│                    ▼                                                         │
│   Step 3: Use these PREDICTIONS as "ground truth" labels                    │
│           severity_class = ["HIGH", "CRITICAL", ...]  ← FAKE LABELS!        │
│                    │                                                         │
│                    ▼                                                         │
│   Step 4: Train model on its OWN predictions                                │
│           Model learns: "When I see 'buffer overflow', output 'HIGH'"       │
│           (because that's what it predicted in step 2!)                     │
│                    │                                                         │
│                    ▼                                                         │
│   Step 5: Evaluate model                                                    │
│           Model perfectly matches its own predictions → 98% accuracy!       │
│                                                                              │
│   ⚠️  THE MODEL LEARNED NOTHING ABOUT REAL SEVERITY!                        │
│   ⚠️  IT JUST MEMORIZED ITS OWN RANDOM PATTERNS!                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Correct Approach

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CORRECT PIPELINE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Step 1: Fetch CVE data from NVD API                                       │
│           API returns: description + CVSS score (0-10)                      │
│                    │                                                         │
│                    ▼                                                         │
│   Step 2: Convert CVSS to severity (GROUND TRUTH)                           │
│           CVSS 9.0-10.0 → CRITICAL  (Official NVD thresholds)              │
│           CVSS 7.0-8.9  → HIGH                                              │
│           CVSS 4.0-6.9  → MEDIUM                                            │
│           CVSS 0.1-3.9  → LOW                                               │
│                    │                                                         │
│                    ▼                                                         │
│   Step 3: Train model on (description → REAL severity)                      │
│           Model learns: "buffer overflow" patterns correlate with           │
│           ACTUAL high CVSS scores from security experts                     │
│                    │                                                         │
│                    ▼                                                         │
│   Step 4: Evaluate on held-out test set                                     │
│           Real accuracy based on real labels                                │
│                                                                              │
│   ✓ THE MODEL LEARNS REAL SECURITY KNOWLEDGE!                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Fix

```python
# CORRECT: Always use CVSS score as ground truth
def get_severity_label(cvss_score):
    """
    Convert CVSS score to severity label.
    This is the GROUND TRUTH - from security experts, not model predictions!
    """
    if cvss_score is None:
        return 'UNKNOWN'
    if cvss_score >= 9.0:
        return 'CRITICAL'
    if cvss_score >= 7.0:
        return 'HIGH'
    if cvss_score >= 4.0:
        return 'MEDIUM'
    return 'LOW'

# NEVER do this:
# severity = model.predict(description)  # ← WRONG during data preparation
```

---

## 🚨 MISTAKE #2: NO PROPER DATA SPLITTING

### Where It Happens

```python
# train_severity_classifier.py - Lines 64-66

train_size = int(0.8 * len(dataset))
val_size = len(dataset) - train_size
train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
```

### What's Wrong

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         YOUR BROKEN SPLITTING                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Problem 1: NO TEST SET                                                     │
│   ─────────────────────                                                      │
│   You only have Train (80%) and Val (20%)                                   │
│   No held-out test set = No way to measure real-world performance           │
│                                                                              │
│   Problem 2: RANDOM SPLIT (not stratified)                                  │
│   ─────────────────────────────────────────                                  │
│   Your data is IMBALANCED:                                                   │
│   CRITICAL: 5%   █                                                           │
│   HIGH:     20%  ████                                                        │
│   MEDIUM:   50%  ██████████                                                  │
│   LOW:      25%  █████                                                       │
│                                                                              │
│   Random split might give you:                                               │
│   Train: CRITICAL=3%, HIGH=22%, MEDIUM=48%, LOW=27%                         │
│   Val:   CRITICAL=12%, HIGH=15%, MEDIUM=55%, LOW=18%                        │
│                                                                              │
│   → Different distributions = misleading evaluation!                        │
│                                                                              │
│   Problem 3: NO REPRODUCIBILITY                                             │
│   ─────────────────────────────                                              │
│   No random_state set = Different split every run                           │
│   Can't reproduce results or compare experiments                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Correct Approach

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CORRECT: STRATIFIED SPLITTING                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Original Data (1000 samples):                                              │
│   CRITICAL: 50 (5%)  │ HIGH: 200 (20%) │ MEDIUM: 500 (50%) │ LOW: 250 (25%)│
│                                                                              │
│                         STRATIFIED SPLIT                                     │
│                              │                                               │
│          ┌───────────────────┼───────────────────┐                          │
│          │                   │                   │                          │
│          ▼                   ▼                   ▼                          │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    │
│   │   TRAIN     │    │     VAL     │    │    TEST     │                    │
│   │    70%      │    │     15%     │    │     15%     │                    │
│   │ 700 samples │    │ 150 samples │    │ 150 samples │                    │
│   ├─────────────┤    ├─────────────┤    ├─────────────┤                    │
│   │ CRIT: 35(5%)│    │ CRIT: 7(5%) │    │ CRIT: 8(5%) │                    │
│   │ HIGH: 140   │    │ HIGH: 30    │    │ HIGH: 30    │                    │
│   │ MED:  350   │    │ MED:  75    │    │ MED:  75    │                    │
│   │ LOW:  175   │    │ LOW:  38    │    │ LOW:  37    │                    │
│   └─────────────┘    └─────────────┘    └─────────────┘                    │
│                                                                              │
│   ✓ Same class proportions in ALL splits!                                   │
│   ✓ Test set never seen during training!                                    │
│   ✓ Reproducible with random_state=42                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Fix

```python
from sklearn.model_selection import train_test_split

# CORRECT: Stratified split with test set
# Step 1: Separate test set (15%)
train_val_data, test_data, train_val_labels, test_labels = train_test_split(
    data, labels,
    test_size=0.15,
    stratify=labels,      # ← CRUCIAL: Preserve class distribution
    random_state=42       # ← CRUCIAL: Reproducibility
)

# Step 2: Split remaining into train (70%) and val (15%)
train_data, val_data, train_labels, val_labels = train_test_split(
    train_val_data, train_val_labels,
    test_size=0.176,      # 0.15 / 0.85 ≈ 0.176
    stratify=train_val_labels,
    random_state=42
)
```

---

## 🚨 MISTAKE #3: IGNORING CLASS IMBALANCE

### The Problem

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CLASS IMBALANCE IN CVE DATA                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Real CVE Severity Distribution:                                            │
│                                                                              │
│   CRITICAL ████                                              5%             │
│   HIGH     ████████████████                                  20%            │
│   MEDIUM   ████████████████████████████████████████████████  50%            │
│   LOW      ████████████████████████                          25%            │
│                                                                              │
│   What happens WITHOUT handling imbalance:                                   │
│   ─────────────────────────────────────────                                  │
│   Model learns: "Just predict MEDIUM for everything!"                       │
│   Result: 50% accuracy (useless but looks okay)                             │
│                                                                              │
│   CRITICAL vulnerabilities get MISSED                                       │
│   → In cybersecurity, this is DANGEROUS!                                    │
│                                                                              │
│   Your code has NO class balancing:                                          │
│   ```python                                                                  │
│   criterion = torch.nn.CrossEntropyLoss()  # No weights!                    │
│   ```                                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Fix

```python
from sklearn.utils.class_weight import compute_class_weight

# Calculate class weights
class_weights = compute_class_weight(
    'balanced',
    classes=np.unique(labels),
    y=labels
)
# Result: [2.0, 1.0, 0.4, 0.8] - Higher weight for rare classes

# Use weighted loss
criterion = nn.CrossEntropyLoss(
    weight=torch.tensor(class_weights, dtype=torch.float32)
)

# Now model is penalized MORE for missing CRITICAL vulnerabilities
```

---

## 🚨 MISTAKE #4: INCOMPLETE DATA CLEANING

### Your Current Cleaning (Minimal)

```python
# data_preprocessor.py - Lines 183-197

def clean_text(self, text: str) -> str:
    text = text.lower()                                    # ✓ Good
    text = re.sub(r'https?://\S+|www\.\S+', '', text)     # ✓ Good
    text = re.sub(r'\S+@\S+', '', text)                   # ✓ Good
    text = re.sub(r'[^a-z0-9\s-]', '', text)              # ⚠️ Too aggressive
    text = re.sub(r'\s+', ' ', text).strip()              # ✓ Good
    
    tokens = word_tokenize(text)
    tokens = [self.lemmatizer.lemmatize(word) 
              for word in tokens if word not in self.stop_words]
    return ' '.join(tokens)
```

### What's Missing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE CLEANING PIPELINE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Raw CVE Description:                                                       │
│   "A vulnerability in &lt;script&gt; the OpenSSL library v1.1.1k           │
│    allows REMOTE attackers to execute arbitrary CODE via CVE-2021-3449.    │
│    See https://openssl.org/news/secadv/20210325.txt for patch info."        │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 1: HTML DECODING                                               │   │
│   │ ─────────────────────                                               │   │
│   │ &lt; → <  |  &gt; → >  |  &amp; → &                                 │   │
│   │ YOUR CODE: ❌ Missing!                                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 2: REMOVE HTML TAGS                                            │   │
│   │ ────────────────────────                                            │   │
│   │ <script>...</script> → ""                                           │   │
│   │ YOUR CODE: ❌ Missing!                                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 3: EXTRACT URLs (don't just remove - count them!)             │   │
│   │ ──────────────────────────────────────────────────────              │   │
│   │ https://... → [URL] + store for features                           │   │
│   │ More URLs often = more serious vulnerability                        │   │
│   │ YOUR CODE: ⚠️ Removes but doesn't extract for features             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 4: EXTRACT CVE REFERENCES                                      │   │
│   │ ──────────────────────────────                                      │   │
│   │ CVE-2021-3449 → extract for relationship mapping                   │   │
│   │ YOUR CODE: ❌ Missing!                                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 5: NORMALIZE VERSION NUMBERS                                   │   │
│   │ ─────────────────────────────────                                   │   │
│   │ v1.1.1k → [VERSION]                                                │   │
│   │ 1.2.3-beta → [VERSION]                                             │   │
│   │ YOUR CODE: ❌ Missing! (versions treated as noise)                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 6: LOWERCASE                                                   │   │
│   │ ─────────────────                                                   │   │
│   │ REMOTE → remote  |  CODE → code                                    │   │
│   │ YOUR CODE: ✓ Good                                                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 7: REMOVE SPECIAL CHARACTERS (carefully!)                     │   │
│   │ ──────────────────────────────────────────────                      │   │
│   │ Keep meaningful punctuation, remove noise                          │   │
│   │ YOUR CODE: ⚠️ Too aggressive - removes everything                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Step 8: TOKENIZE AND LEMMATIZE                                     │   │
│   │ ──────────────────────────────                                      │   │
│   │ "attackers" → "attacker"                                           │   │
│   │ "executing" → "execute"                                            │   │
│   │ YOUR CODE: ✓ Good                                                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                               │                                              │
│                               ▼                                              │
│   Clean Output + Extracted Metadata                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚨 MISTAKE #5: WEAK FEATURE ENGINEERING

### Your Current Features

```python
# data_preprocessor.py - Lines 239-246

df['desc_length'] = df['cleaned_description'].apply(len)           # Basic
df['num_words'] = df['cleaned_description'].apply(lambda x: len(x.split()))  # Basic

attack_keywords = ['overflow', 'injection', 'xss', 'rce', 'dos', 'privilege escalation']
for keyword in attack_keywords:
    df[f'has_{keyword}'] = df['cleaned_description'].apply(lambda x: 1 if keyword in x else 0)
```

### What's Missing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMPREHENSIVE FEATURE ENGINEERING                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   A. TEXT FEATURES (You have some) ✓                                        │
│   ──────────────────────────────────                                         │
│   • desc_length ✓                                                            │
│   • word_count ✓                                                             │
│   • keyword presence ✓                                                       │
│   • avg_word_length ❌                                                       │
│   • sentence_count ❌                                                        │
│                                                                              │
│   B. CVSS VECTOR COMPONENTS (You're ignoring these!) ❌                     │
│   ──────────────────────────────────────────────────────                     │
│   The CVSS vector contains RICH information:                                │
│                                                                              │
│   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H                            │
│              │   │   │   │   │   │   │   │                                  │
│              │   │   │   │   │   │   │   └── Availability Impact           │
│              │   │   │   │   │   │   └────── Integrity Impact              │
│              │   │   │   │   │   └────────── Confidentiality Impact        │
│              │   │   │   │   └────────────── Scope                         │
│              │   │   │   └────────────────── User Interaction              │
│              │   │   └────────────────────── Privileges Required           │
│              │   └────────────────────────── Attack Complexity             │
│              └────────────────────────────── Attack Vector                 │
│                                                                              │
│   Each component is a powerful feature!                                      │
│   • is_network_attack (AV=N)                                                │
│   • is_low_complexity (AC=L)                                                │
│   • requires_no_privileges (PR=N)                                           │
│   • requires_no_interaction (UI=N)                                          │
│   • scope_changed (S=C)                                                     │
│   • high_confidentiality_impact (C=H)                                       │
│   • etc.                                                                     │
│                                                                              │
│   C. TEMPORAL FEATURES ❌                                                    │
│   ──────────────────────                                                     │
│   • days_since_published                                                    │
│   • days_since_modified                                                     │
│   • was_recently_modified                                                   │
│   • publication_year                                                        │
│                                                                              │
│   D. REFERENCE FEATURES ❌                                                  │
│   ────────────────────────                                                   │
│   • reference_count (more refs = more attention = often more severe)       │
│   • has_exploit_reference                                                   │
│   • has_patch_reference                                                     │
│   • has_vendor_advisory                                                     │
│                                                                              │
│   E. CWE-BASED FEATURES ❌                                                  │
│   ────────────────────────                                                   │
│   • CWE category (injection, overflow, etc.)                               │
│   • cwe_count (multiple weaknesses = complex vuln)                         │
│                                                                              │
│   F. DERIVED RISK FEATURES ❌                                               │
│   ───────────────────────────                                                │
│   • ease_of_exploit = (AV_score × AC_score × PR_score × UI_score)          │
│   • total_impact = (C_impact + I_impact + A_impact) / 3                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚨 MISTAKE #6: NO PROPER EVALUATION METRICS

### Your Current Evaluation

```python
# Only tracking accuracy
accuracy = correct_predictions / total_predictions
```

### Why Accuracy Alone is Misleading

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    THE ACCURACY TRAP                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Scenario: 1000 CVEs                                                        │
│   - 50 CRITICAL                                                              │
│   - 200 HIGH                                                                 │
│   - 500 MEDIUM                                                               │
│   - 250 LOW                                                                  │
│                                                                              │
│   DUMB MODEL: Predicts "MEDIUM" for everything                              │
│   - Accuracy: 500/1000 = 50%                                                │
│   - "Looks okay!"                                                            │
│                                                                              │
│   BUT:                                                                       │
│   - CRITICAL recall: 0% (missed ALL critical vulnerabilities!)             │
│   - HIGH recall: 0%                                                          │
│   - This model is USELESS for security!                                     │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   METRICS YOU SHOULD USE:                                                    │
│                                                                              │
│   1. PRECISION (per class)                                                   │
│      "Of all predicted CRITICAL, how many were actually CRITICAL?"          │
│      Important for: Avoiding false alarms                                   │
│                                                                              │
│   2. RECALL (per class)                                                      │
│      "Of all actual CRITICAL, how many did we find?"                        │
│      Important for: Not missing real threats! (CRITICAL for security)       │
│                                                                              │
│   3. F1 SCORE (harmonic mean of precision & recall)                        │
│      Balances both concerns                                                  │
│                                                                              │
│   4. MACRO F1                                                                │
│      Average F1 across all classes (treats all equally)                    │
│      Good for imbalanced data                                               │
│                                                                              │
│   5. CONFUSION MATRIX                                                        │
│      Shows exactly where model makes mistakes                               │
│                                                                              │
│                    Predicted                                                 │
│                CRIT  HIGH  MED   LOW                                        │
│           ┌─────────────────────────┐                                       │
│      CRIT │  45    3     2     0   │  ← 90% recall for CRITICAL           │
│   A  HIGH │   5   180   12    3   │                                        │
│   c  MED  │   2    15  450   33   │                                        │
│   t  LOW  │   0     5   20  225  │                                        │
│           └─────────────────────────┘                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚨 MISTAKE #7: NO EXPERIMENT TRACKING

### Your Code

No MLflow, no logging of hyperparameters, no way to reproduce results.

### Why It Matters

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WITHOUT EXPERIMENT TRACKING                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Week 1: Train model with lr=2e-5, batch=16 → F1=0.75                     │
│   Week 2: Train model with lr=??? batch=??? → F1=0.82                      │
│   Week 3: "Wait, what settings gave me 0.82?"                              │
│                                                                              │
│   You can't:                                                                 │
│   • Reproduce your best results                                             │
│   • Compare experiments fairly                                              │
│   • Debug what went wrong                                                   │
│   • Share results with team                                                 │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   WITH EXPERIMENT TRACKING (MLflow):                                        │
│                                                                              │
│   Run ID: abc123                                                            │
│   ├── Parameters                                                            │
│   │   ├── learning_rate: 2e-5                                              │
│   │   ├── batch_size: 16                                                   │
│   │   ├── epochs: 5                                                        │
│   │   └── dropout: 0.3                                                     │
│   ├── Metrics                                                               │
│   │   ├── train_loss: [1.2, 0.8, 0.5, 0.3, 0.2]                           │
│   │   ├── val_f1: [0.5, 0.65, 0.72, 0.75, 0.75]                           │
│   │   └── test_f1: 0.74                                                    │
│   └── Artifacts                                                             │
│       ├── model.pt                                                          │
│       ├── confusion_matrix.png                                              │
│       └── classification_report.json                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 THE COMPLETE CORRECT ML PIPELINE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                    PROPER ML PIPELINE FOR CTPPO                             │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 1: DATA COLLECTION                                           │   │
│   │  ─────────────────────────                                          │   │
│   │  • Fetch from NVD API                                               │   │
│   │  • Extract CVSS score (GROUND TRUTH!)                               │   │
│   │  • Extract all metadata (dates, CWE, references)                    │   │
│   │  • Cache results for reproducibility                                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 2: EXPLORATORY DATA ANALYSIS (EDA)                          │   │
│   │  ─────────────────────────────────────────                          │   │
│   │  • Check class distribution (is it imbalanced?)                    │   │
│   │  • Analyze text lengths                                            │   │
│   │  • Find missing values                                             │   │
│   │  • Identify outliers                                               │   │
│   │  • Visualize patterns                                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 3: DATA CLEANING                                            │   │
│   │  ───────────────────────                                            │   │
│   │  • HTML decoding                                                   │   │
│   │  • Remove HTML tags                                                │   │
│   │  • Extract & normalize URLs                                        │   │
│   │  • Extract CVE/CWE references                                      │   │
│   │  • Normalize version numbers                                       │   │
│   │  • Lowercase                                                       │   │
│   │  • Remove noise (carefully!)                                       │   │
│   │  • Tokenize and lemmatize                                          │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 4: FEATURE ENGINEERING                                       │   │
│   │  ────────────────────────────                                       │   │
│   │  • Text features (length, word count)                              │   │
│   │  • CVSS vector components (AV, AC, PR, UI, S, C, I, A)            │   │
│   │  • Temporal features (age, recency)                                │   │
│   │  • Reference features (counts, types)                              │   │
│   │  • CWE-based features                                              │   │
│   │  • Derived risk scores                                             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 5: DATA SPLITTING                                           │   │
│   │  ────────────────────────                                           │   │
│   │  • STRATIFIED split (preserve class distribution)                  │   │
│   │  • Train (70%) / Val (15%) / Test (15%)                           │   │
│   │  • Set random_state for reproducibility                            │   │
│   │  • Verify distributions match                                       │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 6: CLASS BALANCING                                          │   │
│   │  ─────────────────────────                                          │   │
│   │  • Compute class weights                                           │   │
│   │  • Use weighted CrossEntropyLoss                                   │   │
│   │  • (Optional) Oversample minority classes                          │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 7: MODEL TRAINING                                           │   │
│   │  ────────────────────────                                           │   │
│   │  • Learning rate warmup                                            │   │
│   │  • Gradient clipping                                               │   │
│   │  • Early stopping (prevent overfitting)                            │   │
│   │  • Save best checkpoint                                            │   │
│   │  • Log all metrics                                                 │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 8: EVALUATION                                               │   │
│   │  ────────────────────                                               │   │
│   │  • Evaluate on HELD-OUT test set                                   │   │
│   │  • Report: Accuracy, Precision, Recall, F1 (per class)            │   │
│   │  • Generate confusion matrix                                       │   │
│   │  • Run cross-validation for confidence                             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  STAGE 9: EXPERIMENT TRACKING                                      │   │
│   │  ─────────────────────────────                                      │   │
│   │  • Log all hyperparameters                                         │   │
│   │  • Save model artifacts                                            │   │
│   │  • Version datasets                                                │   │
│   │  • Enable reproducibility                                          │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 SUMMARY: YOUR MISTAKES vs FIXES

| # | Mistake | Impact | Fix |
|---|---------|--------|-----|
| 1 | **Data Leakage** - Using model predictions as labels | 98% fake accuracy | Use CVSS score as ground truth |
| 2 | **No Test Set** - Only train/val split | Can't measure real performance | Add stratified test split |
| 3 | **Random Split** - Ignores class distribution | Misleading evaluation | Use stratified sampling |
| 4 | **No Class Balancing** - Imbalanced data | Model predicts majority class | Add class weights to loss |
| 5 | **Minimal Cleaning** - Missing steps | Noisy input data | Complete cleaning pipeline |
| 6 | **Weak Features** - Only text stats | Missing rich CVSS features | Engineer all feature types |
| 7 | **Only Accuracy** - Wrong metric | Hides poor performance | Use F1, precision, recall, confusion matrix |
| 8 | **No Experiment Tracking** - No logging | Can't reproduce results | Add MLflow/wandb |

---

## 🎯 KEY TAKEAWAYS

1. **GROUND TRUTH matters** - Labels must come from authoritative sources (CVSS scores), never from model predictions

2. **Data pipeline is 80% of ML success** - Garbage in = garbage out

3. **Stratification is essential** for imbalanced data (which is most real-world data)

4. **Evaluation must be comprehensive** - Accuracy alone is often misleading

5. **Reproducibility is crucial** - Always set random seeds and track experiments

---

*Now you understand exactly what went wrong and why. The fixed pipeline I've built addresses ALL of these issues!*

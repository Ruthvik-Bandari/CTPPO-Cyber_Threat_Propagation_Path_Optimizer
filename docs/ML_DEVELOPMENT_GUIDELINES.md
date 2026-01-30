# 🧠 Machine Learning Model Development Guidelines
## Comprehensive Best Practices for Production-Quality ML

**Author:** Ruthvik Bandari  
**Last Updated:** January 2026  
**Purpose:** Reference guide for building high-quality ML models

---

## 📋 Table of Contents

1. [Core Philosophy](#1-core-philosophy)
2. [Data Pipeline](#2-data-pipeline)
3. [Exploratory Data Analysis (EDA)](#3-exploratory-data-analysis-eda)
4. [Data Cleaning & Preprocessing](#4-data-cleaning--preprocessing)
5. [Feature Engineering](#5-feature-engineering)
6. [Model Architecture](#6-model-architecture)
7. [Training Best Practices](#7-training-best-practices)
8. [Evaluation & Metrics](#8-evaluation--metrics)
9. [Debugging & Troubleshooting](#9-debugging--troubleshooting)
10. [Production Deployment](#10-production-deployment)

---

## 1. Core Philosophy

### Golden Rules

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  RULE 1: Data Quality > Data Quantity                                       │
│  - 100K clean samples beats 1M dirty samples                                │
│  - Garbage in = Garbage out                                                 │
│                                                                             │
│  RULE 2: Understand Before You Model                                        │
│  - ALWAYS do EDA before training                                            │
│  - Know your data distribution, missing values, duplicates                  │
│                                                                             │
│  RULE 3: Simple First, Complex Later                                        │
│  - Start with baseline (logistic regression, simple NN)                     │
│  - Add complexity only if needed                                            │
│                                                                             │
│  RULE 4: Validate Everything                                                │
│  - Check data at each pipeline stage                                        │
│  - Verify no data leakage                                                   │
│  - Test on truly held-out data                                              │
│                                                                             │
│  RULE 5: Reproducibility is Non-Negotiable                                  │
│  - Set random seeds                                                         │
│  - Version your data and code                                               │
│  - Document everything                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Pipeline

### 2.1 Data Collection Checklist

```python
# Before collecting data, answer:
□ What is the data source? (API, database, scraping)
□ What is the data format? (JSON, CSV, Parquet)
□ How much data do I need? (Rule of thumb: 10x features minimum)
□ What is the update frequency? (Static vs streaming)
□ Are there rate limits? (API throttling)
□ What fields do I need? (Don't fetch unnecessary data)
```

### 2.2 Data Storage Strategy

```
project/
├── data/
│   ├── raw/              # Original untouched data
│   ├── processed/        # Cleaned data
│   ├── splits/           # Train/val/test splits
│   │   ├── train.jsonl
│   │   ├── val.jsonl
│   │   └── test.jsonl
│   └── metadata/         # Statistics, encodings
│       ├── eda_stats.json
│       └── feature_encodings.json
```

### 2.3 Data Versioning

```bash
# Always track data versions
data_v1/  # Original
data_v2/  # After removing duplicates
data_v3/  # After adding new features

# Use checksums
md5sum data/train.jsonl > data/train.md5
```

---

## 3. Exploratory Data Analysis (EDA)

### 3.1 Mandatory EDA Checks

```python
# ALWAYS check these before training:

# 1. Basic Statistics
print(f"Total records: {len(data):,}")
print(f"Features: {data.columns.tolist()}")

# 2. Duplicates
duplicates = len(data) - len(data.drop_duplicates())
print(f"Duplicates: {duplicates} ({100*duplicates/len(data):.1f}%)")

# 3. Missing Values
for col in data.columns:
    missing = data[col].isna().sum()
    print(f"{col}: {missing} missing ({100*missing/len(data):.1f}%)")

# 4. Target Distribution (Classification)
print(data['label'].value_counts(normalize=True))

# 5. Feature Distributions
for col in numerical_cols:
    print(f"{col}: mean={data[col].mean():.2f}, std={data[col].std():.2f}")

# 6. Correlations
print(data.corr()['target'].sort_values())

# 7. Outliers
for col in numerical_cols:
    q1, q99 = data[col].quantile([0.01, 0.99])
    outliers = ((data[col] < q1) | (data[col] > q99)).sum()
    print(f"{col}: {outliers} outliers")
```

### 3.2 EDA Red Flags

| Red Flag | Problem | Solution |
|----------|---------|----------|
| >5% duplicates | Data leakage risk | Remove duplicates |
| >20% missing | Poor feature | Impute or drop |
| >90% single value | No signal | Drop feature |
| Label imbalance >10:1 | Poor minority class | Resampling/weighting |
| High correlation >0.95 | Redundant features | Remove one |

---

## 4. Data Cleaning & Preprocessing

### 4.1 Cleaning Pipeline Order

```python
# CORRECT ORDER:
1. Remove exact duplicates
2. Handle missing values
3. Remove/fix invalid values
4. Normalize/standardize
5. Encode categoricals
6. Split data (BEFORE any fitting!)
7. Fit transformers on TRAIN ONLY
8. Apply to val/test
```

### 4.2 Handling Missing Values

```python
# Strategy by data type:

# Numerical - Options:
df['col'].fillna(df['col'].median())  # Robust to outliers
df['col'].fillna(df['col'].mean())    # If normal distribution
df['col'].fillna(-1)                   # Flag as missing (if model can learn)

# Categorical - Options:
df['col'].fillna('UNKNOWN')           # Explicit category
df['col'].fillna(df['col'].mode()[0]) # Most frequent

# Critical fields (labels, IDs):
df = df.dropna(subset=['label'])      # Remove if missing
```

### 4.3 Train/Val/Test Split Rules

```python
# CRITICAL: Split BEFORE any preprocessing that learns from data!

from sklearn.model_selection import train_test_split

# Stratified split (maintains label distribution)
train, temp = train_test_split(data, test_size=0.2, stratify=data['label'], random_state=42)
val, test = train_test_split(temp, test_size=0.5, stratify=temp['label'], random_state=42)

# Result: 80% train, 10% val, 10% test

# VERIFY stratification:
for name, split in [('Train', train), ('Val', val), ('Test', test)]:
    print(f"{name}: {split['label'].value_counts(normalize=True)}")
```

### 4.4 Data Leakage Prevention

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  COMMON DATA LEAKAGE MISTAKES:                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ❌ Fitting scaler on ALL data, then splitting                              │
│  ✅ Split first, fit scaler on TRAIN only                                   │
│                                                                             │
│  ❌ Removing duplicates AFTER splitting (same record in train & test)       │
│  ✅ Remove duplicates BEFORE splitting                                      │
│                                                                             │
│  ❌ Using future data to predict past                                       │
│  ✅ Time-based splits for temporal data                                     │
│                                                                             │
│  ❌ Feature derived from target                                             │
│  ✅ Only use features available at prediction time                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Feature Engineering

### 5.1 Feature Types and Encoding

```python
# Categorical (nominal) - no order
# Use: One-hot or Embedding
# Example: color = [red, blue, green]
encoded = pd.get_dummies(df['color'])  # One-hot
# OR use nn.Embedding for high cardinality

# Categorical (ordinal) - has order
# Use: Integer encoding
# Example: size = [small, medium, large]
mapping = {'small': 0, 'medium': 1, 'large': 2}
df['size_encoded'] = df['size'].map(mapping)

# Numerical (continuous)
# Use: Normalization/Standardization
df['col_normalized'] = (df['col'] - df['col'].min()) / (df['col'].max() - df['col'].min())
df['col_standardized'] = (df['col'] - df['col'].mean()) / df['col'].std()

# Text
# Use: Tokenization + Embeddings (BERT, etc.)
```

### 5.2 Feature Engineering Strategies

```python
# 1. Binning continuous features
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 65, 100], labels=['child', 'young', 'middle', 'senior', 'elderly'])

# 2. Interaction features
df['feature_interaction'] = df['feature_a'] * df['feature_b']

# 3. Aggregations
df['user_avg_purchase'] = df.groupby('user_id')['purchase'].transform('mean')

# 4. Time-based features
df['day_of_week'] = df['date'].dt.dayofweek
df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)

# 5. Text features
df['text_length'] = df['text'].str.len()
df['word_count'] = df['text'].str.split().str.len()
```

---

## 6. Model Architecture

### 6.1 Architecture Selection Guide

| Problem | Data Size | First Try | If Underperforms |
|---------|-----------|-----------|------------------|
| Tabular Classification | <10K | Logistic Regression | XGBoost |
| Tabular Classification | 10K-100K | XGBoost/RandomForest | Neural Network |
| Tabular Classification | >100K | Neural Network | Ensemble |
| Text Classification | Any | BERT/DistilBERT | Fine-tune more |
| Multi-modal | Any | Fusion Network | Attention mechanisms |

### 6.2 Neural Network Building Blocks

```python
# Standard classification head
classifier = nn.Sequential(
    nn.Linear(input_dim, hidden_dim),
    nn.LayerNorm(hidden_dim),      # Stabilizes training
    nn.ReLU(),                      # Activation
    nn.Dropout(0.3),                # Regularization
    nn.Linear(hidden_dim, num_classes)
)

# Multi-modal fusion
class MultiModalModel(nn.Module):
    def __init__(self):
        # Separate encoders for each modality
        self.text_encoder = BertModel(...)
        self.tabular_encoder = nn.Linear(...)
        
        # Fusion layer
        self.fusion = nn.Linear(text_dim + tabular_dim, fusion_dim)
        
        # Classifier
        self.classifier = nn.Linear(fusion_dim, num_classes)
    
    def forward(self, text, tabular):
        text_features = self.text_encoder(text)
        tabular_features = self.tabular_encoder(tabular)
        
        # Concatenate and fuse
        combined = torch.cat([text_features, tabular_features], dim=1)
        fused = self.fusion(combined)
        
        return self.classifier(fused)
```

---

## 7. Training Best Practices

### 7.1 Loss Functions

```python
# Classification - Balanced classes
loss_fn = nn.CrossEntropyLoss()

# Classification - Imbalanced classes
# Option 1: Class weights
weights = torch.tensor([1.0, 2.0, 1.0, 5.0])  # Higher weight for rare classes
loss_fn = nn.CrossEntropyLoss(weight=weights)

# Option 2: Focal Loss (focuses on hard examples)
class FocalLoss(nn.Module):
    def __init__(self, gamma=2.0, weight=None):
        super().__init__()
        self.gamma = gamma
        self.weight = weight
    
    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, weight=self.weight, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma * ce_loss).mean()
        return focal_loss
```

### 7.2 Optimizer Selection

```python
# Default choice: AdamW
optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)

# For fine-tuning pretrained models: lower LR for pretrained, higher for new layers
optimizer = torch.optim.AdamW([
    {'params': model.bert.parameters(), 'lr': 1e-5},
    {'params': model.classifier.parameters(), 'lr': 1e-4}
])
```

### 7.3 Learning Rate Scheduling

```python
# Warmup + Cosine decay (best for transformers)
from transformers import get_cosine_schedule_with_warmup

scheduler = get_cosine_schedule_with_warmup(
    optimizer,
    num_warmup_steps=int(0.1 * total_steps),  # 10% warmup
    num_training_steps=total_steps
)

# Step every batch
for batch in dataloader:
    loss = train_step(batch)
    optimizer.step()
    scheduler.step()  # Update LR
```

### 7.4 Regularization Techniques

```python
# 1. Dropout - randomly zero neurons
nn.Dropout(p=0.3)  # 30% dropout

# 2. Weight Decay (L2 regularization)
optimizer = AdamW(params, weight_decay=0.01)

# 3. Label Smoothing - soft labels
loss_fn = nn.CrossEntropyLoss(label_smoothing=0.1)

# 4. Early Stopping
if val_loss > best_val_loss:
    patience_counter += 1
    if patience_counter >= patience:
        print("Early stopping!")
        break
else:
    best_val_loss = val_loss
    patience_counter = 0
    save_checkpoint()

# 5. Gradient Clipping - prevent exploding gradients
torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
```

### 7.5 Training Loop Template

```python
def train_epoch(model, dataloader, optimizer, scheduler, device):
    model.train()
    total_loss = 0
    
    for batch in tqdm(dataloader):
        # Move to device
        inputs = {k: v.to(device) for k, v in batch.items()}
        labels = inputs.pop('labels')
        
        # Forward pass
        optimizer.zero_grad()
        outputs = model(**inputs)
        loss = loss_fn(outputs, labels)
        
        # Backward pass
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()
        
        total_loss += loss.item()
    
    return total_loss / len(dataloader)

def validate(model, dataloader, device):
    model.eval()
    all_preds, all_labels = [], []
    
    with torch.no_grad():
        for batch in dataloader:
            inputs = {k: v.to(device) for k, v in batch.items()}
            labels = inputs.pop('labels')
            
            outputs = model(**inputs)
            preds = torch.argmax(outputs, dim=1)
            
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    
    accuracy = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average='weighted')
    
    return accuracy, f1
```

---

## 8. Evaluation & Metrics

### 8.1 Metric Selection

| Scenario | Primary Metric | Why |
|----------|---------------|-----|
| Balanced classes | Accuracy | Simple, interpretable |
| Imbalanced classes | F1 (weighted) | Balances precision/recall |
| Cost-sensitive | Custom weighted | Business requirements |
| Ranking | AUC-ROC | Threshold-independent |

### 8.2 Understanding Metrics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CONFUSION MATRIX REFRESHER:                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                          Predicted                                          │
│                    Positive    Negative                                     │
│  Actual  Positive    TP          FN                                        │
│          Negative    FP          TN                                        │
│                                                                             │
│  Precision = TP / (TP + FP)  → "Of predicted positive, how many correct?"  │
│  Recall    = TP / (TP + FN)  → "Of actual positive, how many caught?"      │
│  F1        = 2 * (P * R) / (P + R)  → Harmonic mean of P and R             │
│                                                                             │
│  HIGH PRECISION: Few false alarms (good for spam filter)                   │
│  HIGH RECALL: Catch everything (good for disease detection)                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Loss vs Metrics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CRITICAL DISTINCTION:                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LOSS FUNCTION:                                                             │
│  - Used to UPDATE WEIGHTS via backpropagation                              │
│  - MUST be differentiable                                                   │
│  - Examples: CrossEntropy, MSE, Focal Loss                                  │
│                                                                             │
│  EVALUATION METRICS:                                                        │
│  - Used to MEASURE PERFORMANCE for humans                                   │
│  - NOT differentiable (discrete counting)                                   │
│  - Examples: Accuracy, F1, Precision, Recall                                │
│                                                                             │
│  You CANNOT backprop through F1 score!                                      │
│  Loss tells model "how wrong", metrics tell us "how good"                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Debugging & Troubleshooting

### 9.1 Common Problems and Solutions

| Problem | Symptom | Solution |
|---------|---------|----------|
| **Overfitting** | Train loss ↓, Val loss ↑ | More dropout, weight decay, data augmentation |
| **Underfitting** | Both losses high | Bigger model, more features, longer training |
| **Vanishing gradients** | No learning | Use ReLU, LayerNorm, skip connections |
| **Exploding gradients** | NaN loss | Gradient clipping, lower LR |
| **Class imbalance** | Poor minority F1 | Class weights, focal loss, resampling |
| **Data leakage** | Val >> Test | Check preprocessing order, duplicates |

### 9.2 Overfitting Diagnosis

```python
# Plot learning curves
plt.plot(train_losses, label='Train')
plt.plot(val_losses, label='Validation')
plt.legend()

# If gap is large → Overfitting
# Remedies:
# 1. Increase dropout (0.3 → 0.5)
# 2. Increase weight decay (0.01 → 0.05)
# 3. Add label smoothing (0.1)
# 4. Reduce model size
# 5. Early stopping
# 6. More training data
# 7. Data augmentation
```

### 9.3 Debugging Checklist

```python
# When model isn't learning:
□ Is data loaded correctly? (print samples)
□ Are labels correct? (verify mapping)
□ Is loss decreasing? (even slowly)
□ Are gradients flowing? (check grad norms)
□ Is learning rate appropriate? (try 10x and 0.1x)
□ Is model in train mode? (model.train())
□ Are you zeroing gradients? (optimizer.zero_grad())
□ Did you call backward and step? (loss.backward(), optimizer.step())
```

---

## 10. Production Deployment

### 10.1 Model Saving & Loading

```python
# Save complete checkpoint
torch.save({
    'epoch': epoch,
    'model_state_dict': model.state_dict(),
    'optimizer_state_dict': optimizer.state_dict(),
    'best_val_f1': best_f1,
    'config': config
}, 'checkpoint.pt')

# Load checkpoint
checkpoint = torch.load('checkpoint.pt')
model.load_state_dict(checkpoint['model_state_dict'])
```

### 10.2 Inference Optimization

```python
# 1. Use eval mode
model.eval()

# 2. Disable gradients
with torch.no_grad():
    outputs = model(inputs)

# 3. Batch predictions
# Instead of one-by-one, batch multiple inputs

# 4. Use half precision (if GPU supports)
model.half()

# 5. Export to ONNX for faster inference
torch.onnx.export(model, sample_input, "model.onnx")
```

### 10.3 Deployment Checklist

```
□ Model saved and loadable
□ Preprocessing pipeline saved (tokenizer, encoders)
□ Input validation (handle edge cases)
□ Error handling (graceful failures)
□ Logging (track predictions)
□ Monitoring (detect drift)
□ API wrapper (FastAPI/Flask)
□ Documentation (input/output format)
□ Tests (unit + integration)
□ Version control (model versioning)
```

---

## 📝 Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ML DEVELOPMENT QUICK REFERENCE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PIPELINE ORDER:                                                            │
│  1. Collect data → 2. EDA → 3. Clean → 4. Split → 5. Preprocess            │
│  → 6. Train → 7. Evaluate → 8. Tune → 9. Test → 10. Deploy                 │
│                                                                             │
│  EDA MUST-CHECKS:                                                           │
│  □ Duplicates  □ Missing values  □ Label distribution  □ Feature stats     │
│                                                                             │
│  PREVENT DATA LEAKAGE:                                                      │
│  □ Remove duplicates BEFORE split                                          │
│  □ Fit transformers on TRAIN ONLY                                          │
│  □ Never use future to predict past                                        │
│                                                                             │
│  TRAINING ESSENTIALS:                                                       │
│  □ Set random seed  □ Use validation set  □ Save best checkpoint           │
│  □ Monitor train & val loss  □ Use early stopping                          │
│                                                                             │
│  COMBAT OVERFITTING:                                                        │
│  □ Dropout  □ Weight decay  □ Label smoothing  □ Early stopping            │
│                                                                             │
│  COMBAT UNDERFITTING:                                                       │
│  □ Bigger model  □ More features  □ Longer training  □ Lower regularization│
│                                                                             │
│  IMBALANCED CLASSES:                                                        │
│  □ Class weights  □ Focal loss  □ Oversampling  □ F1 metric               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Remember

> **"The best model is one that generalizes well to unseen data, not one that memorizes the training data."**

> **"Spend 80% of time on data, 20% on modeling."**

> **"If you can't explain why your model works, you don't understand it."**

---

*This guide is based on practical experience building the CTPPO CVE Severity Classification model and general ML best practices.*

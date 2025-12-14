# CTPPO Complete ML Integration

## 🎯 Quick Start

### 1. Copy to your CTPPO project
```bash
cp -r ml ~/Desktop/cyber_threat_optimizer/
```

### 2. Copy your trained models
```bash
cp ~/Desktop/ctppo_ml_training/training/checkpoints/gnn_predictor/best_gnn_model.pt \
   ~/Desktop/cyber_threat_optimizer/ml/trained_models/

cp ~/Desktop/ctppo_ml_training/training/checkpoints/rl_defender/best_rl_model.pt \
   ~/Desktop/cyber_threat_optimizer/ml/trained_models/
```

### 3. Test
```bash
cd ~/Desktop/cyber_threat_optimizer
python3 ml/ctppo_ml.py
```

### 4. Use in your code
```python
from ml.ctppo_ml import CTPPOPipeline

pipeline = CTPPOPipeline()
results = pipeline.analyze(your_scan_results)

print(f"Risk: {results['risk_score']}/10")
print(f"Top Action: {results['recommendations'][0]['action']}")
```

## 📁 Structure

```
ml/
├── ctppo_ml.py              # Main integration (use this!)
├── trained_models/          # Your trained .pt files go here
│   ├── best_gnn_model.pt
│   └── best_rl_model.pt
└── models/                  # Model architectures
    ├── gnn_predictor/
    ├── rl_defender/
    └── severity_classifier/
```

## 📊 Components

| Component | Method | Status |
|-----------|--------|--------|
| Severity | CVSS Rules | Always works |
| GNN Risk | ML Model | Needs best_gnn_model.pt |
| RL Defense | ML Model | Needs best_rl_model.pt |

## 🔧 API

```python
from ml.ctppo_ml import CTPPOPipeline

pipeline = CTPPOPipeline()

# Full analysis
results = pipeline.analyze({"vulnerabilities": [...]})

# Quick severity
severity = pipeline.get_severity(9.5)  # "CRITICAL"

# Quick risk score
score = pipeline.quick_score(vulnerabilities)  # 7.8
```

## 📈 Training Results

| Model | Performance |
|-------|-------------|
| Severity | 100% (rule-based) |
| GNN | 97.6% accuracy |
| RL | 5000 episodes |

---
**Author:** Ruthvik Bandari | Northeastern University

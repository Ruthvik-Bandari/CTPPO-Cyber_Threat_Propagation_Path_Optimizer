# Getting Started with CTPPO

## Cyber Threat Propagation Path Optimizer - Step by Step Guide

**Author:** Ruthvik  
**Date:** November 2025  
**Version:** 1.0.0

---

## Quick Start (5 minutes)

### Step 1: Download/Clone the Project

```bash
# If you have git
git clone <your-repo-url> cyber_threat_optimizer
cd cyber_threat_optimizer

# Or if you received it as a zip file
unzip cyber_threat_optimizer.zip
cd cyber_threat_optimizer
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it (Linux/Mac)
source venv/bin/activate

# Activate it (Windows)
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt

# Install the project in development mode
pip install -e .
```

### Step 4: Verify Installation

```bash
python run_quick_test.py
```

You should see all tests pass with green checkmarks.

---

## Detailed Setup Instructions

### Prerequisites

1. **Python 3.10+** - Check with `python3 --version`
2. **pip** - Check with `pip --version`
3. **Git** (optional) - For version control

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4 GB | 16 GB |
| CPU | 2 cores | 8+ cores |
| Disk | 2 GB | 10 GB |
| GPU | Not required | CUDA-capable (for RL) |

### Installing Dependencies Manually

If the automatic installation fails, install these packages:

```bash
# Core packages
pip install numpy scipy pandas networkx

# Visualization
pip install matplotlib seaborn plotly

# Machine Learning (optional, for RL-guided search)
pip install torch torch-geometric scikit-learn

# Optimization
pip install cvxpy pulp

# Logging
pip install loguru rich tqdm

# Data validation
pip install pydantic
```

---

## Project Structure Overview

```
cyber_threat_optimizer/
│
├── core/                      # Core data structures
│   ├── __init__.py
│   ├── node_types.py          # Asset, Vulnerability, Exploit nodes
│   ├── edge_costs.py          # Multi-dimensional costs & distributions
│   ├── attack_graph.py        # Main AttackGraph class
│   └── logging_system.py      # Research logging
│
├── algorithms/                # MOSP algorithms
│   ├── pareto_utils.py        # Pareto dominance operations
│   ├── namoa_star.py          # NAMOA* algorithm (coming next)
│   ├── label_setting.py       # Label-setting variants
│   └── heuristics.py          # Cyber-specific heuristics
│
├── probabilistic/             # Stochastic extensions
├── dynamic/                   # Dynamic graph updates
├── defense/                   # Mitigation optimization
├── visualization/             # Graphs and dashboards
├── experiments/               # Benchmarking framework
├── logs/                      # Execution logs (auto-generated)
│
├── requirements.txt           # Dependencies
├── setup.py                   # Package installer
├── run_quick_test.py          # Verification script
└── GETTING_STARTED.md         # This file
```

---

## What to Do Next

### Option A: Run the Demo (Recommended First)

```bash
python run_demo.py
```

This will:
1. Create a sample enterprise network attack graph
2. Find all attack paths from entry points to goals
3. Run multi-objective path optimization
4. Display Pareto-optimal attack paths
5. Generate visualizations

### Option B: Interactive Exploration with Jupyter

```bash
# Start Jupyter Lab
jupyter lab

# Open notebooks/01_getting_started.ipynb
```

### Option C: Build Your Own Attack Graph

```python
from core import AttackGraph, AssetNode, VulnerabilityNode
from core import EdgeType, EdgeCostVector, CostType

# Create empty graph
graph = AttackGraph(name="MyNetwork")

# Add an asset
server = AssetNode(
    name="WebServer",
    ip_addresses=["10.0.1.10"],
    criticality=8.0
)
graph.add_node(server)

# Add a vulnerability
vuln = VulnerabilityNode(
    name="SQL Injection",
    cve_id="CVE-2023-12345",
    cvss_score=8.5
)
graph.add_node(vuln)

# Connect them
graph.add_edge(server.id, vuln.id, EdgeType.ASSET_HAS_VULN)

# Save the graph
graph.save_json("my_network.json")
```

---

## Development Workflow

### Running Tests

```bash
# Quick verification
python run_quick_test.py

# Full test suite (when available)
pytest tests/ -v
```

### Logging for Research

All operations are automatically logged. Find logs in:

```
logs/
├── exp_20251128_123456_abc123/
│   ├── full_log.jsonl           # All log entries
│   ├── metrics.jsonl            # Performance metrics
│   └── algorithm_decisions.jsonl # Algorithmic choices
```

Export for your research paper:

```python
from core import ResearchLogger

logger = ResearchLogger("MyExperiment")
# ... run your experiments ...
logger.export_for_paper()  # Creates paper_export/ directory
```

### Visualization

```python
from visualization import GraphVisualizer

viz = GraphVisualizer(graph)
viz.plot_attack_graph()        # NetworkX visualization
viz.plot_pareto_front(paths)   # Pareto frontier
viz.save_all("figures/")       # Save for paper
```

---

## Common Issues & Solutions

### Issue: Module not found

```
ModuleNotFoundError: No module named 'core'
```

**Solution:** Install in development mode:
```bash
pip install -e .
```

### Issue: NumPy/SciPy errors

**Solution:** Upgrade packages:
```bash
pip install --upgrade numpy scipy
```

### Issue: Visualization not showing

**Solution:** For Jupyter:
```python
%matplotlib inline
```

For scripts:
```python
import matplotlib
matplotlib.use('TkAgg')  # or 'Agg' for saving only
```

---

## Research Paper Preparation

### Collecting Metrics

```python
# The logger automatically tracks:
# - Algorithm runtime
# - Memory usage
# - Pareto set sizes
# - Dominance statistics
# - Path quality metrics

logger.export_for_paper()
```

### Generating Figures

All figures are saved in publication-ready formats:

```python
from visualization import ParetoVisualizer

viz = ParetoVisualizer(pareto_front)
viz.plot_2d_front(save_path="figures/pareto_front.pdf", dpi=300)
viz.plot_3d_front(save_path="figures/pareto_3d.pdf")
```

### BibTeX Citation

```bibtex
@inproceedings{ruthvik2025ctppo,
  title={CTPPO: Multi-Objective Probabilistic Attack Path Optimization},
  author={Ruthvik},
  booktitle={[Conference Name]},
  year={2025}
}
```

---

## Next Steps in Development

1. **[DONE]** Core data structures (nodes, edges, costs)
2. **[DONE]** Pareto dominance utilities
3. **[NEXT]** NAMOA* algorithm implementation
4. **[TODO]** Probabilistic path computation
5. **[TODO]** Dynamic graph updates
6. **[TODO]** RL-guided search
7. **[TODO]** Defense optimization layer
8. **[TODO]** Full visualization dashboard

---

## Getting Help

- Check the logs in `logs/` for detailed error information
- Review the docstrings in each module
- Open an issue on the repository

---

**Happy Researching! 🔬**

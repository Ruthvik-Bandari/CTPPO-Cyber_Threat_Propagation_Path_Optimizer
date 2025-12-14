# CTPPO: Cyber Threat Propagation Path Optimizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![arXiv](https://img.shields.io/badge/arXiv-2412.XXXXX-b31b1b.svg)](https://arxiv.org/abs/2412.XXXXX)

A hybrid machine learning framework for multi-objective vulnerability prioritization using Graph Neural Networks and Reinforcement Learning.

![System Architecture](docs/images/architecture.png)

## Overview

CTPPO addresses the critical challenge of **alert fatigue** in Security Operations Centers (SOCs) by providing intelligent vulnerability prioritization through:

- **Multi-objective optimization** using NAMOA* algorithm
- **Graph Neural Networks** (GraphSAGE) for risk prediction
- **Reinforcement Learning** (Dueling DQN) for defense recommendations
- **Automated scanning** with OWASP ZAP and Nmap integration

## Key Features

| Feature | Description |
|---------|-------------|
| **Vulnerability Scanning** | Automated scanning with OWASP ZAP and Nmap |
| **Attack Graph Generation** | Dynamic graph modeling of vulnerability relationships |
| **Pareto-Optimal Paths** | NAMOA* algorithm finds optimal attack paths |
| **Risk Prediction** | GNN achieves 97.6% accuracy on graph classification |
| **Defense Recommendations** | RL agent trained over 5,000 episodes |
| **Interactive Dashboard** | Real-time visualization with Plotly Dash |

## Performance

| Metric | Value |
|--------|-------|
| GNN Classification Accuracy | 97.6% |
| Risk Score R² | 0.9286 |
| NAMOA* Execution Time | 383 ms |
| Training Data | 68,355 real CVEs from NVD |

## Installation

### Prerequisites

- Python 3.11+
- OWASP ZAP (for vulnerability scanning)
- Nmap (for network scanning)

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ctppo.git
cd ctppo

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Install OWASP ZAP

**macOS:**
```bash
brew install --cask owasp-zap
```

**Ubuntu/Debian:**
```bash
sudo apt install zaproxy
```

### Install Nmap

**macOS:**
```bash
brew install nmap
```

**Ubuntu/Debian:**
```bash
sudo apt install nmap
```

## Usage

### 1. Start OWASP ZAP in Daemon Mode

```bash
# macOS
/Applications/OWASP\ ZAP.app/Contents/Java/zap.sh -daemon -port 8080

# Linux
zap.sh -daemon -port 8080
```

### 2. Run the Dashboard

```bash
python run_dashboard.py
```

Open your browser and navigate to `http://127.0.0.1:8050`

### 3. Run a Scan

Enter a target URL (use only authorized test sites) and click "Start Scan".

## Project Structure

```
ctppo/
├── run_dashboard.py          # Main entry point
├── requirements.txt          # Python dependencies
├── src/
│   ├── scanner/              # Vulnerability scanning modules
│   │   ├── zap_scanner.py    # OWASP ZAP integration
│   │   └── nmap_scanner.py   # Nmap integration
│   ├── graph/                # Attack graph generation
│   │   └── attack_graph.py   # Graph construction
│   ├── optimization/         # Path optimization
│   │   └── namoa_star.py     # NAMOA* algorithm
│   ├── ml/                   # Machine learning models
│   │   ├── gnn_model.py      # GraphSAGE model
│   │   └── rl_agent.py       # Dueling DQN agent
│   └── dashboard/            # Web interface
│       └── app.py            # Plotly Dash application
├── models/                   # Trained model checkpoints
│   ├── gnn_model.pt          # GNN weights
│   └── rl_model.pt           # RL agent weights
├── data/                     # Data files
│   └── cve_data/             # CVE dataset from NVD
└── docs/                     # Documentation
    └── images/               # Architecture diagrams
```

## Authorized Test Targets

**Only scan websites you have permission to test!** Here are intentionally vulnerable sites for testing:

| Site | URL |
|------|-----|
| TestPHP (Acunetix) | http://testphp.vulnweb.com |
| Altoro Mutual | http://demo.testfire.net |
| OWASP Juice Shop | https://juice-shop.herokuapp.com |
| Hackazon | http://hackazon.webscantest.com |

## Model Training

### Train GNN Model

```bash
python train_gnn.py --epochs 100 --patience 10
```

### Train RL Agent

```bash
python train_rl.py --episodes 5000
```

### Download CVE Data from NVD

```bash
python download_cve_data.py --start 2023-01 --end 2024-12
```

## Citation

If you use CTPPO in your research, please cite:

```bibtex
@article{bandari2024ctppo,
  title={CTPPO: A Hybrid Machine Learning Framework for Multi-Objective Vulnerability Prioritization Using Graph Neural Networks and Reinforcement Learning},
  author={Bandari, Ruthvik Nath},
  journal={arXiv preprint arXiv:2412.XXXXX},
  year={2024}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

⚠️ **IMPORTANT: This tool is provided for EDUCATIONAL and RESEARCH purposes only.**

- **DO NOT** use this tool to scan systems without explicit written permission
- **DO NOT** use this tool for illegal or unethical purposes
- The authors are **NOT responsible** for any misuse or damage caused by this tool
- Always comply with applicable laws and regulations
- Unauthorized scanning of computer systems is illegal in most jurisdictions

By using this software, you agree to use it responsibly and ethically.

## Author

**Ruthvik Nath Bandari**  
Master of Professional Studies in Applied Artificial Intelligence  
Northeastern University  
Email: bandari.ru@northeastern.edu

## Acknowledgments

- [OWASP Foundation](https://owasp.org/) for ZAP and security resources
- [NIST](https://nvd.nist.gov/) for the National Vulnerability Database
- [PyTorch Geometric](https://pytorch-geometric.readthedocs.io/) for GNN implementation

---

⭐ **Star this repo if you find it useful!**

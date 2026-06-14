# CTPPO - Cyber Threat Propagation Path Optimizer

## Enterprise Cybersecurity Platform | AI-Powered Attack Path Analysis

**Version 3.0.0** | **Proprietary Software** | **All Rights Reserved**

---

## Overview

CTPPO (Cyber Threat Propagation Path Optimizer) is a research platform that uses the NAMOA* multi-objective optimization algorithm to identify and prioritize cyber attack paths in network infrastructures. Data-grounded cost modeling (EPSS / CISA KEV / CVSS) and Graph Neural Network cost-learning are under active development.

This software is developed and owned by **Ruthvik Bandari** and requires a valid subscription license to operate.

---

## Project Status

> **Research project under active development.** The table below reflects what is
> actually implemented today. No performance metrics are published yet — they will be
> added only after a documented evaluation against baselines.

| Component | Status |
|-----------|--------|
| NAMOA* multi-objective path engine | Implemented |
| Vulnerability scanners (headers, SSL, ports) | Implemented |
| Attack-graph construction from scans | Implemented (heuristic edge costs) |
| Data-grounded edge costs (EPSS / CISA KEV / CVSS) | In development |
| GNN-based cost / exploitability learning | In development |
| CVE severity classifier (trained model) | Not trained yet |

---

## Core Features

### AI-Powered Analysis
- CVE severity classification via transformer models *(training pipeline present; no trained model or published metric yet)*
- Graph Neural Network for attack-propagation cost learning *(planned — see Project Status)*
- Reinforcement Learning for defensive resource allocation *(planned)*

### Real-time Security Scanning
- Port scanning and service discovery
- Vulnerability detection (missing security headers, SSL issues, version disclosure)
- Cloud provider detection (Vercel, Netlify, AWS, Cloudflare)

### Advanced Visualization
- Interactive 2D network graphs with multiple layout algorithms
- Pareto Front analysis for multi-objective optimization
- Attack path highlighting and tracing

### Enterprise Features
- JWT-based authentication with subscription validation
- Product key licensing system
- Professional PDF report generation
- Full REST API for integration

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, TypeScript, TailwindCSS |
| Backend | Python 3.10+, FastAPI, Pydantic |
| ML/AI | PyTorch, Transformers, Scikit-learn, NetworkX |
| Database | SQLite (dev), PostgreSQL (prod) |
| DevOps | Docker, GitHub Actions |

---

## Licensing

**This software is proprietary and requires a valid subscription license.**

- Personal/Educational use requires a valid product key
- Commercial use requires enterprise licensing agreement
- Unauthorized use, copying, or distribution is strictly prohibited

To obtain a license, contact: **bandari.ru@northeastern.edu**

See [LICENSE](LICENSE) for complete terms.

---

## Installation (Licensed Users Only)

### Prerequisites
- Valid product key linked to your email
- Python 3.10+
- Node.js 18+ or Bun

### Setup

```bash
# Clone repository (licensed users only)
git clone https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer

# Run setup
chmod +x setup.sh
./setup.sh

# Start application
./start.sh
```

### Access Points

| Service | URL |
|---------|-----|
| Application | http://localhost:5173 |
| API Documentation | http://localhost:8000/docs |

---

## Project Structure

```
CTPPO/
├── api/                 # FastAPI backend with authentication
├── frontend/            # React TypeScript frontend
├── ml/                  # Machine Learning models and pipelines
├── algorithms/          # NAMOA* and Pareto optimization
├── scanners/            # Security scanning modules
├── core/                # Attack graph and node types
├── models/              # Trained ML models
├── tests/               # Test suite
└── docs/                # Documentation
```

---

## API Overview

All API endpoints require valid authentication token.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | User authentication |
| `/api/auth/activate` | POST | Activate product key |
| `/api/cve/classify` | POST | Classify CVE severity |
| `/api/scan` | POST | Scan target for vulnerabilities |
| `/api/attack-paths/analyze` | POST | Analyze attack paths |

---

## Security Notice

This tool is designed for **authorized security testing only**. Users must:

- Only scan systems they own or have explicit permission to test
- Comply with all applicable laws and regulations
- Not use this tool for malicious purposes

Misuse of this software may result in license revocation and legal action.

---

## About the Developer

**Ruthvik Bandari**

- MS in Applied Artificial Intelligence, Northeastern University (4.0 GPA)
- Specialization: Machine Learning, Cybersecurity, Graph Neural Networks
- Email: bandari.ru@northeastern.edu
- LinkedIn: linkedin.com/in/ruthvik-bandari
- GitHub: github.com/Ruthvik-Bandari

---

## Support

For technical support, licensing inquiries, or bug reports:

- Email: bandari.ru@northeastern.edu
- Subject line: [CTPPO Support] Your Issue

---

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. THE DEVELOPER SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE. USERS ARE RESPONSIBLE FOR ENSURING THEY HAVE PROPER AUTHORIZATION BEFORE SCANNING ANY SYSTEMS.

---

**© 2024-2026 Ruthvik Bandari. All Rights Reserved.**

*Unauthorized copying, modification, distribution, or use of this software is strictly prohibited.*

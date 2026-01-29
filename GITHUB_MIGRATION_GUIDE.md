# 🚀 GitHub Repository Replacement Guide

## Complete Instructions to Replace Your CTPPO Repository

This guide will help you completely replace your existing GitHub repository with the new v3.0 codebase.

---

## Step 1: Backup Your Existing Repo (Optional)

```bash
# Clone your existing repo as backup
git clone https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git ctppo-backup
```

---

## Step 2: Delete All Files in Existing Repo

### Option A: Via GitHub Web Interface
1. Go to https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer
2. Settings → Danger Zone → Delete this repository
3. Create a new repository with the same name

### Option B: Via Command Line (Recommended)
```bash
# Clone your repo
git clone https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer

# Remove all files except .git
git rm -rf .
git commit -m "chore: clear repository for v3.0 migration"
git push origin main
```

---

## Step 3: Extract New Code

```bash
# Download the ctppo-github.zip from Claude
# Extract it
unzip ctppo-github.zip

# Copy all files to your repo directory
cp -r ctppo-github/* CTPPO-Cyber_Threat_Propagation_Path_Optimizer/
cp ctppo-github/.gitignore CTPPO-Cyber_Threat_Propagation_Path_Optimizer/
cp -r ctppo-github/.github CTPPO-Cyber_Threat_Propagation_Path_Optimizer/
```

---

## Step 4: Push New Code

```bash
cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer

# Add all new files
git add .

# Commit
git commit -m "feat: complete v3.0 rewrite with ML, NAMOA*, and React frontend

- Add CVE Severity Classifier (97.5% F1 Score)
- Implement NAMOA* multi-objective attack path optimization
- Create React + TypeScript frontend with 2D/3D visualization
- Add FastAPI backend with JWT authentication
- Include Docker support and CI/CD pipelines
- Add comprehensive documentation"

# Push to GitHub
git push origin main

# Create a release tag
git tag -a v3.0.0 -m "Version 3.0.0 - Complete Rewrite"
git push origin v3.0.0
```

---

## Step 5: Configure GitHub Repository Settings

### 5.1 Update Repository Description
Go to your repo → About (gear icon):
- **Description**: `AI-Powered Cyber Threat Analysis using Graph Neural Networks & NAMOA* Algorithm | 97.5% F1 Score`
- **Website**: Your deployment URL (optional)
- **Topics**: `cybersecurity`, `machine-learning`, `attack-path`, `gnn`, `python`, `react`, `fastapi`, `namoa-star`

### 5.2 Enable GitHub Pages (Optional)
Settings → Pages → Source: Deploy from branch → `main` → `/docs`

### 5.3 Configure Secrets for CI/CD
Settings → Secrets and variables → Actions → New repository secret:

| Secret Name | Description |
|-------------|-------------|
| `SECRET_KEY` | Random 32-char string |
| `JWT_SECRET` | Random 32-char string |
| `VERCEL_TOKEN` | (Optional) For frontend deployment |
| `NVD_API_KEY` | (Optional) For CVE data updates |

---

## Step 6: Verify Everything Works

```bash
# Test CI pipeline
# Push a small change to trigger GitHub Actions
echo "# Test" >> test.md
git add test.md
git commit -m "test: verify CI pipeline"
git push origin main

# Check Actions tab on GitHub for CI results
```

---

## Repository Structure After Migration

```
CTPPO-Cyber_Threat_Propagation_Path_Optimizer/
├── .github/
│   └── workflows/
│       ├── ci.yml           # CI pipeline
│       └── deploy.yml       # CD pipeline
├── api/
│   ├── server_secure.py     # FastAPI backend
│   └── pdf_generator.py     # Report generation
├── frontend/
│   ├── src/
│   │   ├── routes/          # Page components
│   │   │   ├── attack-paths.tsx
│   │   │   ├── dashboard.tsx
│   │   │   ├── classify.tsx
│   │   │   └── scan.tsx
│   │   └── ...
│   ├── package.json
│   └── Dockerfile
├── ml/
│   ├── ctppo_ml.py          # ML models
│   └── real_scanner.py      # Vulnerability scanner
├── algorithms/
│   ├── namoa_star.py        # NAMOA* implementation
│   └── pareto_utils.py      # Pareto optimization
├── docs/
│   ├── INSTALLATION.md      # Setup guide
│   └── CICD.md              # CI/CD documentation
├── models/                   # Trained ML models
├── tests/                    # Test suite
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── setup.sh
├── start.sh
├── README.md
├── LICENSE
├── CONTRIBUTING.md
└── .gitignore
```

---

## Next Steps After Migration

1. **Star your own repo** to boost visibility
2. **Add topics** for discoverability
3. **Create releases** for version tracking
4. **Enable Discussions** for community interaction
5. **Set up branch protection** for main branch

---

## Troubleshooting

### Git push rejected
```bash
git pull origin main --rebase
git push origin main
```

### Large file error
```bash
# If you have large model files
git lfs install
git lfs track "*.pt"
git lfs track "*.pth"
git add .gitattributes
```

### Permission denied
```bash
# Check your SSH key
ssh -T git@github.com

# Or use HTTPS with token
git remote set-url origin https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
```

---

*Generated for CTPPO v3.0.0 Migration*

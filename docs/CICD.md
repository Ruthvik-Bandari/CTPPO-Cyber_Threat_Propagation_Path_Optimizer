# CI/CD Pipeline Documentation

This document describes the Continuous Integration and Continuous Deployment (CI/CD) pipelines for CTPPO.

## Table of Contents

- [Overview](#overview)
- [Pipeline Architecture](#pipeline-architecture)
- [CI Pipeline](#ci-pipeline)
- [CD Pipeline](#cd-pipeline)
- [ML Pipeline](#ml-pipeline)
- [Secrets Configuration](#secrets-configuration)
- [Local Testing](#local-testing)

---

## Overview

CTPPO uses GitHub Actions for automated testing, building, and deployment. The pipelines ensure code quality, security, and reliable deployments.

### Pipeline Summary

| Pipeline | Trigger | Purpose |
|----------|---------|---------|
| CI | Push/PR | Test, lint, build |
| Deploy | Release/Manual | Production deployment |
| ML Pipeline | Schedule/Manual | Model retraining |

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Git Repository                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Actions                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │     CI       │  │    Deploy    │  │  ML Pipeline │          │
│  │   Pipeline   │  │   Pipeline   │  │              │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│         ▼                 ▼                 ▼                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Backend    │  │    Docker    │  │    Model     │          │
│  │   Frontend   │  │    Build     │  │   Training   │          │
│  │   Security   │  │   & Push     │  │   & Upload   │          │
│  └──────────────┘  └──────┬───────┘  └──────────────┘          │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
       ┌──────────────┐            ┌──────────────┐
       │    Vercel    │            │  Cloud Run   │
       │  (Frontend)  │            │  (Backend)   │
       └──────────────┘            └──────────────┘
```

---

## CI Pipeline

**File:** `.github/workflows/ci.yml`

### Trigger Events

```yaml
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
```

### Jobs

#### 1. Backend Tests

```yaml
backend:
  steps:
    - Checkout code
    - Setup Python 3.10
    - Install dependencies
    - Run flake8 linting
    - Run Black formatter check
    - Run mypy type checking
    - Run pytest with coverage
    - Upload coverage to Codecov
```

**Commands:**
```bash
# Linting
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

# Formatting check
black --check --diff .

# Type checking
mypy api/ --ignore-missing-imports

# Tests with coverage
pytest tests/ -v --tb=short --cov=. --cov-report=xml
```

#### 2. Frontend Tests

```yaml
frontend:
  steps:
    - Checkout code
    - Setup Bun
    - Install dependencies
    - Run ESLint
    - Type check
    - Build production bundle
    - Upload build artifacts
```

**Commands:**
```bash
# Install
bun install

# Lint
bun run lint

# Type check
bun run type-check

# Build
bun run build
```

#### 3. ML Validation

```yaml
ml-validation:
  steps:
    - Validate model files exist
    - Test NAMOA* algorithm
    - Verify classifier loads
```

#### 4. Security Scan

```yaml
security:
  steps:
    - Run Trivy vulnerability scanner
    - Run pip-audit
```

---

## CD Pipeline

**File:** `.github/workflows/deploy.yml`

### Trigger Events

```yaml
on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      environment:
        type: choice
        options: [staging, production]
```

### Jobs

#### 1. Build and Push Docker Image

```yaml
build-and-push:
  steps:
    - Setup Docker Buildx
    - Login to GitHub Container Registry
    - Build multi-platform image
    - Push to registry with semantic versioning tags
```

**Image Tags:**
- `v1.2.3` - Version tag
- `v1.2` - Minor version tag
- `sha-abc1234` - Commit SHA tag

#### 2. Deploy Frontend (Vercel)

```yaml
deploy-frontend:
  steps:
    - Build frontend with production API URL
    - Deploy to Vercel with production flag
```

#### 3. Deploy Backend (Cloud Run)

```yaml
deploy-backend:
  steps:
    - Authenticate to GCP
    - Deploy container to Cloud Run
    - Configure auto-scaling (1-10 instances)
```

#### 4. Smoke Tests

```yaml
smoke-tests:
  steps:
    - Health check API endpoint
    - Health check Frontend
    - Test CVE classification endpoint
```

---

## ML Pipeline

**File:** `.github/workflows/ml-pipeline.yml`

```yaml
name: ML Model Training Pipeline

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:
    inputs:
      force_retrain:
        type: boolean
        default: false

jobs:
  fetch-data:
    steps:
      - Fetch latest CVEs from NVD
      - Preprocess data
      - Upload as artifact

  train-model:
    needs: fetch-data
    steps:
      - Download data artifact
      - Train severity classifier
      - Evaluate model performance
      - Upload trained model

  validate-model:
    needs: train-model
    steps:
      - Download new model
      - Compare with existing model
      - Run integration tests
      - Approve if better

  deploy-model:
    needs: validate-model
    if: success()
    steps:
      - Upload model to cloud storage
      - Update model version in config
      - Trigger backend deployment
```

### Model Training Commands

```bash
# Fetch latest CVE data
python ml/01_fetch_nvd.py

# Preprocess data
python ml/02_preprocess_data.py

# Train model
python ml/04_train_model.py

# Evaluate
python ml/05_evaluate_model.py
```

---

## Secrets Configuration

### Required Secrets

Configure these in GitHub Repository Settings → Secrets:

#### General

| Secret | Description |
|--------|-------------|
| `SECRET_KEY` | Application secret key |
| `JWT_SECRET` | JWT signing secret |

#### Vercel (Frontend)

| Secret | Description |
|--------|-------------|
| `VERCEL_TOKEN` | Vercel API token |
| `VERCEL_ORG_ID` | Vercel organization ID |
| `VERCEL_PROJECT_ID` | Vercel project ID |

#### Google Cloud (Backend)

| Secret | Description |
|--------|-------------|
| `GCP_PROJECT_ID` | GCP project ID |
| `GCP_SERVICE_ACCOUNT` | Service account email |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Workload identity provider |

#### Optional

| Secret | Description |
|--------|-------------|
| `NVD_API_KEY` | NVD API key for CVE fetching |
| `SLACK_WEBHOOK_URL` | Slack notifications |
| `CODECOV_TOKEN` | Codecov upload token |

### Setting Secrets

```bash
# Using GitHub CLI
gh secret set SECRET_KEY --body "your-secret-value"
gh secret set VERCEL_TOKEN --body "your-vercel-token"

# Or via GitHub UI:
# Settings → Secrets and variables → Actions → New repository secret
```

---

## Local Testing

### Test CI Pipeline Locally

```bash
# Install act (GitHub Actions local runner)
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run CI workflow
act push

# Run specific job
act -j backend

# Run with secrets
act --secret-file .secrets
```

### Test Docker Build

```bash
# Build image locally
docker build -t ctppo:local .

# Run container
docker run -p 8000:8000 ctppo:local

# Test
curl http://localhost:8000/api/health
```

### Validate Workflow Syntax

```bash
# Install actionlint
brew install actionlint

# Validate workflows
actionlint .github/workflows/*.yml
```

---

## Workflow Files

### Directory Structure

```
.github/
└── workflows/
    ├── ci.yml           # Continuous Integration
    ├── deploy.yml       # Deployment pipeline
    ├── ml-pipeline.yml  # ML model training
    └── codeql.yml       # Code security analysis
```

### Reusable Actions

```yaml
# Example reusable workflow
name: Reusable Build

on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... build steps
```

---

## Monitoring & Alerts

### GitHub Actions Dashboard

- Monitor runs: https://github.com/YOUR_REPO/actions
- View workflow insights
- Download artifacts
- Re-run failed jobs

### Slack Integration

```yaml
- name: Notify Slack
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    fields: repo,message,commit,author
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Email Notifications

Configure in GitHub Settings → Notifications:
- Workflow run failures
- Deployment status
- Security alerts

---

## Best Practices

1. **Keep workflows DRY** - Use reusable workflows and composite actions
2. **Cache dependencies** - Speed up builds with caching
3. **Use matrix builds** - Test across multiple versions
4. **Limit concurrency** - Prevent resource conflicts
5. **Use environments** - Separate staging and production
6. **Require reviews** - Protect production deployments
7. **Monitor costs** - Set usage limits for self-hosted runners

---

## Troubleshooting

### Common Issues

#### Workflow not triggering

```yaml
# Check branch protection rules
# Ensure workflow file is in default branch
# Verify trigger conditions match
```

#### Permission denied

```yaml
# Add permissions block
permissions:
  contents: read
  packages: write
  id-token: write
```

#### Cache miss

```yaml
# Check cache key matches
# Verify cache path exists
# Use fallback keys
```

---

*Last updated: January 2026*

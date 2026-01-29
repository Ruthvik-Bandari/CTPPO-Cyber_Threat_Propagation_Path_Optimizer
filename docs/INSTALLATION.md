# Installation Guide

Complete installation guide for CTPPO (Cyber Threat Propagation Path Optimizer).

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Detailed Installation](#detailed-installation)
- [Docker Installation](#docker-installation)
- [Cloud Deployment](#cloud-deployment)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 20.04+, macOS 12+, Windows 10+ |
| CPU | 4 cores |
| RAM | 8 GB |
| Storage | 10 GB free |
| Python | 3.10+ |
| Node.js | 18+ (or Bun) |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 8+ cores |
| RAM | 16 GB+ |
| GPU | NVIDIA with CUDA (for ML training) |
| Storage | 50 GB SSD |

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer

# Run setup script
chmod +x setup.sh
./setup.sh

# Start application
./start.sh
```

---

## Detailed Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer
```

### Step 2: Backend Setup

#### Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

#### Install Python Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install main dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

#### Configure Environment Variables

```bash
# Copy example env file
cp .env.example .env

# Edit with your settings
nano .env
```

**Required Environment Variables:**

```env
# Application
ENV=development
DEBUG=true
SECRET_KEY=your-secret-key-here

# Database (optional - uses SQLite by default)
DATABASE_URL=sqlite:///./ctppo.db

# JWT Authentication
JWT_SECRET=your-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# NVD API (optional - for CVE data updates)
NVD_API_KEY=your-nvd-api-key
```

### Step 3: Frontend Setup

#### Using Bun (Recommended)

```bash
# Install Bun (if not installed)
curl -fsSL https://bun.sh/install | bash

# Navigate to frontend
cd frontend

# Install dependencies
bun install

# Return to root
cd ..
```

#### Using npm

```bash
cd frontend
npm install
cd ..
```

### Step 4: Initialize ML Models

```bash
# Download pre-trained models (if available)
python -c "from ml.ctppo_ml import download_models; download_models()"

# Or train from scratch (takes ~30 minutes)
python ml/04_train_model.py
```

### Step 5: Start the Application

#### Development Mode

```bash
# Terminal 1: Start Backend
cd api
uvicorn server_secure:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Start Frontend
cd frontend
bun dev
```

#### Production Mode

```bash
# Backend with Gunicorn
gunicorn api.server_secure:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# Frontend build
cd frontend
bun run build
bun run preview
```

### Step 6: Verify Installation

```bash
# Run installation test
python test_installation.py

# Or manually verify
curl http://localhost:8000/api/health
# Should return: {"status": "healthy", "version": "3.0.0"}
```

---

## Docker Installation

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

### Quick Docker Setup

```bash
# Build and start all services
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - ENV=production
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ./models:/app/models
      - ./data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "5173:80"
    depends_on:
      - backend
    environment:
      - VITE_API_URL=http://backend:8000

  # Optional: Redis for caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

### Build Individual Images

```bash
# Build backend
docker build -t ctppo-backend:latest .

# Build frontend
docker build -t ctppo-frontend:latest ./frontend

# Run backend
docker run -p 8000:8000 ctppo-backend:latest

# Run frontend
docker run -p 5173:80 ctppo-frontend:latest
```

---

## Cloud Deployment

### Vercel (Frontend)

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Deploy:
   ```bash
   cd frontend
   vercel --prod
   ```

3. Configure environment variables in Vercel dashboard:
   - `VITE_API_URL`: Your backend API URL

### Google Cloud Run (Backend)

```bash
# Authenticate
gcloud auth login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Build and deploy
gcloud run deploy ctppo-api \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

### AWS EC2

```bash
# SSH into instance
ssh -i your-key.pem ubuntu@your-instance-ip

# Install dependencies
sudo apt update
sudo apt install python3-pip python3-venv nodejs npm

# Clone and setup
git clone https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer
./setup.sh

# Start with PM2
npm install -g pm2
pm2 start ecosystem.config.js
```

### Heroku

```bash
# Login to Heroku
heroku login

# Create app
heroku create ctppo-app

# Set environment variables
heroku config:set SECRET_KEY=your-secret-key
heroku config:set ENV=production

# Deploy
git push heroku main
```

---

## Troubleshooting

### Common Issues

#### 1. Python version error

```
Error: Python 3.10+ required
```

**Solution:**
```bash
# Install Python 3.10+
sudo apt install python3.10 python3.10-venv
python3.10 -m venv venv
```

#### 2. Port already in use

```
Error: Address already in use :8000
```

**Solution:**
```bash
# Find and kill process
lsof -i :8000
kill -9 <PID>

# Or use different port
uvicorn server_secure:app --port 8001
```

#### 3. Module not found

```
ModuleNotFoundError: No module named 'xxx'
```

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

#### 4. CORS errors

```
Access-Control-Allow-Origin error
```

**Solution:**
Add frontend URL to CORS settings in `api/server_secure.py`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://your-domain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### 5. ML model not loading

```
Error: Model file not found
```

**Solution:**
```bash
# Train a new model
python ml/04_train_model.py

# Or download pre-trained models
python -c "from ml.ctppo_ml import download_models; download_models()"
```

### Getting Help

- 📧 Email: bandari.ru@northeastern.edu
- 🐛 Issues: [GitHub Issues](https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer/issues)
- 📖 Documentation: [docs/](./docs/)

---

## Next Steps

After installation:

1. **Create an account** at http://localhost:5173
2. **Explore the dashboard** with demo data
3. **Run your first scan** on a test target
4. **Read the API documentation** at http://localhost:8000/docs
5. **Check out the ML pipeline** for model customization

---

*Last updated: January 2026*

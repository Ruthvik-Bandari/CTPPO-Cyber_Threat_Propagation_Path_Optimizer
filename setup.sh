#!/bin/bash

# ============================================
# CTPPO Setup Script
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║        CTPPO Setup Script                                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

# Create virtual environment
echo -e "${BLUE}Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment created${NC}"

# Upgrade pip
echo -e "${BLUE}Upgrading pip...${NC}"
pip install --upgrade pip

# Install Python dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
pip install -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Check for Node.js or Bun
echo -e "${BLUE}Checking for Node.js/Bun...${NC}"
if command -v bun &> /dev/null; then
    echo -e "${GREEN}✓ Bun found${NC}"
    PACKAGE_MANAGER="bun"
elif command -v node &> /dev/null; then
    NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -ge 18 ]; then
        echo -e "${GREEN}✓ Node.js v$NODE_VERSION found${NC}"
        PACKAGE_MANAGER="npm"
    else
        echo -e "${YELLOW}Warning: Node.js 18+ recommended (found v$NODE_VERSION)${NC}"
        PACKAGE_MANAGER="npm"
    fi
else
    echo -e "${YELLOW}Warning: Neither Bun nor Node.js found. Frontend setup skipped.${NC}"
    echo -e "${YELLOW}Install Bun: curl -fsSL https://bun.sh/install | bash${NC}"
    PACKAGE_MANAGER=""
fi

# Install frontend dependencies
if [ -n "$PACKAGE_MANAGER" ]; then
    echo -e "${BLUE}Installing frontend dependencies...${NC}"
    cd frontend
    $PACKAGE_MANAGER install
    cd ..
    echo -e "${GREEN}✓ Frontend dependencies installed${NC}"
fi

# Create necessary directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p data logs models/severity_classifier reports
echo -e "${GREEN}✓ Directories created${NC}"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${BLUE}Creating .env file...${NC}"
    cat > .env << EOF
# CTPPO Environment Configuration
ENV=development
DEBUG=true

# Security (change in production!)
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Database
DATABASE_URL=sqlite:///./data/ctppo.db

# NVD API (optional)
# NVD_API_KEY=your-nvd-api-key
EOF
    echo -e "${GREEN}✓ .env file created${NC}"
else
    echo -e "${YELLOW}→ .env file already exists, skipping${NC}"
fi

# Make scripts executable
chmod +x start.sh 2>/dev/null || true
chmod +x setup.sh 2>/dev/null || true

# Run installation test
echo -e "${BLUE}Running installation test...${NC}"
python -c "
import sys
try:
    import fastapi
    import uvicorn
    import torch
    import transformers
    print('✓ All core packages imported successfully')
except ImportError as e:
    print(f'✗ Missing package: {e}')
    sys.exit(1)
"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Setup Complete!                              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Review and update ${YELLOW}.env${NC} file with your settings"
echo -e "  2. Run ${YELLOW}./start.sh${NC} to start the application"
echo -e "  3. Open ${BLUE}http://localhost:5173${NC} in your browser"
echo ""
echo -e "For more information, see ${BLUE}docs/INSTALLATION.md${NC}"

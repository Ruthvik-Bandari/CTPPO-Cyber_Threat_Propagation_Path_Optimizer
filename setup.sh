#!/bin/bash
# =============================================================================
# CTPPO - Cyber Threat Propagation Path Optimizer
# Setup Script
# =============================================================================
#
# This script sets up the development environment for CTPPO.
# It ensures reproducible builds by using a lock file and separates
# development dependencies.
#
# Author: Ruthvik, Gemini
# Date: January 2026
# =============================================================================

set -e # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/setup.log"
mkdir -p $LOG_DIR
touch $LOG_FILE

echo -e "${BLUE}"
echo "============================================================================="
echo "  CTPPO - Cyber Threat Propagation Path Optimizer"
echo "  Setup Script v2.0"
echo "============================================================================="
echo -e "${NC}"
echo "Full installation log will be available at: $LOG_FILE"

# Step 1: Check Python version
echo -e "${YELLOW}[Step 1/8] Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 10 ]; then
    echo -e "${GREEN}✓ Python $PYTHON_VERSION detected${NC}"
else
    echo -e "${RED}✗ Python 3.10+ required, found $PYTHON_VERSION${NC}"
    exit 1
fi

# Step 2: Create virtual environment
echo -e "${YELLOW}[Step 2/8] Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Step 3: Activate virtual environment
echo -e "${YELLOW}[Step 3/8] Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Step 4: Upgrade pip
echo -e "${YELLOW}[Step 4/8] Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel >> "$LOG_FILE" 2>&1
echo -e "${GREEN}✓ pip upgraded${NC}"

# Step 5: Install dependencies
echo -e "${YELLOW}[Step 5/8] Installing dependencies...${NC}"
if [ -f "requirements.lock" ]; then
    echo "  -> Found requirements.lock, installing from lock file for reproducibility."
    pip install -r requirements.lock >> "$LOG_FILE" 2>&1
    echo -e "${GREEN}✓ Dependencies installed from lock file${NC}"
else
    echo "  -> requirements.lock not found. Installing from requirements.txt and creating lock file."
    pip install -r requirements.txt >> "$LOG_FILE" 2>&1
    pip freeze > requirements.lock
    echo -e "${GREEN}✓ Dependencies installed and requirements.lock created${NC}"
fi

# Step 6: Install development dependencies
echo -e "${YELLOW}[Step 6/8] Installing development dependencies...${NC}"
if [ -f "requirements-dev.txt" ]; then
    pip install -r requirements-dev.txt >> "$LOG_FILE" 2>&1
    echo -e "${GREEN}✓ Development dependencies installed${NC}"
else
    echo -e "${YELLOW}  -> Skipping: requirements-dev.txt not found.${NC}"
fi

# Step 7: Install package in development mode
echo -e "${YELLOW}[Step 7/8] Installing CTPPO in development mode...${NC}"
pip install -e . >> "$LOG_FILE" 2>&1
echo -e "${GREEN}✓ CTPPO installed${NC}"

# Step 8: Verify installation
echo -e "${YELLOW}[Step 8/8] Verifying installation...${NC}"
python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from core.attack_graph import AttackGraph
    from algorithms.pareto_utils import CostVector
    print('✓ Core modules imported successfully')
except ImportError as e:
    print(f'${RED}✗ Failed to import core modules: {e}${NC}')
    sys.exit(1)
"
echo -e "${GREEN}✓ Verification successful${NC}"


echo ""
echo -e "${GREEN}=============================================================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}=============================================================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run the quick test:"
echo "     python run_quick_test.py"
echo ""
echo "  3. Start Jupyter for interactive exploration:"
echo "     jupyter lab"
echo ""
echo -e "${BLUE}Happy researching! 🔬${NC}"

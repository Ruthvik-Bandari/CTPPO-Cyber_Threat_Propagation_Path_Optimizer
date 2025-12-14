#!/bin/bash
# =============================================================================
# CTPPO - Cyber Threat Propagation Path Optimizer
# Setup Script
# =============================================================================
# 
# This script sets up the development environment for CTPPO.
# Run this script from the project root directory.
#
# Author: Ruthvik
# Date: November 2025
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "============================================================================="
echo "  CTPPO - Cyber Threat Propagation Path Optimizer"
echo "  Setup Script v1.0"
echo "============================================================================="
echo -e "${NC}"

# Step 1: Check Python version
echo -e "${YELLOW}[Step 1/6] Checking Python version...${NC}"
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
echo -e "${YELLOW}[Step 2/6] Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Step 3: Activate virtual environment
echo -e "${YELLOW}[Step 3/6] Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Step 4: Upgrade pip
echo -e "${YELLOW}[Step 4/6] Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
echo -e "${GREEN}✓ pip upgraded${NC}"

# Step 5: Install dependencies
echo -e "${YELLOW}[Step 5/6] Installing dependencies (this may take a few minutes)...${NC}"
pip install -r requirements.txt > /dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 6: Install package in development mode
echo -e "${YELLOW}[Step 6/6] Installing CTPPO in development mode...${NC}"
pip install -e . > /dev/null 2>&1
echo -e "${GREEN}✓ CTPPO installed${NC}"

# Verify installation
echo ""
echo -e "${YELLOW}Verifying installation...${NC}"
python3 -c "
import sys
sys.path.insert(0, '.')
from core import AttackGraph, create_sample_enterprise_graph
from algorithms.pareto_utils import CostVector, ParetoSet
print('✓ Core modules imported successfully')
graph = create_sample_enterprise_graph()
print(f'✓ Sample graph created: {graph.num_nodes} nodes, {graph.num_edges} edges')
"

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
echo "  3. Run the full demo:"
echo "     python run_demo.py"
echo ""
echo "  4. Start Jupyter for interactive exploration:"
echo "     jupyter lab"
echo ""
echo -e "${BLUE}Happy researching! 🔬${NC}"

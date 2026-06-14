#!/bin/bash
# ============================================================================
# CTPPO Transfer Package Creator
# Run this on your Mac to create a package for Alienware
# ============================================================================

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    CTPPO TRANSFER PACKAGE CREATOR                             ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "Project directory: $PROJECT_DIR"
echo ""

# Create transfer directory
TRANSFER_DIR="$PROJECT_DIR/alienware_transfer"
rm -rf "$TRANSFER_DIR"
mkdir -p "$TRANSFER_DIR"

echo "Creating transfer package..."
echo ""

# 1. Copy data (most important!)
echo "📁 Copying data/clean_v3/splits/..."
mkdir -p "$TRANSFER_DIR/data/clean_v3"
cp -r data/clean_v3/splits "$TRANSFER_DIR/data/clean_v3/"

# Verify data
TRAIN_COUNT=$(wc -l < data/clean_v3/splits/train.jsonl 2>/dev/null || echo "0")
VAL_COUNT=$(wc -l < data/clean_v3/splits/val.jsonl 2>/dev/null || echo "0")
TEST_COUNT=$(wc -l < data/clean_v3/splits/test.jsonl 2>/dev/null || echo "0")
echo "   ✓ train.jsonl: $TRAIN_COUNT records"
echo "   ✓ val.jsonl: $VAL_COUNT records"
echo "   ✓ test.jsonl: $TEST_COUNT records"

# 2. Copy ML scripts
echo ""
echo "📁 Copying ml/ scripts..."
mkdir -p "$TRANSFER_DIR/ml"
cp ml/04_train_v3.py "$TRANSFER_DIR/ml/"
cp ml/03_clean_and_label.py "$TRANSFER_DIR/ml/" 2>/dev/null || true
cp ml/02_eda_complete.py "$TRANSFER_DIR/ml/" 2>/dev/null || true
echo "   ✓ 04_train_v3.py (main training script)"

# 3. Copy docs
echo ""
echo "📁 Copying docs/..."
mkdir -p "$TRANSFER_DIR/docs"
cp docs/ALIENWARE_SETUP_GUIDE.md "$TRANSFER_DIR/docs/"
cp docs/ML_MODEL_DEVELOPMENT_GUIDE.md "$TRANSFER_DIR/docs/" 2>/dev/null || true
cp docs/CTPPO_PROJECT_SUMMARY.md "$TRANSFER_DIR/docs/" 2>/dev/null || true
echo "   ✓ ALIENWARE_SETUP_GUIDE.md"

# 4. Create requirements.txt
echo ""
echo "📁 Creating requirements.txt..."
cat > "$TRANSFER_DIR/requirements.txt" << 'EOF'
# CTPPO v3 Requirements
# Install with: pip install -r requirements.txt

# PyTorch (install separately with CUDA)
# pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Transformers
transformers>=4.35.0

# ML utilities
scikit-learn>=1.3.0
numpy>=1.24.0
pandas>=2.0.0

# Progress bars
tqdm>=4.65.0

# Visualization
matplotlib>=3.7.0
seaborn>=0.12.0

# PDF reports
reportlab>=4.0.0
EOF
echo "   ✓ requirements.txt"

# 5. Create quick start script
echo ""
echo "📁 Creating quick_start.sh..."
cat > "$TRANSFER_DIR/quick_start.sh" << 'EOF'
#!/bin/bash
# Quick start script for Alienware
# Run: chmod +x quick_start.sh && ./quick_start.sh

echo "Setting up CTPPO..."

# Check NVIDIA GPU
if ! command -v nvidia-smi &> /dev/null; then
    echo "❌ NVIDIA driver not found. Please install NVIDIA drivers first."
    exit 1
fi

echo "✓ NVIDIA GPU detected:"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

# Create venv if not exists
if [ ! -d "venv" ]; then
    echo ""
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install PyTorch with CUDA
echo ""
echo "Installing PyTorch with CUDA support..."
pip install --upgrade pip
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Check CUDA
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"

# Install other requirements
echo ""
echo "Installing other dependencies..."
pip install -r requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start training, run:"
echo "  source venv/bin/activate"
echo "  python ml/04_train_v3.py --data-dir data/clean_v3/splits --epochs 10 --batch-size 32"
EOF
chmod +x "$TRANSFER_DIR/quick_start.sh"
echo "   ✓ quick_start.sh"

# 6. Create zip file
echo ""
echo "📦 Creating zip archive..."
cd "$PROJECT_DIR"
ZIP_FILE="ctppo_alienware_transfer.zip"
rm -f "$ZIP_FILE"
zip -r "$ZIP_FILE" alienware_transfer/

# Get zip size
ZIP_SIZE=$(du -h "$ZIP_FILE" | cut -f1)

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                         TRANSFER PACKAGE READY!                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📦 Package: $PROJECT_DIR/$ZIP_FILE"
echo "📊 Size: $ZIP_SIZE"
echo ""
echo "Contents:"
echo "  ├── data/clean_v3/splits/     (training data)"
echo "  │   ├── train.jsonl           ($TRAIN_COUNT records)"
echo "  │   ├── val.jsonl             ($VAL_COUNT records)"
echo "  │   └── test.jsonl            ($TEST_COUNT records)"
echo "  ├── ml/04_train_v3.py         (training script)"
echo "  ├── docs/                     (documentation)"
echo "  ├── requirements.txt          (Python dependencies)"
echo "  └── quick_start.sh            (setup script)"
echo ""
echo "📋 Next steps:"
echo "  1. Copy $ZIP_FILE to your Alienware (USB/Cloud/Network)"
echo "  2. On Alienware, extract: unzip ctppo_alienware_transfer.zip"
echo "  3. cd alienware_transfer && chmod +x quick_start.sh && ./quick_start.sh"
echo "  4. Start training!"
echo ""

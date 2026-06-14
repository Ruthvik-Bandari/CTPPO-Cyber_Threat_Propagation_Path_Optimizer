# 🚀 CTPPO Alienware Setup Guide
## Dell Alienware with i9 + RTX 5070 + 64GB RAM

---

## 📋 Quick Overview

Your Alienware specs:
- **CPU:** Intel i9-265H (High Performance)
- **RAM:** 64 GB (Excellent for ML)
- **GPU:** RTX 5070 (~12GB VRAM) - MASSIVE speed boost!

Expected training time:
- **Mac MPS:** ~2 hours/epoch
- **Alienware GPU:** ~15-20 minutes/epoch (6-8x faster!)

---

## 🔧 STEP 1: Install Prerequisites

### Option A: Windows (with WSL2) - RECOMMENDED

```powershell
# 1. Open PowerShell as Administrator

# 2. Install WSL2
wsl --install

# 3. Restart computer, then open Ubuntu from Start Menu

# 4. In Ubuntu terminal, continue with Linux setup below
```

### Option B: Native Windows (Anaconda)

```powershell
# 1. Download and install Anaconda
# https://www.anaconda.com/download

# 2. Download and install CUDA Toolkit 12.x
# https://developer.nvidia.com/cuda-downloads

# 3. Open Anaconda Prompt and continue to Step 2
```

### Option C: Linux (Ubuntu)

```bash
# Already good! Continue to Step 2
```

---

## 🔧 STEP 2: Install NVIDIA Drivers & CUDA

### Check GPU is detected:
```bash
nvidia-smi
```

You should see your RTX 5070 listed. If not:

### Install NVIDIA Driver (Linux/WSL2):
```bash
# Add NVIDIA repository
sudo apt update
sudo apt install -y nvidia-driver-550  # or latest version

# Reboot
sudo reboot

# Verify
nvidia-smi
```

### Install CUDA Toolkit:
```bash
# For Ubuntu/WSL2
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt update
sudo apt install -y cuda-toolkit-12-4

# Add to PATH
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Verify
nvcc --version
```

---

## 🔧 STEP 3: Create Python Environment

```bash
# Install Python 3.10+ if not present
sudo apt install -y python3.10 python3.10-venv python3-pip

# Create project directory
mkdir -p ~/ctppo
cd ~/ctppo

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

---

## 🔧 STEP 4: Install PyTorch with CUDA

```bash
# IMPORTANT: Install PyTorch with CUDA support!
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Verify CUDA is available
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else None}')"
```

Expected output:
```
CUDA available: True
GPU: NVIDIA GeForce RTX 5070
```

---

## 🔧 STEP 5: Install Dependencies

```bash
# Install all required packages
pip install transformers==4.36.0
pip install scikit-learn==1.3.2
pip install pandas numpy
pip install tqdm
pip install matplotlib seaborn
pip install reportlab  # For PDF reports

# Verify transformers
python -c "from transformers import DistilBertTokenizer; print('Transformers OK')"
```

---

## 📁 STEP 6: Copy Files from Mac

### On your Mac, create a zip of required files:

```bash
cd ~/Downloads/ctppo

# Create a transfer package
mkdir -p transfer_package

# Copy essential files
cp -r data/clean_v3 transfer_package/data/
cp -r ml transfer_package/
cp -r docs transfer_package/

# Create zip
zip -r ctppo_transfer.zip transfer_package/
```

### Transfer Options:

**Option 1: USB Drive**
```bash
# Copy to USB on Mac
cp ctppo_transfer.zip /Volumes/USB_DRIVE/

# On Alienware, copy from USB
cp /media/USB_DRIVE/ctppo_transfer.zip ~/
cd ~
unzip ctppo_transfer.zip
mv transfer_package/* ~/ctppo/
```

**Option 2: Cloud Storage (Google Drive, OneDrive)**
- Upload `ctppo_transfer.zip` to cloud
- Download on Alienware
- Extract to `~/ctppo/`

**Option 3: SCP/SSH (if on same network)**
```bash
# On Mac (replace with your Alienware IP)
scp ctppo_transfer.zip username@ALIENWARE_IP:~/
```

---

## 📁 STEP 7: Verify File Structure

On your Alienware, verify:

```bash
cd ~/ctppo
ls -la
```

Should show:
```
ctppo/
├── data/
│   └── clean_v3/
│       └── splits/
│           ├── train.jsonl    (~141K records)
│           ├── val.jsonl      (~17K records)
│           └── test.jsonl     (~17K records)
├── ml/
│   ├── 04_train_v3.py         # Training script
│   └── ...
└── docs/
```

Verify data:
```bash
wc -l data/clean_v3/splits/*.jsonl
```

Expected:
```
  141226 data/clean_v3/splits/train.jsonl
   17652 data/clean_v3/splits/val.jsonl
   17656 data/clean_v3/splits/test.jsonl
```

---

## 🚀 STEP 8: Run Training!

### Activate environment:
```bash
cd ~/ctppo
source venv/bin/activate
```

### Start training with optimal settings:
```bash
python ml/04_train_v3.py \
    --data-dir data/clean_v3/splits \
    --output-dir models/severity_v3 \
    --epochs 10 \
    --batch-size 32
```

### For maximum GPU utilization (if you have enough VRAM):
```bash
python ml/04_train_v3.py \
    --data-dir data/clean_v3/splits \
    --output-dir models/severity_v3 \
    --epochs 10 \
    --batch-size 64
```

---

## 📊 STEP 9: Monitor Training

### In another terminal, monitor GPU:
```bash
watch -n 1 nvidia-smi
```

You should see:
- GPU utilization: 80-100%
- Memory usage: 8-10 GB
- Temperature: 60-80°C (normal)

### Expected output during training:
```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    CTPPO v3.0 - MULTI-MODAL TRAINING                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝

INFO - Using CUDA: NVIDIA GeForce RTX 5070
INFO - CUDA Memory: 12.0 GB

============================================================
Epoch 1/10
============================================================
Training: 100%|██████████████████████| 4413/4413 [15:23<00:00]
Train Loss: 0.8234
Val Loss: 0.6521 | Val Acc: 0.7423 | Val F1: 0.7512

✓ Saved best model (F1: 0.7512)
```

---

## ⚡ Performance Optimization Tips

### 1. Enable Performance Mode (Windows)
```
Settings → System → Power → Performance mode
```

### 2. Alienware Command Center
- Set Thermal Profile to "Performance" or "Full Speed"
- Disable battery optimization while plugged in

### 3. Close unnecessary applications
- Close Chrome, games, etc.
- Maximum resources for training

### 4. Use larger batch size if VRAM allows
```bash
# Try batch size 64 first
python ml/04_train_v3.py --batch-size 64 ...

# If out of memory, fall back to 32
python ml/04_train_v3.py --batch-size 32 ...
```

---

## 🔥 Troubleshooting

### "CUDA out of memory"
```bash
# Reduce batch size
python ml/04_train_v3.py --batch-size 16 ...
```

### "CUDA not available"
```bash
# Check NVIDIA driver
nvidia-smi

# Reinstall PyTorch with CUDA
pip uninstall torch
pip install torch --index-url https://download.pytorch.org/whl/cu124
```

### "Module not found"
```bash
# Make sure venv is activated
source venv/bin/activate

# Reinstall requirements
pip install transformers scikit-learn tqdm
```

### Slow training (GPU not being used)
```bash
# Check if CUDA is being used
python -c "import torch; print(torch.cuda.is_available())"

# Should print: True
```

---

## 📦 After Training: Copy Results Back to Mac

### On Alienware:
```bash
cd ~/ctppo
zip -r training_results.zip models/severity_v3/
```

### Transfer back to Mac via USB/Cloud, then:
```bash
# On Mac
unzip training_results.zip -d ~/Downloads/ctppo/
```

---

## ⏱️ Expected Timeline

| Phase | Mac MPS | Alienware GPU |
|-------|---------|---------------|
| Per Epoch | ~2 hours | ~15-20 min |
| 10 Epochs | ~20 hours | ~2.5-3 hours |
| Full Training | Overnight | Same afternoon! |

---

## 📝 Quick Commands Reference

```bash
# Activate environment
cd ~/ctppo && source venv/bin/activate

# Check GPU
nvidia-smi

# Start training
python ml/04_train_v3.py --data-dir data/clean_v3/splits --epochs 10 --batch-size 32

# Monitor GPU (in another terminal)
watch -n 1 nvidia-smi

# Check training progress
tail -f training.log
```

---

## 🎯 Success Checklist

- [ ] NVIDIA driver installed (`nvidia-smi` works)
- [ ] CUDA toolkit installed (`nvcc --version` works)
- [ ] Python venv created and activated
- [ ] PyTorch with CUDA installed (`torch.cuda.is_available()` = True)
- [ ] Data files copied (train/val/test.jsonl)
- [ ] Training script runs without errors
- [ ] GPU utilization > 80% during training

---

**Good luck! Your Alienware will crush this training! 🚀**

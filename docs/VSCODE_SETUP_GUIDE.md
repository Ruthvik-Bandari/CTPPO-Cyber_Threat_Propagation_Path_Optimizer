# VS Code Setup Guide for CTPPO

## Complete Step-by-Step Instructions

Follow these instructions exactly to set up and run the Cyber Threat Propagation Path Optimizer on your local machine.

---

## Prerequisites

Before starting, ensure you have:
- **Python 3.10 or higher** installed
- **VS Code** installed
- **Git** installed (optional, for version control)

---

## Step 1: Download the Project

### Option A: Download from Claude
1. Click the download button in Claude's interface to get the project files
2. Extract to a folder, e.g., `C:\Projects\cyber_threat_optimizer` (Windows) or `~/Projects/cyber_threat_optimizer` (Mac/Linux)

### Option B: Create manually
Create the folder structure and copy each file from our conversation.

---

## Step 2: Open in VS Code

1. Open VS Code
2. Go to **File → Open Folder**
3. Navigate to and select your `cyber_threat_optimizer` folder
4. Click **Select Folder**

---

## Step 3: Set Up Python Virtual Environment

Open the VS Code integrated terminal:
- **Windows:** Press `Ctrl + `` ` (backtick) or go to **Terminal → New Terminal**
- **Mac:** Press `Cmd + `` ` or go to **Terminal → New Terminal**

Run these commands:

### Windows (PowerShell)
```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1

# If you get an execution policy error, run this first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Windows (Command Prompt)
```cmd
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate.bat
```

### Mac/Linux
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```

You should see `(venv)` at the beginning of your terminal prompt.

---

## Step 4: Install Dependencies

With the virtual environment activated, run:

```bash
# Upgrade pip first
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt
```

This will install:
- numpy, scipy, pandas (scientific computing)
- networkx, igraph (graph processing)
- torch, torch-geometric (deep learning - optional)
- matplotlib, plotly, seaborn (visualization)
- rich (beautiful terminal output)
- And many more...

**Note:** If you encounter errors with `torch-geometric`, you can skip it for now:
```bash
pip install numpy scipy pandas networkx matplotlib plotly seaborn rich loguru pydantic tqdm
```

---

## Step 5: Configure VS Code Python Interpreter

1. Press `Ctrl+Shift+P` (Windows) or `Cmd+Shift+P` (Mac)
2. Type "Python: Select Interpreter"
3. Select the interpreter from your `venv` folder:
   - Windows: `.\venv\Scripts\python.exe`
   - Mac/Linux: `./venv/bin/python`

---

## Step 6: Install Recommended VS Code Extensions

Press `Ctrl+Shift+X` to open Extensions, then install:

1. **Python** (by Microsoft) - Essential
2. **Pylance** (by Microsoft) - Better IntelliSense
3. **Python Debugger** (by Microsoft) - Debugging support
4. **Jupyter** (by Microsoft) - For notebooks
5. **GitLens** (optional) - Git integration

---

## Step 7: Run the Project

### Method 1: Using Terminal (Recommended)
```bash
# Make sure you're in the project directory
cd cyber_threat_optimizer

# Make sure venv is activated (you should see (venv) in prompt)

# Run the main demo
python main.py
```

### Method 2: Using VS Code Run Button
1. Open `main.py` in VS Code
2. Click the **Run** button (▷) in the top right corner
3. Or press `F5` to run with debugger

### Method 3: Run Quick Demo
```bash
python main.py --quick
```

---

## Step 8: Verify Installation

When you run `python main.py`, you should see:

1. A banner with "CTPPO" ASCII art
2. Step-by-step progress messages
3. Tables showing:
   - Attack Graph Statistics
   - NAMOA* Algorithm Results
   - Pareto-Optimal Attack Paths
4. Security analysis insights
5. Export confirmation

If you see all this, **congratulations!** The setup is complete.

---

## Project Structure Explained

```
cyber_threat_optimizer/
│
├── main.py                 # ← RUN THIS FIRST
├── requirements.txt        # Dependencies
├── setup.py               # Package setup
├── README.md              # Project documentation
│
├── core/                  # Core data structures
│   ├── __init__.py
│   ├── attack_graph.py    # Main AttackGraph class
│   ├── node_types.py      # Node definitions
│   ├── edge_costs.py      # Cost distributions
│   └── logging_system.py  # Research logging
│
├── algorithms/            # Path algorithms
│   ├── __init__.py
│   ├── namoa_star.py      # NAMOA* implementation
│   └── pareto_utils.py    # Pareto operations
│
├── logs/                  # Generated logs (created at runtime)
│
└── docs/                  # Documentation
```

---

## Common Issues and Solutions

### Issue 1: "python is not recognized"
**Solution:** Python is not in your PATH. 
- Reinstall Python and check "Add Python to PATH"
- Or use `python3` instead of `python`

### Issue 2: "No module named 'rich'"
**Solution:** Dependencies not installed.
```bash
pip install rich
```

### Issue 3: "venv activation doesn't work on Windows"
**Solution:** Run PowerShell as Administrator and execute:
```powershell
Set-ExecutionPolicy RemoteSigned
```

### Issue 4: "torch installation fails"
**Solution:** PyTorch is optional. Install basic dependencies:
```bash
pip install numpy scipy pandas networkx matplotlib plotly seaborn rich loguru pydantic tqdm psutil
```

### Issue 5: "Import errors when running"
**Solution:** Make sure you're running from the project root directory:
```bash
cd path/to/cyber_threat_optimizer
python main.py
```

---

## Next Steps After Setup

1. **Run the demo:** `python main.py`

2. **Explore the code:**
   - Start with `main.py` to understand the flow
   - Look at `core/attack_graph.py` for graph structure
   - Study `algorithms/namoa_star.py` for the algorithm

3. **Check the logs:**
   - Look in the `logs/` directory after running
   - Each run creates a new experiment folder

4. **Modify and experiment:**
   - Change the sample graph in `create_sample_enterprise_graph()`
   - Adjust algorithm parameters in `namoa_star.py`

5. **Build your research paper:**
   - Use exported metrics from `logs/exp_*/paper_export/`
   - Algorithm decisions are documented in markdown

---

## VS Code Keyboard Shortcuts

| Action | Windows | Mac |
|--------|---------|-----|
| Run Python file | `F5` or `Ctrl+F5` | `F5` or `Cmd+F5` |
| Open terminal | `Ctrl+`` ` | `Cmd+`` ` |
| Command palette | `Ctrl+Shift+P` | `Cmd+Shift+P` |
| Go to definition | `F12` | `F12` |
| Find in files | `Ctrl+Shift+F` | `Cmd+Shift+F` |
| Format document | `Shift+Alt+F` | `Shift+Option+F` |

---

## Getting Help

If you encounter issues:
1. Check the error message carefully
2. Look at the Common Issues section above
3. Make sure your virtual environment is activated
4. Verify you're in the correct directory

Good luck with your research, Ruthvik!

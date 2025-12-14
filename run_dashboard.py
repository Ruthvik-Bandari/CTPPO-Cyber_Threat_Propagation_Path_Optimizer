#!/usr/bin/env python3
"""
CTPPO - Cyber Threat Propagation Path Optimizer
=================================================

Main entry point for the web dashboard.

Usage:
    python run_dashboard.py

Then open http://127.0.0.1:8050 in your browser.

Author: Ruthvik
Institution: Northeastern University
Course: AAI6610 - Applied Machine Learning
Date: November 2025
"""

import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def print_banner():
    """Print startup banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗████████╗██████╗ ██████╗  ██████╗                                  ║
║    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗                                 ║
║    ██║        ██║   ██████╔╝██████╔╝██║   ██║                                 ║
║    ██║        ██║   ██╔═══╝ ██╔═══╝ ██║   ██║                                 ║
║    ╚██████╗   ██║   ██║     ██║     ╚██████╔╝                                 ║
║     ╚═════╝   ╚═╝   ╚═╝     ╚═╝      ╚═════╝                                  ║
║                                                                               ║
║     Cyber Threat Propagation Path Optimizer                                   ║
║     AI-Powered Web Security Assessment Platform                               ║
║                                                                               ║
║     Author: Ruthvik                                                           ║
║     Institution: Northeastern University                                      ║
║     Course: AAI6610 - Applied Machine Learning                                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_dependencies():
    """Check if all required dependencies are installed"""
    required = [
        ('dash', 'dash'),
        ('dash_bootstrap_components', 'dash-bootstrap-components'),
        ('dash_cytoscape', 'dash-cytoscape'),
        ('plotly', 'plotly'),
        ('torch', 'torch'),
        ('numpy', 'numpy'),
        ('networkx', 'networkx'),
        ('scipy', 'scipy'),
    ]
    
    missing = []
    for module, package in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print("❌ Missing dependencies:")
        for pkg in missing:
            print(f"   - {pkg}")
        print("\nInstall them with:")
        print(f"   pip install {' '.join(missing)}")
        return False
    
    print("✓ All dependencies installed")
    return True


def main():
    """Main entry point"""
    print_banner()
    
    print("\n🔍 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    
    print("\n🚀 Starting web dashboard...")
    print("\n" + "="*60)
    print("  Open your browser to: http://127.0.0.1:8050")
    print("  Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    # Import and run the dashboard
    from dashboard.app import app
    app.run(debug=True, host='127.0.0.1', port=8050)


if __name__ == '__main__':
    main()

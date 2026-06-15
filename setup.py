"""
Setup script for Cyber Threat Propagation Path Optimizer (CTPPO)

A Multi-Objective, Probabilistic, Dynamic Shortest-Path Engine for Attack Graph Analysis
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cyber-threat-optimizer",
    version="1.0.0",
    author="Ruthvik",
    author_email="",
    description="Multi-Objective Probabilistic Framework for Cyber Threat Propagation Path Optimization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ruthvik/cyber-threat-optimizer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "isort>=5.12.0",
            "mypy>=1.4.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ctppo-cli=cli.main:main",   # local-first, no-auth CLI client
        ],
    },
)

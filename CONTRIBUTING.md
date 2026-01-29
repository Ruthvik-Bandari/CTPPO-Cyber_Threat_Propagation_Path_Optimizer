# Contributing to CTPPO

Thank you for your interest in contributing to CTPPO! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please be kind and constructive in all interactions.

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+ or Bun
- Git
- Docker (optional)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
   cd CTPPO-Cyber_Threat_Propagation_Path_Optimizer
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer.git
   ```

---

## Development Setup

### Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Frontend Setup

```bash
cd frontend

# Using Bun (recommended)
bun install

# Or using npm
npm install
```

### Running the Development Server

```bash
# Terminal 1: Backend
cd api
uvicorn server_secure:app --reload --port 8000

# Terminal 2: Frontend
cd frontend
bun dev
```

---

## Making Changes

### Branch Naming Convention

Use descriptive branch names:

- `feature/add-new-scanner` - New features
- `fix/cve-classifier-bug` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/api-cleanup` - Code refactoring
- `test/add-ml-tests` - Adding tests

### Commit Message Format

Follow conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(api): add batch CVE classification endpoint

fix(scanner): handle timeout for slow targets

docs(readme): update installation instructions
```

---

## Pull Request Process

### Before Submitting

1. **Update your branch:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests:**
   ```bash
   pytest
   ```

3. **Run linting:**
   ```bash
   flake8 .
   black --check .
   ```

4. **Update documentation** if needed

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe how you tested the changes

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No new warnings
```

### Review Process

1. PRs require at least one approval
2. All CI checks must pass
3. Address all review comments
4. Squash commits before merge

---

## Coding Standards

### Python

- Follow PEP 8 style guide
- Use type hints
- Maximum line length: 100 characters
- Use docstrings for functions/classes

```python
def classify_cve(description: str, model: Optional[str] = None) -> dict:
    """
    Classify a CVE description by severity.
    
    Args:
        description: The CVE description text
        model: Optional model name to use
        
    Returns:
        Dictionary with severity and confidence
        
    Raises:
        ValueError: If description is empty
    """
    if not description:
        raise ValueError("Description cannot be empty")
    # Implementation...
```

### TypeScript/React

- Use functional components with hooks
- Use TypeScript strict mode
- Follow ESLint configuration
- Use TailwindCSS for styling

```typescript
interface Props {
  title: string;
  onSubmit: (data: FormData) => Promise<void>;
}

export function ScanForm({ title, onSubmit }: Props) {
  const [loading, setLoading] = useState(false);
  
  const handleSubmit = async (data: FormData) => {
    setLoading(true);
    try {
      await onSubmit(data);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    // JSX...
  );
}
```

---

## Testing Guidelines

### Backend Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test
pytest tests/ml/test_classifier.py -v

# Run only fast tests
pytest -m "not slow"
```

### Writing Tests

```python
import pytest
from api.server_secure import classify_cve

class TestCVEClassifier:
    """Tests for CVE classification."""
    
    def test_classify_valid_cve(self):
        """Test classification with valid description."""
        result = classify_cve("SQL injection vulnerability")
        assert result["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert 0 <= result["confidence"] <= 1
    
    def test_classify_empty_raises_error(self):
        """Test that empty description raises ValueError."""
        with pytest.raises(ValueError):
            classify_cve("")
    
    @pytest.mark.slow
    def test_batch_classification(self):
        """Test batch classification (slow test)."""
        # ...
```

### Frontend Tests

```bash
cd frontend

# Run tests
bun test

# Run with coverage
bun test --coverage
```

---

## Project Structure

```
CTPPO/
├── api/                 # FastAPI backend
├── frontend/            # React frontend
├── ml/                  # ML pipelines
├── algorithms/          # Core algorithms
├── models/              # Trained models
├── tests/               # Test suite
├── docs/                # Documentation
└── .github/             # CI/CD workflows
```

---

## Need Help?

- 📧 Email: bandari.ru@northeastern.edu
- 🐛 Issues: [GitHub Issues](https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Ruthvik-Bandari/CTPPO-Cyber_Threat_Propagation_Path_Optimizer/discussions)

---

Thank you for contributing to CTPPO! 🎉

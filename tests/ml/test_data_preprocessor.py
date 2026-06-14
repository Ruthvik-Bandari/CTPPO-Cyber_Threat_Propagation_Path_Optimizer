"""
Unit Tests for DataPreprocessor
"""

import pytest
import pandas as pd
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Conditional import to avoid errors if torch/transformers are not in the test environment
try:
    from ml.data_preprocessor import DataPreprocessor, MODELS_AVAILABLE
except ImportError:
    # Handle case where dependencies might not be installed in a pure test-runner environment
    # This allows collection of other tests to proceed.
    pytest.skip("Skipping DataPreprocessor tests: PyTorch/Transformers not found", allow_module_level=True)


@pytest.fixture
def preprocessor() -> DataPreprocessor:
    """Provides a DataPreprocessor instance for testing."""
    return DataPreprocessor()

def test_clean_text(preprocessor: DataPreprocessor):
    """Test the text cleaning and normalization logic."""
    raw_text = "See https://example.com for info. Email support@test.com. CRITICAL issue!"
    expected_text = "see for info email critical issue"
    cleaned = preprocessor.clean_text(raw_text)
    assert cleaned == expected_text

    raw_text_2 = "SQL Injection in 'user-profile' page."
    expected_text_2 = "sql injection in user-profile page"
    cleaned_2 = preprocessor.clean_text(raw_text_2)
    assert cleaned_2 == expected_text_2

def test_extract_features_fallback(preprocessor: DataPreprocessor):
    """
    Test feature extraction, specifically the CVSS-based fallback for severity
    when a model is not available.
    """
    # Temporarily disable model to test fallback
    preprocessor.severity_model = None
    
    mock_cve_data = [
        {"id": "CVE-1", "description": "High severity issue", "cvss_v3": 8.0, "attackVector": "NETWORK", "vendor": "Test Inc.", "product": "P1"},
        {"id": "CVE-2", "description": "Low severity issue", "cvss_v3": 2.5, "attackVector": "LOCAL", "vendor": "Test Corp", "product": "P2"},
    ]
    
    df = preprocessor.extract_features(mock_cve_data)
    
    assert 'id' in df.columns
    assert 'severity_class' in df.columns
    assert 'severity_source' in df.columns
    
    # Check fallback behavior
    assert df.loc[df['id'] == 'CVE-1', 'severity_class'].iloc[0] == 'HIGH'
    assert df.loc[df['id'] == 'CVE-1', 'severity_source'].iloc[0] == 'cvss'
    assert df.loc[df['id'] == 'CVE-2', 'severity_class'].iloc[0] == 'LOW'
    assert df.loc[df['id'] == 'CVE-2', 'severity_source'].iloc[0] == 'cvss'

@pytest.mark.skipif(not MODELS_AVAILABLE, reason="PyTorch/Transformers not installed")
def test_extract_features_model_prediction(preprocessor: DataPreprocessor, mocker):
    """
    Test that feature extraction correctly uses the ML model for severity prediction.
    Mocks the model's output to avoid running the actual transformer.
    """
    # Ensure model is "available" for this test
    if not preprocessor.severity_model:
        pytest.skip("Severity model not loaded, skipping test.")

    # Mock the predict_severity method
    mock_predictions = ["CRITICAL", "MEDIUM"]
    mocker.patch.object(preprocessor, 'predict_severity', return_value=mock_predictions)
    
    mock_cve_data = [
        {"id": "CVE-1", "description": "Some critical issue", "cvss_v3": 9.8, "attackVector": "NETWORK", "vendor": "Test Inc.", "product": "P1"},
        {"id": "CVE-2", "description": "A medium issue", "cvss_v3": 5.0, "attackVector": "LOCAL", "vendor": "Test Corp", "product": "P2"},
    ]
    
    df = preprocessor.extract_features(mock_cve_data)

    preprocessor.predict_severity.assert_called_once()
    
    # Check that the model's output was used
    assert df.loc[df['id'] == 'CVE-1', 'severity_class'].iloc[0] == 'CRITICAL'
    assert df.loc[df['id'] == 'CVE-1', 'severity_source'].iloc[0] == 'model'
    assert df.loc[df['id'] == 'CVE-2', 'severity_class'].iloc[0] == 'MEDIUM'
    assert df.loc[df['id'] == 'CVE-2', 'severity_source'].iloc[0] == 'model'

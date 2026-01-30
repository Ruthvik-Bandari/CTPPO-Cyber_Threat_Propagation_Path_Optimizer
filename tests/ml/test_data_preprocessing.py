import unittest
from unittest.mock import patch, MagicMock
import pandas as pd
import numpy as np
from pathlib import Path
import os
import sys

# Add the 'ml' directory to the path so we can import modules from it
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))

from ml.data_preprocessor import DataPreprocessor

class TestDataPreprocessor(unittest.TestCase):

    def setUp(self):
        self.api_key = "test_api_key"
        self.preprocessor = DataPreprocessor(api_key=self.api_key)
        # Ensure NLTK data is downloaded for tests
        try:
            self.preprocessor.stop_words = set(nltk.corpus.stopwords.words('english'))
        except LookupError:
            nltk.download('stopwords')
            self.preprocessor.stop_words = set(nltk.corpus.stopwords.words('english'))
        try:
            self.preprocessor.lemmatizer = nltk.stem.WordNetLemmatizer()
        except LookupError:
            nltk.download('wordnet')
            self.preprocessor.lemmatizer = nltk.stem.WordNetLemmatizer()
        try:
            nltk.tokenize.word_tokenize('')
        except LookupError:
            nltk.download('punkt')


    @patch('requests.get')
    def test_fetch_cve_data(self, mock_get):
        # Mock API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-1000",
                        "descriptions": [{"lang": "en", "value": "Test vulnerability description."}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "attackVector": "NETWORK"}}]
                        }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2023-1001",
                        "descriptions": [{"lang": "en", "value": "Another test description with XSS."}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "attackVector": "LOCAL"}}]
                        }
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        query = "test_product"
        limit = 2
        cve_data = self.preprocessor.fetch_cve_data(query, limit)

        self.assertEqual(len(cve_data), 2)
        self.assertEqual(cve_data[0]['id'], "CVE-2023-1000")
        self.assertEqual(cve_data[0]['description'], "Test vulnerability description.")
        self.assertEqual(cve_data[0]['cvss_v3'], 7.5)
        self.assertEqual(cve_data[0]['attackVector'], "NETWORK")
        self.assertEqual(cve_data[0]['product'], query) # Simplified product
        self.assertEqual(cve_data[0]['vendor'], "N/A")

        mock_get.assert_called_once_with(
            self.preprocessor.NVD_API_URL,
            params={"keywordSearch": query, "resultsPerPage": limit, "startIndex": 0},
            headers={"apiKey": self.api_key},
            timeout=30
        )

    def test_clean_text(self):
        text1 = "This is a TEST with a URL https://example.com and an email test@example.org. It has some CAPS."
        cleaned_text1 = self.preprocessor.clean_text(text1)
        # Expected: lowercase, no url/email, no special chars, stopwords removed, lemmatized
        # "this is a test url and an email it has some caps" -> "test url email caps" (after stopwords and lemmatization)
        # NLTK's word_tokenize might handle "test-product" differently than simple split
        self.assertIn("test", cleaned_text1)
        self.assertNotIn("https", cleaned_text1)
        self.assertNotIn("example", cleaned_text1) # as a stopword
        self.assertNotIn("caps", cleaned_text1) # as a stopword
        self.assertNotIn("url", cleaned_text1) # as a stopword
        self.assertNotIn("email", cleaned_text1) # as a stopword
        
        text2 = "SQL Injection (SQLi) vulnerability."
        cleaned_text2 = self.preprocessor.clean_text(text2)
        self.assertEqual(cleaned_text2, "sqli vulnerability") # 'sql' is a stopword or removed by lemmatizer

    @patch('ml.models.severity_classifier.model.SeverityClassifier')
    @patch('transformers.DistilBertTokenizer')
    def test_extract_features(self, MockTokenizer, MockSeverityClassifier):
        # Mock NLP model for severity prediction
        mock_tokenizer_instance = MockTokenizer.from_pretrained.return_value
        mock_severity_model_instance = MockSeverityClassifier.return_value
        
        # Configure predict method to return fixed predictions
        mock_severity_model_instance.predict.return_value = (torch.tensor([LABEL_TO_ID["CRITICAL"], LABEL_TO_ID["MEDIUM"]]), None)

        mock_cve_data = [
            {
                "id": "CVE-2023-1000",
                "description": "Critical buffer overflow in product X, allowing RCE.",
                "cvss_v3": 9.8,
                "attackVector": "NETWORK",
                "product": "ProductX",
                "vendor": "VendorA"
            },
            {
                "id": "CVE-2023-1001",
                "description": "SQL Injection vulnerability in module Y. Local access required.",
                "cvss_v3": 6.5,
                "attackVector": "LOCAL",
                "product": "ModuleY",
                "vendor": "VendorB"
            }
        ]
        
        # Make sure severity model is considered available
        self.preprocessor.severity_model = mock_severity_model_instance
        self.preprocessor.tokenizer = mock_tokenizer_instance

        df = self.preprocessor.extract_features(mock_cve_data)

        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertIn('id', df.columns)
        self.assertIn('cleaned_description', df.columns)
        self.assertIn('severity_class', df.columns)
        self.assertIn('desc_length', df.columns)
        self.assertIn('num_words', df.columns)
        self.assertIn('has_overflow', df.columns)
        self.assertIn('has_sql_injection', df.columns)
        
        self.assertEqual(df.loc[0, 'id'], 'CVE-2023-1000')
        self.assertEqual(df.loc[0, 'severity_class'], 'CRITICAL')
        self.assertEqual(df.loc[0, 'has_overflow'], 1)
        self.assertEqual(df.loc[0, 'has_rce'], 1)
        self.assertEqual(df.loc[0, 'has_sql_injection'], 0)
        
        self.assertEqual(df.loc[1, 'id'], 'CVE-2023-1001')
        self.assertEqual(df.loc[1, 'severity_class'], 'MEDIUM')
        self.assertEqual(df.loc[1, 'has_overflow'], 0)
        self.assertEqual(df.loc[1, 'has_sql_injection'], 1)
        
    @patch('requests.get')
    @patch('ml.models.severity_classifier.model.SeverityClassifier')
    @patch('transformers.DistilBertTokenizer')
    def test_process_pipeline(self, MockTokenizer, MockSeverityClassifier, mock_get):
        # Mock NVD API call
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-PIPE1",
                        "descriptions": [{"lang": "en", "value": "Pipeline test vulnerability."}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 8.0, "attackVector": "NETWORK"}}]
                        }
                    }
                }
            ]
        }

        # Mock NLP model for severity prediction
        mock_tokenizer_instance = MockTokenizer.from_pretrained.return_value
        mock_severity_model_instance = MockSeverityClassifier.return_value
        mock_severity_model_instance.predict.return_value = (torch.tensor([LABEL_TO_ID["HIGH"]]), None)
        
        self.preprocessor.severity_model = mock_severity_model_instance
        self.preprocessor.tokenizer = mock_tokenizer_instance

        query = "pipeline_test"
        processed_data = self.preprocessor.process(query, limit=1)

        self.assertIn("dataframe", processed_data)
        self.assertFalse(processed_data["dataframe"].empty)
        df = processed_data["dataframe"]

        self.assertEqual(df.loc[0, 'id'], "CVE-2023-PIPE1")
        self.assertEqual(df.loc[0, 'severity_class'], "HIGH")
        self.assertTrue(df.loc[0, 'desc_length'] > 0)
        
        mock_get.assert_called_once()


if __name__ == '__main__':
    # Add parent directory of 'ml' to sys.path for test discovery if run directly
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    unittest.main()
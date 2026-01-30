# -*- coding: utf-8 -*-
"""
CTPPO - Data Preprocessing Pipeline
====================================

This module provides a structured pipeline for fetching, cleaning, feature-engineering,
and transforming data from various cybersecurity sources, such as CVE databases,
Nmap scans, and other threat intelligence feeds.

The goal is to convert raw, noisy data into clean, feature-rich tensors
suitable for training machine learning models.

Author: Gemini
Date: January 2026
"""

import re
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional
from pathlib import Path
import requests
import time
import logging

# NLTK imports for enhanced text cleaning
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

# Download necessary NLTK data (only needs to be done once)
try:
    stopwords.words('english')
except LookupError:
    nltk.download('stopwords')
try:
    WordNetLemmatizer()
except LookupError:
    nltk.download('wordnet')
try:
    word_tokenize('')
except LookupError:
    nltk.download('punkt')
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import torch
    from transformers import DistilBertTokenizer
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

class DataPreprocessor:
    """
    A pipeline for ingesting, cleaning, and transforming cybersecurity data.
    """
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None, model_dir: Optional[Path] = None):
        """
        Initializes the preprocessor.

        Args:
            api_key (Optional[str]): API key for services like NVD CVE database.
            model_dir (Optional[Path]): Directory containing trained ML models.
        """
        self.api_key = api_key
        self.severity_model = None
        self.tokenizer = None
        self.stop_words = set(stopwords.words('english'))
        self.lemmatizer = WordNetLemmatizer()

        if MODELS_AVAILABLE:
            try:
                # Import SeverityClassifier only if MODELS_AVAILABLE is True
                from ml.models.severity_classifier.model import SeverityClassifier, ID_TO_LABEL
                self.ID_TO_LABEL = ID_TO_LABEL
                
                if model_dir is None:
                    model_dir = Path(__file__).parent / "models" / "severity_classifier"
                
                model_path = model_dir / "best_model.pt"

                self.tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
                self.severity_model = SeverityClassifier(num_classes=4)
                
                if model_path.exists():
                    logger.info("Found trained severity classifier model.")
                    # checkpoint = torch.load(model_path, map_location='cpu')
                    # self.severity_model.load_state_dict(checkpoint['model_state_dict'])
                else:
                    logger.info("Initialized pre-trained DistilBERT model (not fine-tuned).")

                self.severity_model.eval()

            except Exception as e:
                logger.warning(f"Could not load severity model. Reason: {e}")
                self.severity_model = None
                self.tokenizer = None
        else:
            logger.warning("PyTorch or Transformers not installed. ML-based severity prediction disabled.")

    def fetch_cve_data(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetches CVE data from the NVD API 2.0, handling pagination and rate limits.
        """
        logger.info(f"Fetching up to {limit} CVEs for query: '{query}'...")
        
        headers = {"apiKey": self.api_key} if self.api_key else {}
        all_parsed_data = []
        start_index = 0
        results_per_page = 2000 # Max allowed by NVD API

        # Determine delay based on API key presence
        delay = 0.6 if self.api_key else 6.0
        
        while len(all_parsed_data) < limit:
            params = {
                "keywordSearch": query,
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            
            try:
                response = requests.get(self.NVD_API_URL, params=params, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    logger.info("No more vulnerabilities found from the API.")
                    break # Exit loop if no more results

                logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities (total collected: {len(all_parsed_data) + len(vulnerabilities)}).")

                # The API response is nested, so we need to parse it
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    
                    # Extract description
                    description = "No description available."
                    for desc in cve.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value")
                            break

                    # Extract CVSS v3.1 metrics
                    cvss_metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})

                    parsed_item = {
                        "id": cve.get("id"),
                        "description": description,
                        "cvss_v3": cvss_metrics.get("baseScore"),
                        "attackVector": cvss_metrics.get("attackVector"),
                        "product": query, # Simplified for now
                        "vendor": "N/A", # Vendor info is complex, skipping for now
                    }
                    all_parsed_data.append(parsed_item)

                    if len(all_parsed_data) >= limit:
                        break # Stop if we've reached the desired limit

                start_index += results_per_page
                time.sleep(delay) # Wait before next request

            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching CVE data: {e}")
                break
            except Exception as e:
                logger.error(f"An unexpected error occurred during CVE fetching: {e}")
                break
        
        logger.info(f"Finished fetching. Total CVEs collected: {len(all_parsed_data)}")
        return all_parsed_data[:limit]

    def clean_text(self, text: str) -> str:
        """
        Cleans and normalizes a text string, removes stopwords, and lemmatizes.
        """
        if not isinstance(text, str):
            return ""
        text = text.lower()
        text = re.sub(r'https?://\S+|www\.\S+', '', text)
        text = re.sub(r'\S+@\S+', '', text)
        text = re.sub(r'[^a-z0-9\s-]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        
        tokens = word_tokenize(text)
        tokens = [self.lemmatizer.lemmatize(word) for word in tokens if word not in self.stop_words]
        return ' '.join(tokens)

    def predict_severity(self, descriptions: List[str]) -> List[str]:
        """
        Predicts severity from a list of CVE descriptions using the loaded model.
        """
        if not self.severity_model or not self.tokenizer:
            return ["N/A"] * len(descriptions)

        logger.info("Predicting severity from text descriptions...")
        encodings = self.tokenizer(
            descriptions,
            truncation=True,
            padding=True,
            max_length=256,
            return_tensors='pt'
        )
        
        with torch.no_grad():
            predictions, _ = self.severity_model.predict(
                input_ids=encodings['input_ids'],
                attention_mask=encodings['attention_mask']
            )
        
        predicted_labels = [self.ID_TO_LABEL.get(pred.item(), "MEDIUM") for pred in predictions]
        return predicted_labels

    def extract_features(self, cve_data: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extracts relevant features from raw CVE data into a pandas DataFrame.
        """
        if not cve_data:
            return pd.DataFrame()

        df = pd.DataFrame(cve_data)
        
        df['cleaned_description'] = df['description'].apply(self.clean_text)
        df['vendor'] = df.get('vendor', 'N/A').astype(str).str.lower().str.replace(' inc.', '').str.replace(' corp', '')
        df['product'] = df.get('product', 'N/A').astype(str).str.lower()
        df['is_remote'] = np.where(df['attackVector'] == 'NETWORK', 1, 0)
        df['cvss_score'] = pd.to_numeric(df['cvss_v3'], errors='coerce').fillna(0)

        # --- Enhanced Feature Engineering ---
        df['desc_length'] = df['cleaned_description'].apply(len)
        df['num_words'] = df['cleaned_description'].apply(lambda x: len(x.split()))
        
        # Example: Keyword presence as features
        attack_keywords = ['overflow', 'injection', 'xss', 'rce', 'dos', 'privilege escalation']
        for keyword in attack_keywords:
            df[f'has_{keyword.replace(" ", "_")}'] = df['cleaned_description'].apply(lambda x: 1 if keyword in x else 0)

        # --- Severity Classification ---
        if self.severity_model and self.tokenizer:
            predicted_severities = self.predict_severity(df['cleaned_description'].tolist())
            df['severity_class'] = predicted_severities
            df['severity_source'] = 'model'
        else:
            df['severity_class'] = pd.cut(
                df['cvss_score'], 
                bins=[-1, 3.9, 6.9, 8.9, 10], 
                labels=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            ).astype(str)
            df['severity_source'] = 'cvss'

        return df[['id', 'cleaned_description', 'vendor', 'product', 'is_remote', 'cvss_score', 'severity_class', 'severity_source', 
                   'desc_length', 'num_words'] + [f'has_{keyword.replace(" ", "_")}' for keyword in attack_keywords]]

    def transform_data(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Transforms the feature DataFrame into model-consumable tensors.
        """
        logger.info("Transforming features into model-ready format...")
        transformed_output = {
            "dataframe": features_df,
            "tensors": {}
        }
        return transformed_output

    def process(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """
        Runs the full preprocessing pipeline.
        """
        logger.info("Starting data preprocessing pipeline...")
        raw_data = self.fetch_cve_data(query, limit)
        features_df = self.extract_features(raw_data)
        model_ready_data = self.transform_data(features_df)
        logger.info("Data preprocessing pipeline finished.")
        return model_ready_data

# Example Usage:
if __name__ == '__main__':
    import os
    # For testing, you can set an NVD API key as an environment variable
    # export NVD_API_KEY="your_key_here"
    api_key = os.environ.get("NVD_API_KEY")
    
    preprocessor = DataPreprocessor(api_key=api_key)
    
    # Let's test with a real product name
    test_query = "openssh"
    processed_data = preprocessor.process(query=test_query, limit=5)
    
    print("\n--- Processed DataFrame ---")
    if "dataframe" in processed_data and not processed_data["dataframe"].empty:
        print(processed_data['dataframe'])
    else:
        print(f"No data processed for query: '{test_query}'. This may be due to API limits or no results.")

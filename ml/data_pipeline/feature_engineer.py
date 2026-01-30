# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Feature Engineer
=============================

Comprehensive feature engineering for CVE data.

Feature Categories:
1. Text features (for NLP models)
2. Numerical features (CVSS components, counts)
3. Categorical features (attack vector, CWE)
4. Derived features (risk indicators)
5. Temporal features (age, recency)
6. Graph features (for GNN models)

Author: Ruthvik (Fixed by Claude)
Date: January 2026
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Attack type keywords for classification
ATTACK_TYPE_KEYWORDS = {
    'injection': ['injection', 'sqli', 'sql injection', 'command injection', 
                  'ldap injection', 'xpath injection', 'nosql injection'],
    'xss': ['xss', 'cross-site scripting', 'cross site scripting', 'script injection'],
    'buffer_overflow': ['buffer overflow', 'stack overflow', 'heap overflow', 
                        'integer overflow', 'memory corruption'],
    'rce': ['remote code execution', 'rce', 'arbitrary code', 'code execution'],
    'dos': ['denial of service', 'dos', 'ddos', 'resource exhaustion', 'crash'],
    'auth_bypass': ['authentication bypass', 'auth bypass', 'authorization bypass',
                    'privilege escalation', 'access control'],
    'info_disclosure': ['information disclosure', 'data leak', 'sensitive data',
                        'information leak', 'data exposure'],
    'traversal': ['path traversal', 'directory traversal', 'lfi', 'rfi',
                  'file inclusion', 'file read'],
    'csrf': ['csrf', 'cross-site request forgery', 'request forgery'],
    'ssrf': ['ssrf', 'server-side request forgery']
}

# CWE to attack type mapping (top CWEs)
CWE_ATTACK_MAPPING = {
    'CWE-79': 'xss',
    'CWE-89': 'injection',
    'CWE-787': 'buffer_overflow',
    'CWE-125': 'buffer_overflow',
    'CWE-416': 'buffer_overflow',
    'CWE-190': 'buffer_overflow',
    'CWE-20': 'injection',
    'CWE-22': 'traversal',
    'CWE-352': 'csrf',
    'CWE-918': 'ssrf',
    'CWE-94': 'rce',
    'CWE-78': 'rce',
    'CWE-287': 'auth_bypass',
    'CWE-200': 'info_disclosure',
    'CWE-400': 'dos',
    'CWE-502': 'rce',
}


@dataclass
class FeatureSet:
    """Complete feature set for a CVE record."""
    
    # Identifier
    cve_id: str
    
    # Text features (for BERT/transformer models)
    text: str
    text_tokens: Optional[List[int]] = None
    attention_mask: Optional[List[int]] = None
    
    # Numerical features
    numerical_features: Dict[str, float] = field(default_factory=dict)
    
    # Categorical features (one-hot or label encoded)
    categorical_features: Dict[str, Any] = field(default_factory=dict)
    
    # Target label
    severity_label: Optional[str] = None
    severity_id: Optional[int] = None
    
    # Feature vector for traditional ML
    feature_vector: Optional[np.ndarray] = None


class FeatureEngineer:
    """
    Comprehensive feature engineering for CVE data.
    
    Creates rich feature representations for multiple model types:
    - Text features for transformers
    - Numerical features for traditional ML
    - Graph features for GNNs
    """
    
    # Severity label mapping
    SEVERITY_TO_ID = {
        'CRITICAL': 3,
        'HIGH': 2,
        'MEDIUM': 1,
        'LOW': 0,
        'NONE': 0,
        'UNKNOWN': -1
    }
    
    # CVSS vector component mappings
    ATTACK_VECTOR_MAP = {'NETWORK': 1.0, 'ADJACENT_NETWORK': 0.75, 'LOCAL': 0.5, 'PHYSICAL': 0.25}
    ATTACK_COMPLEXITY_MAP = {'LOW': 1.0, 'HIGH': 0.5}
    PRIVILEGES_REQUIRED_MAP = {'NONE': 1.0, 'LOW': 0.5, 'HIGH': 0.25}
    USER_INTERACTION_MAP = {'NONE': 1.0, 'REQUIRED': 0.5}
    SCOPE_MAP = {'CHANGED': 1.0, 'UNCHANGED': 0.5}
    IMPACT_MAP = {'HIGH': 1.0, 'LOW': 0.5, 'NONE': 0.0}
    
    def __init__(
        self,
        include_text_stats: bool = True,
        include_cvss_components: bool = True,
        include_temporal: bool = True,
        include_attack_type: bool = True,
        reference_date: Optional[datetime] = None
    ):
        """
        Initialize feature engineer.
        
        Args:
            include_text_stats: Include text-based statistics
            include_cvss_components: Include CVSS vector components
            include_temporal: Include temporal features
            include_attack_type: Include attack type classification
            reference_date: Reference date for temporal features
        """
        self.include_text_stats = include_text_stats
        self.include_cvss_components = include_cvss_components
        self.include_temporal = include_temporal
        self.include_attack_type = include_attack_type
        self.reference_date = reference_date or datetime.now()
    
    def _extract_text_features(
        self, 
        text: str, 
        metadata: Optional[Dict] = None
    ) -> Dict[str, float]:
        """Extract numerical features from text."""
        features = {}
        
        if not text:
            return features
        
        # Basic text statistics
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['avg_word_length'] = (
            features['text_length'] / max(1, features['word_count'])
        )
        
        # Use metadata if available
        if metadata:
            features['url_count'] = len(metadata.get('extracted_urls', []))
            features['cve_ref_count'] = len(metadata.get('extracted_cves', []))
            features['cwe_ref_count'] = len(metadata.get('extracted_cwes', []))
            features['version_count'] = len(metadata.get('extracted_versions', []))
            features['has_code_snippet'] = float(metadata.get('has_code_snippet', False))
            features['has_exploit_mention'] = float(metadata.get('has_exploit_mention', False))
            features['has_patch_mention'] = float(metadata.get('has_patch_mention', False))
        
        # Security keyword counts
        text_lower = text.lower()
        for attack_type, keywords in ATTACK_TYPE_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            features[f'keyword_{attack_type}'] = float(count > 0)
        
        return features
    
    def _extract_cvss_features(self, record: Dict) -> Dict[str, float]:
        """Extract features from CVSS data."""
        features = {}
        
        # CVSS score
        cvss_score = record.get('cvss_score')
        features['cvss_score'] = cvss_score if cvss_score is not None else 5.0
        features['cvss_normalized'] = features['cvss_score'] / 10.0
        features['cvss_missing'] = float(cvss_score is None)
        
        # CVSS vector components
        cvss_vector = record.get('cvss_vector', {})
        if isinstance(cvss_vector, dict) or hasattr(cvss_vector, '__dict__'):
            if hasattr(cvss_vector, '__dict__'):
                cvss_vector = cvss_vector.__dict__
            
            # Attack Vector
            av = cvss_vector.get('attack_vector')
            features['av_score'] = self.ATTACK_VECTOR_MAP.get(av, 0.5)
            features['is_network_attack'] = float(av == 'NETWORK')
            features['is_local_attack'] = float(av in ['LOCAL', 'PHYSICAL'])
            
            # Attack Complexity
            ac = cvss_vector.get('attack_complexity')
            features['ac_score'] = self.ATTACK_COMPLEXITY_MAP.get(ac, 0.5)
            features['is_low_complexity'] = float(ac == 'LOW')
            
            # Privileges Required
            pr = cvss_vector.get('privileges_required')
            features['pr_score'] = self.PRIVILEGES_REQUIRED_MAP.get(pr, 0.5)
            features['requires_no_privs'] = float(pr == 'NONE')
            
            # User Interaction
            ui = cvss_vector.get('user_interaction')
            features['ui_score'] = self.USER_INTERACTION_MAP.get(ui, 0.5)
            features['requires_no_interaction'] = float(ui == 'NONE')
            
            # Scope
            scope = cvss_vector.get('scope')
            features['scope_score'] = self.SCOPE_MAP.get(scope, 0.5)
            features['scope_changed'] = float(scope == 'CHANGED')
            
            # Impact scores
            c_impact = cvss_vector.get('confidentiality_impact')
            i_impact = cvss_vector.get('integrity_impact')
            a_impact = cvss_vector.get('availability_impact')
            
            features['confidentiality_score'] = self.IMPACT_MAP.get(c_impact, 0.5)
            features['integrity_score'] = self.IMPACT_MAP.get(i_impact, 0.5)
            features['availability_score'] = self.IMPACT_MAP.get(a_impact, 0.5)
            
            # Derived: Total impact
            features['total_impact'] = (
                features['confidentiality_score'] +
                features['integrity_score'] +
                features['availability_score']
            ) / 3.0
            
            # Derived: Ease of exploitation
            features['ease_of_exploit'] = (
                features['av_score'] * 
                features['ac_score'] * 
                features['pr_score'] * 
                features['ui_score']
            )
        
        return features
    
    def _extract_temporal_features(self, record: Dict) -> Dict[str, float]:
        """Extract temporal features."""
        features = {}
        
        pub_date = record.get('published_date')
        mod_date = record.get('modified_date')
        
        if pub_date:
            if isinstance(pub_date, str):
                pub_date = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
            
            # Days since publication
            days_since_pub = (self.reference_date - pub_date.replace(tzinfo=None)).days
            features['days_since_published'] = max(0, days_since_pub)
            features['log_days_since_published'] = np.log1p(features['days_since_published'])
            
            # Year and month (for seasonality)
            features['pub_year'] = pub_date.year
            features['pub_month'] = pub_date.month
            features['pub_quarter'] = (pub_date.month - 1) // 3 + 1
            
            # Is recent (last 30 days)
            features['is_recent'] = float(days_since_pub <= 30)
            # Is old (more than 2 years)
            features['is_old'] = float(days_since_pub > 730)
        
        if mod_date and pub_date:
            if isinstance(mod_date, str):
                mod_date = datetime.fromisoformat(mod_date.replace('Z', '+00:00'))
            
            # Days between publication and modification
            days_to_modify = (mod_date.replace(tzinfo=None) - pub_date.replace(tzinfo=None)).days
            features['days_to_first_modify'] = max(0, days_to_modify)
            features['was_modified'] = float(days_to_modify > 0)
        
        return features
    
    def _extract_cwe_features(self, record: Dict) -> Dict[str, Any]:
        """Extract CWE-based features."""
        features = {}
        
        cwe_ids = record.get('cwe_ids', [])
        
        # CWE count
        features['cwe_count'] = len(cwe_ids)
        features['has_cwe'] = float(len(cwe_ids) > 0)
        
        # Map CWEs to attack types
        attack_types_found = set()
        for cwe in cwe_ids:
            cwe_upper = cwe.upper()
            if cwe_upper in CWE_ATTACK_MAPPING:
                attack_types_found.add(CWE_ATTACK_MAPPING[cwe_upper])
        
        # One-hot encode attack types
        for attack_type in ATTACK_TYPE_KEYWORDS.keys():
            features[f'cwe_attack_{attack_type}'] = float(attack_type in attack_types_found)
        
        # Primary CWE (first one) for categorical encoding
        features['primary_cwe'] = cwe_ids[0] if cwe_ids else 'UNKNOWN'
        
        return features
    
    def _extract_reference_features(self, record: Dict) -> Dict[str, float]:
        """Extract features from references."""
        features = {}
        
        references = record.get('references', [])
        
        # Reference counts
        features['reference_count'] = len(references)
        features['log_reference_count'] = np.log1p(len(references))
        
        # Categorize references by tags
        tag_counts = Counter()
        for ref in references:
            tags = ref.get('tags', [])
            for tag in tags:
                tag_counts[tag.lower()] += 1
        
        # Important reference types
        features['has_exploit_ref'] = float(
            tag_counts.get('exploit', 0) > 0 or 
            tag_counts.get('technical-description', 0) > 0
        )
        features['has_patch_ref'] = float(
            tag_counts.get('patch', 0) > 0 or
            tag_counts.get('mitigation', 0) > 0
        )
        features['has_vendor_ref'] = float(
            tag_counts.get('vendor-advisory', 0) > 0
        )
        features['has_third_party_ref'] = float(
            tag_counts.get('third-party-advisory', 0) > 0
        )
        
        return features
    
    def _extract_product_features(self, record: Dict) -> Dict[str, Any]:
        """Extract features from affected products."""
        features = {}
        
        products = record.get('affected_products', [])
        
        features['affected_product_count'] = len(products)
        features['log_product_count'] = np.log1p(len(products))
        
        # Extract vendor information from CPE strings
        vendors = set()
        for cpe in products:
            parts = cpe.split(':')
            if len(parts) > 3:
                vendors.add(parts[3])
        
        features['affected_vendor_count'] = len(vendors)
        features['is_multi_vendor'] = float(len(vendors) > 1)
        
        return features
    
    def engineer_features(self, record: Dict) -> FeatureSet:
        """
        Engineer all features for a single record.
        
        Args:
            record: CVE record dictionary (from data collector)
            
        Returns:
            FeatureSet with all engineered features
        """
        # Get basic fields
        cve_id = record.get('cve_id', 'UNKNOWN')
        text = record.get('cleaned_description', record.get('description', ''))
        text_metadata = record.get('text_metadata', {})
        
        # Get severity label
        severity_label = record.get('severity_label')
        if hasattr(severity_label, 'value'):
            severity_label = severity_label.value
        severity_id = self.SEVERITY_TO_ID.get(severity_label, -1)
        
        # Collect all numerical features
        numerical_features = {}
        
        if self.include_text_stats:
            numerical_features.update(self._extract_text_features(text, text_metadata))
        
        if self.include_cvss_components:
            numerical_features.update(self._extract_cvss_features(record))
        
        if self.include_temporal:
            numerical_features.update(self._extract_temporal_features(record))
        
        if self.include_attack_type:
            cwe_features = self._extract_cwe_features(record)
            # Separate categorical from numerical
            primary_cwe = cwe_features.pop('primary_cwe', 'UNKNOWN')
            numerical_features.update(cwe_features)
        
        numerical_features.update(self._extract_reference_features(record))
        numerical_features.update(self._extract_product_features(record))
        
        # Categorical features
        categorical_features = {
            'primary_cwe': cwe_features.get('primary_cwe', 'UNKNOWN') if self.include_attack_type else 'UNKNOWN',
            'cvss_version': record.get('cvss_version', 'UNKNOWN')
        }
        
        # Create feature vector
        feature_names = sorted(numerical_features.keys())
        feature_vector = np.array([numerical_features[k] for k in feature_names])
        
        return FeatureSet(
            cve_id=cve_id,
            text=text,
            numerical_features=numerical_features,
            categorical_features=categorical_features,
            severity_label=severity_label,
            severity_id=severity_id,
            feature_vector=feature_vector
        )
    
    def engineer_batch(self, records: List[Dict]) -> List[FeatureSet]:
        """Engineer features for multiple records."""
        return [self.engineer_features(r) for r in records]
    
    def to_dataframe(self, feature_sets: List[FeatureSet]) -> pd.DataFrame:
        """Convert feature sets to pandas DataFrame."""
        rows = []
        
        for fs in feature_sets:
            row = {
                'cve_id': fs.cve_id,
                'text': fs.text,
                'severity_label': fs.severity_label,
                'severity_id': fs.severity_id,
                **fs.numerical_features,
                **{f'cat_{k}': v for k, v in fs.categorical_features.items()}
            }
            rows.append(row)
        
        return pd.DataFrame(rows)
    
    def get_feature_names(self, feature_sets: List[FeatureSet]) -> List[str]:
        """Get ordered list of numerical feature names."""
        if not feature_sets:
            return []
        return sorted(feature_sets[0].numerical_features.keys())


# Example usage
if __name__ == "__main__":
    # Test feature engineering
    engineer = FeatureEngineer()
    
    # Sample record (simulating output from data collector + cleaner)
    test_record = {
        'cve_id': 'CVE-2021-44228',
        'description': 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features...',
        'cleaned_description': 'apache log4j jndi feature remote code execution',
        'cvss_score': 10.0,
        'severity_label': 'CRITICAL',
        'cvss_vector': {
            'attack_vector': 'NETWORK',
            'attack_complexity': 'LOW',
            'privileges_required': 'NONE',
            'user_interaction': 'NONE',
            'scope': 'CHANGED',
            'confidentiality_impact': 'HIGH',
            'integrity_impact': 'HIGH',
            'availability_impact': 'HIGH'
        },
        'published_date': '2021-12-10T10:15:00Z',
        'modified_date': '2023-01-15T12:00:00Z',
        'cwe_ids': ['CWE-502', 'CWE-917'],
        'references': [
            {'url': 'https://logging.apache.org/', 'tags': ['vendor-advisory']},
            {'url': 'https://exploit-db.com/', 'tags': ['exploit']}
        ],
        'affected_products': ['cpe:2.3:a:apache:log4j:2.14.1'],
        'text_metadata': {
            'has_exploit_mention': True,
            'extracted_urls': ['https://example.com'],
            'extracted_cves': [],
            'extracted_cwes': [],
            'extracted_versions': ['2.0', '2.15.0']
        }
    }
    
    # Engineer features
    features = engineer.engineer_features(test_record)
    
    print("Engineered Features for", features.cve_id)
    print("\nNumerical Features:")
    for name, value in sorted(features.numerical_features.items()):
        print(f"  {name}: {value}")
    
    print(f"\nFeature Vector Shape: {features.feature_vector.shape}")
    print(f"Severity Label: {features.severity_label} (ID: {features.severity_id})")

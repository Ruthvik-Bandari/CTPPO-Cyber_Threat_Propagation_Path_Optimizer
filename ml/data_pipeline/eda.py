#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Exploratory Data Analysis (EDA)
=============================================

Phase 1.2 of the ML Pipeline: Understanding your data BEFORE training.

EDA Steps:
1. Shape & Structure - How many samples? How many features?
2. Data Types - Numerical vs Categorical?
3. Statistical Summary - Mean, std, min, max
4. Missing Values - How much data is missing?
5. Class Distribution - Is the data balanced?
6. Correlation Analysis - Which features are related?
7. Outlier Detection - Are there extreme values?

Author: Ruthvik
Date: January 2026
"""

import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CVEDataAnalyzer:
    """
    Comprehensive EDA for CVE datasets.
    """
    
    def __init__(self, data_path: Path):
        """
        Initialize analyzer.
        
        Args:
            data_path: Path to data file (JSON Lines format)
        """
        self.data_path = Path(data_path)
        if not self.data_path.exists():
            raise FileNotFoundError(f"Data file not found: {self.data_path}")
    
    def analyze_all(self, max_samples: Optional[int] = None) -> Dict[str, Any]:
        """
        Run complete EDA and return results.
        
        Args:
            max_samples: Maximum samples to analyze (None = all)
            
        Returns:
            Dictionary with all analysis results
        """
        logger.info("Starting Exploratory Data Analysis...")
        
        # Load data
        records = self._load_data(max_samples)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'data_file': str(self.data_path),
            'total_records': len(records)
        }
        
        # 1. Shape & Structure
        results['shape'] = self._analyze_shape(records)
        
        # 2. Data Types
        results['data_types'] = self._analyze_types(records)
        
        # 3. Statistical Summary
        results['statistics'] = self._analyze_statistics(records)
        
        # 4. Missing Values
        results['missing'] = self._analyze_missing(records)
        
        # 5. Class Distribution (Severity)
        results['class_distribution'] = self._analyze_class_distribution(records)
        
        # 6. Temporal Analysis
        results['temporal'] = self._analyze_temporal(records)
        
        # 7. Text Analysis
        results['text'] = self._analyze_text(records)
        
        # 8. CVSS Analysis
        results['cvss'] = self._analyze_cvss(records)
        
        logger.info("EDA Complete!")
        return results
    
    def _load_data(self, max_samples: Optional[int] = None) -> List[Dict]:
        """Load data from JSON Lines file."""
        records = []
        with open(self.data_path, 'r') as f:
            for line in f:
                if max_samples and len(records) >= max_samples:
                    break
                records.append(json.loads(line))
        logger.info(f"Loaded {len(records)} records")
        return records
    
    def _analyze_shape(self, records: List[Dict]) -> Dict:
        """Analyze data shape and structure."""
        if not records:
            return {'n_samples': 0, 'n_features': 0}
        
        # Get all unique keys across records
        all_keys = set()
        for r in records:
            all_keys.update(r.keys())
        
        return {
            'n_samples': len(records),
            'n_features': len(all_keys),
            'features': sorted(list(all_keys))
        }
    
    def _analyze_types(self, records: List[Dict]) -> Dict:
        """Analyze data types of each field."""
        if not records:
            return {}
        
        type_info = {}
        sample = records[0]
        
        for key, value in sample.items():
            if value is None:
                type_info[key] = 'null'
            elif isinstance(value, bool):
                type_info[key] = 'boolean'
            elif isinstance(value, int):
                type_info[key] = 'integer'
            elif isinstance(value, float):
                type_info[key] = 'float'
            elif isinstance(value, str):
                type_info[key] = 'string'
            elif isinstance(value, list):
                type_info[key] = 'list'
            elif isinstance(value, dict):
                type_info[key] = 'dict'
            else:
                type_info[key] = str(type(value).__name__)
        
        # Categorize
        numerical = [k for k, v in type_info.items() if v in ['integer', 'float']]
        categorical = [k for k, v in type_info.items() if v in ['string', 'boolean']]
        complex_types = [k for k, v in type_info.items() if v in ['list', 'dict']]
        
        return {
            'types': type_info,
            'numerical_features': numerical,
            'categorical_features': categorical,
            'complex_features': complex_types
        }
    
    def _analyze_statistics(self, records: List[Dict]) -> Dict:
        """Compute statistical summary for numerical fields."""
        if not records:
            return {}
        
        # Extract CVSS scores
        cvss_scores = [r.get('cvss_score') for r in records if r.get('cvss_score') is not None]
        
        # Description lengths
        desc_lengths = [len(r.get('description', '')) for r in records]
        
        # Reference counts
        ref_counts = [len(r.get('references', [])) for r in records]
        
        stats = {}
        
        if cvss_scores:
            stats['cvss_score'] = {
                'count': len(cvss_scores),
                'mean': np.mean(cvss_scores),
                'std': np.std(cvss_scores),
                'min': min(cvss_scores),
                '25%': np.percentile(cvss_scores, 25),
                '50%': np.percentile(cvss_scores, 50),
                '75%': np.percentile(cvss_scores, 75),
                'max': max(cvss_scores)
            }
        
        if desc_lengths:
            stats['description_length'] = {
                'count': len(desc_lengths),
                'mean': np.mean(desc_lengths),
                'std': np.std(desc_lengths),
                'min': min(desc_lengths),
                '25%': np.percentile(desc_lengths, 25),
                '50%': np.percentile(desc_lengths, 50),
                '75%': np.percentile(desc_lengths, 75),
                'max': max(desc_lengths)
            }
        
        if ref_counts:
            stats['reference_count'] = {
                'count': len(ref_counts),
                'mean': np.mean(ref_counts),
                'std': np.std(ref_counts),
                'min': min(ref_counts),
                'max': max(ref_counts)
            }
        
        return stats
    
    def _analyze_missing(self, records: List[Dict]) -> Dict:
        """Analyze missing values."""
        if not records:
            return {}
        
        # Get all possible fields
        all_fields = set()
        for r in records:
            all_fields.update(r.keys())
        
        missing_info = {}
        total = len(records)
        
        for field in all_fields:
            missing = sum(1 for r in records if r.get(field) is None)
            pct = 100 * missing / total
            missing_info[field] = {
                'missing_count': missing,
                'missing_percent': round(pct, 2),
                'present_count': total - missing
            }
        
        # Sort by missing percentage
        sorted_fields = sorted(missing_info.items(), key=lambda x: x[1]['missing_percent'], reverse=True)
        
        return {
            'by_field': dict(sorted_fields),
            'fields_with_missing': [f for f, info in sorted_fields if info['missing_count'] > 0]
        }
    
    def _analyze_class_distribution(self, records: List[Dict]) -> Dict:
        """Analyze severity class distribution."""
        severities = [r.get('severity', 'UNKNOWN') for r in records]
        counts = Counter(severities)
        total = len(severities)
        
        distribution = {}
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE']:
            count = counts.get(severity, 0)
            distribution[severity] = {
                'count': count,
                'percentage': round(100 * count / total, 2) if total > 0 else 0
            }
        
        # Calculate imbalance ratio
        valid_counts = [c for sev, c in counts.items() if sev not in ['UNKNOWN', 'NONE']]
        imbalance_ratio = max(valid_counts) / min(valid_counts) if valid_counts and min(valid_counts) > 0 else float('inf')
        
        return {
            'distribution': distribution,
            'imbalance_ratio': round(imbalance_ratio, 2),
            'is_imbalanced': imbalance_ratio > 3,
            'recommendation': 'Use class weights or oversampling' if imbalance_ratio > 3 else 'Distribution is reasonable'
        }
    
    def _analyze_temporal(self, records: List[Dict]) -> Dict:
        """Analyze temporal patterns."""
        years = Counter()
        months = Counter()
        
        for r in records:
            pub_date = r.get('published_date')
            if pub_date:
                try:
                    if isinstance(pub_date, str):
                        year = pub_date[:4]
                        month = pub_date[5:7]
                        years[year] += 1
                        months[month] += 1
                except:
                    pass
        
        return {
            'records_by_year': dict(sorted(years.items())),
            'records_by_month': dict(sorted(months.items())),
            'year_range': (min(years.keys()), max(years.keys())) if years else (None, None)
        }
    
    def _analyze_text(self, records: List[Dict]) -> Dict:
        """Analyze text descriptions."""
        descriptions = [r.get('description', '') for r in records]
        
        lengths = [len(d) for d in descriptions]
        word_counts = [len(d.split()) for d in descriptions]
        
        # Common words (simple analysis)
        all_words = []
        for d in descriptions[:1000]:  # Sample for speed
            all_words.extend(d.lower().split())
        
        word_freq = Counter(all_words)
        
        # Security keywords
        security_keywords = ['vulnerability', 'attack', 'exploit', 'remote', 'execution',
                           'overflow', 'injection', 'bypass', 'denial', 'disclosure']
        keyword_presence = {kw: sum(1 for d in descriptions if kw in d.lower()) for kw in security_keywords}
        
        return {
            'length_stats': {
                'mean': np.mean(lengths),
                'std': np.std(lengths),
                'min': min(lengths),
                'max': max(lengths)
            },
            'word_count_stats': {
                'mean': np.mean(word_counts),
                'std': np.std(word_counts),
                'min': min(word_counts),
                'max': max(word_counts)
            },
            'top_words': dict(word_freq.most_common(20)),
            'security_keyword_presence': keyword_presence
        }
    
    def _analyze_cvss(self, records: List[Dict]) -> Dict:
        """Analyze CVSS vector components."""
        # Collect CVSS vector components
        attack_vectors = Counter()
        attack_complexity = Counter()
        privileges_required = Counter()
        user_interaction = Counter()
        scope = Counter()
        
        for r in records:
            vec = r.get('cvss_vector', {})
            if vec:
                if vec.get('attack_vector'):
                    attack_vectors[vec['attack_vector']] += 1
                if vec.get('attack_complexity'):
                    attack_complexity[vec['attack_complexity']] += 1
                if vec.get('privileges_required'):
                    privileges_required[vec['privileges_required']] += 1
                if vec.get('user_interaction'):
                    user_interaction[vec['user_interaction']] += 1
                if vec.get('scope'):
                    scope[vec['scope']] += 1
        
        return {
            'attack_vector': dict(attack_vectors),
            'attack_complexity': dict(attack_complexity),
            'privileges_required': dict(privileges_required),
            'user_interaction': dict(user_interaction),
            'scope': dict(scope)
        }
    
    def print_report(self, results: Dict):
        """Print a formatted EDA report."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════╗
║              EXPLORATORY DATA ANALYSIS (EDA) REPORT                   ║
╚═══════════════════════════════════════════════════════════════════════╝
        """)
        
        # 1. Shape
        print("\n" + "="*60)
        print("1. DATA SHAPE & STRUCTURE")
        print("="*60)
        shape = results.get('shape', {})
        print(f"   Total samples: {shape.get('n_samples', 0):,}")
        print(f"   Total features: {shape.get('n_features', 0)}")
        
        # 2. Data Types
        print("\n" + "="*60)
        print("2. DATA TYPES")
        print("="*60)
        types = results.get('data_types', {})
        print(f"   Numerical features: {len(types.get('numerical_features', []))}")
        print(f"   Categorical features: {len(types.get('categorical_features', []))}")
        print(f"   Complex features: {len(types.get('complex_features', []))}")
        
        # 3. Statistics
        print("\n" + "="*60)
        print("3. STATISTICAL SUMMARY")
        print("="*60)
        stats = results.get('statistics', {})
        
        if 'cvss_score' in stats:
            cvss = stats['cvss_score']
            print(f"\n   CVSS Score:")
            print(f"      Mean: {cvss['mean']:.2f}")
            print(f"      Std:  {cvss['std']:.2f}")
            print(f"      Min:  {cvss['min']:.1f}")
            print(f"      Max:  {cvss['max']:.1f}")
        
        if 'description_length' in stats:
            desc = stats['description_length']
            print(f"\n   Description Length:")
            print(f"      Mean: {desc['mean']:.0f} chars")
            print(f"      Std:  {desc['std']:.0f}")
            print(f"      Min:  {desc['min']}")
            print(f"      Max:  {desc['max']}")
        
        # 4. Missing Values
        print("\n" + "="*60)
        print("4. MISSING VALUES")
        print("="*60)
        missing = results.get('missing', {})
        fields_with_missing = missing.get('fields_with_missing', [])
        if fields_with_missing:
            print(f"   Fields with missing values: {len(fields_with_missing)}")
            for field in fields_with_missing[:5]:
                info = missing['by_field'][field]
                print(f"      {field}: {info['missing_percent']:.1f}% missing")
        else:
            print("   No missing values found!")
        
        # 5. Class Distribution
        print("\n" + "="*60)
        print("5. CLASS DISTRIBUTION (Severity)")
        print("="*60)
        class_dist = results.get('class_distribution', {})
        dist = class_dist.get('distribution', {})
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            info = dist.get(severity, {})
            count = info.get('count', 0)
            pct = info.get('percentage', 0)
            bar = "█" * int(pct / 2)
            print(f"   {severity:<10}: {count:>8,} ({pct:>5.1f}%) {bar}")
        
        imb = class_dist.get('imbalance_ratio', 0)
        print(f"\n   Imbalance ratio: {imb:.1f}")
        if class_dist.get('is_imbalanced'):
            print("   ⚠️  Data is IMBALANCED!")
            print(f"   Recommendation: {class_dist.get('recommendation')}")
        else:
            print("   ✓ Class distribution is reasonable")
        
        # 6. CVSS Components
        print("\n" + "="*60)
        print("6. CVSS VECTOR ANALYSIS")
        print("="*60)
        cvss = results.get('cvss', {})
        
        av = cvss.get('attack_vector', {})
        if av:
            print("\n   Attack Vector:")
            for k, v in sorted(av.items(), key=lambda x: -x[1])[:4]:
                print(f"      {k}: {v:,}")
        
        ac = cvss.get('attack_complexity', {})
        if ac:
            print("\n   Attack Complexity:")
            for k, v in ac.items():
                print(f"      {k}: {v:,}")
        
        # 7. Temporal
        print("\n" + "="*60)
        print("7. TEMPORAL ANALYSIS")
        print("="*60)
        temporal = results.get('temporal', {})
        year_range = temporal.get('year_range', (None, None))
        if year_range[0]:
            print(f"   Year range: {year_range[0]} - {year_range[1]}")
        
        years = temporal.get('records_by_year', {})
        if years:
            print("\n   Recent years:")
            for year in sorted(years.keys())[-5:]:
                print(f"      {year}: {years[year]:,}")
        
        print("\n" + "="*60)
        print("EDA COMPLETE")
        print("="*60)


def run_eda(data_path: str, output_path: Optional[str] = None, max_samples: Optional[int] = None):
    """
    Run EDA on CVE dataset.
    
    Args:
        data_path: Path to data file
        output_path: Optional path to save results JSON
        max_samples: Maximum samples to analyze
    """
    analyzer = CVEDataAnalyzer(Path(data_path))
    results = analyzer.analyze_all(max_samples)
    
    # Print report
    analyzer.print_report(results)
    
    # Save if requested
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to: {output_path}")
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run EDA on CVE dataset")
    parser.add_argument("data_path", help="Path to data file (JSON Lines)")
    parser.add_argument("--output", "-o", help="Output path for JSON results")
    parser.add_argument("--max-samples", "-n", type=int, help="Max samples to analyze")
    
    args = parser.parse_args()
    
    run_eda(args.data_path, args.output, args.max_samples)

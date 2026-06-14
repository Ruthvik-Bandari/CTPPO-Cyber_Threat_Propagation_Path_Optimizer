#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Step 1: Data Analysis (EDA)
=========================================

ALWAYS RUN THIS FIRST before any preprocessing!

This script analyzes your raw CVE data to understand:
1. How much data do we have?
2. What's the class distribution (balanced or imbalanced)?
3. Are there missing values?
4. What do the descriptions look like?
5. Are there data quality issues?

Usage:
    python ml/01_analyze_data.py
    python ml/01_analyze_data.py --input data/nvd_full/all_cves.jsonl
    python ml/01_analyze_data.py --sample 10000  # Quick analysis on subset

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import logging
import numpy as np
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any, Optional
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CVEDataAnalyzer:
    """
    Comprehensive Exploratory Data Analysis for CVE datasets.
    """
    
    def __init__(self, data_path: str):
        """
        Initialize analyzer with data path.
        
        Args:
            data_path: Path to JSON Lines file containing CVE data
        """
        self.data_path = Path(data_path)
        if not self.data_path.exists():
            raise FileNotFoundError(f"Data file not found: {self.data_path}")
        
        self.records = []
        self.analysis = {}
    
    def load_data(self, max_records: Optional[int] = None) -> int:
        """
        Load data from file.
        
        Args:
            max_records: Maximum records to load (None = all)
            
        Returns:
            Number of records loaded
        """
        logger.info(f"Loading data from {self.data_path}...")
        
        self.records = []
        with open(self.data_path, 'r') as f:
            for i, line in enumerate(f):
                if max_records and i >= max_records:
                    break
                self.records.append(json.loads(line))
        
        logger.info(f"Loaded {len(self.records):,} records")
        return len(self.records)
    
    def analyze(self) -> Dict[str, Any]:
        """
        Run complete EDA analysis.
        
        Returns:
            Dictionary with all analysis results
        """
        if not self.records:
            raise ValueError("No data loaded. Call load_data() first.")
        
        logger.info("Running Exploratory Data Analysis...")
        
        self.analysis = {
            'metadata': {
                'data_file': str(self.data_path),
                'total_records': len(self.records),
                'analysis_timestamp': datetime.now().isoformat(),
                'file_size_mb': self.data_path.stat().st_size / (1024 * 1024)
            }
        }
        
        # Run all analyses
        self._analyze_severity_distribution()
        self._analyze_missing_values()
        self._analyze_descriptions()
        self._analyze_cvss_scores()
        self._analyze_cwe_distribution()
        self._analyze_temporal()
        self._analyze_data_quality()
        self._generate_recommendations()
        
        return self.analysis
    
    def _analyze_severity_distribution(self):
        """Analyze target variable (severity) distribution."""
        logger.info("Analyzing severity distribution...")
        
        severities = [r.get('severity', 'UNKNOWN') for r in self.records]
        counts = Counter(severities)
        total = len(severities)
        
        distribution = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']:
            if sev in counts:
                distribution[sev] = {
                    'count': counts[sev],
                    'percentage': round(100 * counts[sev] / total, 2)
                }
        
        # Calculate imbalance metrics
        known = {k: v['count'] for k, v in distribution.items() if k not in ['UNKNOWN', 'NONE']}
        
        if known:
            max_count = max(known.values())
            min_count = min(known.values())
            imbalance_ratio = max_count / min_count if min_count > 0 else float('inf')
        else:
            imbalance_ratio = 0
        
        self.analysis['severity'] = {
            'distribution': distribution,
            'imbalance_ratio': round(imbalance_ratio, 2),
            'is_imbalanced': imbalance_ratio > 3,
            'majority_class': max(known, key=known.get) if known else None,
            'minority_class': min(known, key=known.get) if known else None
        }
    
    def _analyze_missing_values(self):
        """Analyze missing values in all fields."""
        logger.info("Analyzing missing values...")
        
        fields_to_check = [
            'cve_id', 'description', 'cvss_score', 'severity', 
            'cvss_version', 'cvss_vector', 'cwe_ids', 'references',
            'affected_products', 'published_date', 'modified_date'
        ]
        
        missing = {}
        total = len(self.records)
        
        for field in fields_to_check:
            null_count = 0
            empty_count = 0
            
            for r in self.records:
                value = r.get(field)
                
                if value is None:
                    null_count += 1
                elif isinstance(value, str) and value.strip() == '':
                    empty_count += 1
                elif isinstance(value, list) and len(value) == 0:
                    empty_count += 1
                elif isinstance(value, dict) and len(value) == 0:
                    empty_count += 1
            
            total_missing = null_count + empty_count
            
            if total_missing > 0:
                missing[field] = {
                    'null': null_count,
                    'empty': empty_count,
                    'total_missing': total_missing,
                    'percentage': round(100 * total_missing / total, 2)
                }
        
        self.analysis['missing_values'] = {
            'fields_with_missing': missing,
            'total_fields_checked': len(fields_to_check),
            'fields_with_issues': len(missing)
        }
    
    def _analyze_descriptions(self):
        """Analyze text descriptions (model input)."""
        logger.info("Analyzing descriptions...")
        
        descriptions = [r.get('description', '') for r in self.records]
        
        # Length statistics
        char_lengths = [len(d) for d in descriptions]
        word_counts = [len(d.split()) for d in descriptions]
        
        # Identify issues
        empty = sum(1 for d in descriptions if len(d.strip()) == 0)
        very_short = sum(1 for d in descriptions if 0 < len(d.split()) < 5)
        short = sum(1 for d in descriptions if 5 <= len(d.split()) < 10)
        medium = sum(1 for d in descriptions if 10 <= len(d.split()) < 50)
        long_desc = sum(1 for d in descriptions if 50 <= len(d.split()) < 200)
        very_long = sum(1 for d in descriptions if len(d.split()) >= 200)
        
        # Content analysis
        has_html = sum(1 for d in descriptions if '<' in d and '>' in d)
        has_url = sum(1 for d in descriptions if 'http' in d.lower())
        has_code = sum(1 for d in descriptions if '```' in d or '()' in d)
        
        # Problematic patterns
        rejected = sum(1 for d in descriptions if 'rejected' in d.lower())
        reserved = sum(1 for d in descriptions if 'reserved' in d.lower())
        disputed = sum(1 for d in descriptions if 'disputed' in d.lower())
        
        self.analysis['descriptions'] = {
            'statistics': {
                'char_length': {
                    'mean': round(np.mean(char_lengths), 1),
                    'std': round(np.std(char_lengths), 1),
                    'min': int(min(char_lengths)),
                    'max': int(max(char_lengths)),
                    'median': round(np.median(char_lengths), 1),
                    'p25': round(np.percentile(char_lengths, 25), 1),
                    'p75': round(np.percentile(char_lengths, 75), 1)
                },
                'word_count': {
                    'mean': round(np.mean(word_counts), 1),
                    'std': round(np.std(word_counts), 1),
                    'min': int(min(word_counts)),
                    'max': int(max(word_counts)),
                    'median': round(np.median(word_counts), 1)
                }
            },
            'length_distribution': {
                'empty': empty,
                'very_short_1_4_words': very_short,
                'short_5_9_words': short,
                'medium_10_49_words': medium,
                'long_50_199_words': long_desc,
                'very_long_200_plus_words': very_long
            },
            'content_patterns': {
                'contains_html': has_html,
                'contains_url': has_url,
                'contains_code': has_code
            },
            'problematic_records': {
                'rejected_cves': rejected,
                'reserved_cves': reserved,
                'disputed_cves': disputed,
                'total_problematic': rejected + reserved + disputed
            }
        }
    
    def _analyze_cvss_scores(self):
        """Analyze CVSS score distribution."""
        logger.info("Analyzing CVSS scores...")
        
        scores = []
        versions = Counter()
        
        for r in self.records:
            score = r.get('cvss_score')
            version = r.get('cvss_version')
            
            if score is not None:
                scores.append(score)
            if version:
                versions[version] += 1
        
        # Score distribution by severity range
        score_ranges = {
            'critical_9_10': sum(1 for s in scores if 9.0 <= s <= 10.0),
            'high_7_8_9': sum(1 for s in scores if 7.0 <= s < 9.0),
            'medium_4_6_9': sum(1 for s in scores if 4.0 <= s < 7.0),
            'low_0_1_3_9': sum(1 for s in scores if 0.1 <= s < 4.0),
            'none_0': sum(1 for s in scores if s == 0.0)
        }
        
        self.analysis['cvss'] = {
            'coverage': {
                'has_score': len(scores),
                'missing_score': len(self.records) - len(scores),
                'coverage_percentage': round(100 * len(scores) / len(self.records), 2)
            },
            'statistics': {
                'mean': round(np.mean(scores), 2) if scores else 0,
                'std': round(np.std(scores), 2) if scores else 0,
                'min': round(min(scores), 1) if scores else 0,
                'max': round(max(scores), 1) if scores else 0,
                'median': round(np.median(scores), 2) if scores else 0
            },
            'score_ranges': score_ranges,
            'versions': dict(versions)
        }
    
    def _analyze_cwe_distribution(self):
        """Analyze CWE (weakness type) distribution."""
        logger.info("Analyzing CWE distribution...")
        
        all_cwes = []
        has_cwe = 0
        multi_cwe = 0
        
        for r in self.records:
            cwes = r.get('cwe_ids', [])
            if cwes:
                has_cwe += 1
                if len(cwes) > 1:
                    multi_cwe += 1
                all_cwes.extend(cwes)
        
        cwe_counts = Counter(all_cwes)
        
        self.analysis['cwe'] = {
            'coverage': {
                'has_cwe': has_cwe,
                'no_cwe': len(self.records) - has_cwe,
                'multiple_cwes': multi_cwe,
                'coverage_percentage': round(100 * has_cwe / len(self.records), 2)
            },
            'unique_cwes': len(cwe_counts),
            'top_20_cwes': dict(cwe_counts.most_common(20)),
            'cwe_frequency': {
                'appears_once': sum(1 for c in cwe_counts.values() if c == 1),
                'appears_2_10': sum(1 for c in cwe_counts.values() if 2 <= c <= 10),
                'appears_11_100': sum(1 for c in cwe_counts.values() if 11 <= c <= 100),
                'appears_100_plus': sum(1 for c in cwe_counts.values() if c > 100)
            }
        }
    
    def _analyze_temporal(self):
        """Analyze temporal distribution of CVEs."""
        logger.info("Analyzing temporal distribution...")
        
        years = Counter()
        months = Counter()
        
        for r in self.records:
            pub_date = r.get('published_date', '')
            if pub_date and len(pub_date) >= 7:
                try:
                    year = pub_date[:4]
                    month = pub_date[:7]
                    years[year] += 1
                    months[month] += 1
                except:
                    pass
        
        # Recent trend (last 5 years)
        sorted_years = sorted(years.items())
        recent_years = dict(sorted_years[-5:]) if len(sorted_years) >= 5 else dict(sorted_years)
        
        self.analysis['temporal'] = {
            'year_range': {
                'earliest': min(years.keys()) if years else None,
                'latest': max(years.keys()) if years else None
            },
            'by_year': dict(sorted(years.items())),
            'recent_5_years': recent_years,
            'trend': 'increasing' if len(recent_years) >= 2 and list(recent_years.values())[-1] > list(recent_years.values())[0] else 'stable'
        }
    
    def _analyze_data_quality(self):
        """Identify data quality issues that need attention."""
        logger.info("Analyzing data quality...")
        
        issues = []
        
        # Check severity
        sev = self.analysis.get('severity', {})
        unknown_pct = sev.get('distribution', {}).get('UNKNOWN', {}).get('percentage', 0)
        if unknown_pct > 5:
            issues.append({
                'issue': 'High percentage of UNKNOWN severity',
                'percentage': unknown_pct,
                'action': 'Filter out UNKNOWN records before training'
            })
        
        if sev.get('imbalance_ratio', 0) > 5:
            issues.append({
                'issue': 'Severe class imbalance',
                'ratio': sev.get('imbalance_ratio'),
                'action': 'Use class weights, oversampling, or undersampling'
            })
        
        # Check descriptions
        desc = self.analysis.get('descriptions', {})
        prob = desc.get('problematic_records', {})
        if prob.get('total_problematic', 0) > 0:
            issues.append({
                'issue': 'Rejected/Reserved/Disputed CVEs present',
                'count': prob.get('total_problematic'),
                'action': 'Filter out these records - they have no useful information'
            })
        
        empty = desc.get('length_distribution', {}).get('empty', 0)
        if empty > 0:
            issues.append({
                'issue': 'Empty descriptions',
                'count': empty,
                'action': 'Remove records with empty descriptions'
            })
        
        # Check CVSS coverage
        cvss = self.analysis.get('cvss', {})
        coverage = cvss.get('coverage', {}).get('coverage_percentage', 0)
        if coverage < 95:
            issues.append({
                'issue': 'Missing CVSS scores',
                'coverage': coverage,
                'action': 'Records without CVSS have UNKNOWN severity - will be filtered'
            })
        
        self.analysis['data_quality'] = {
            'issues_found': len(issues),
            'issues': issues
        }
    
    def _generate_recommendations(self):
        """Generate preprocessing recommendations based on analysis."""
        logger.info("Generating recommendations...")
        
        recommendations = []
        
        # Based on severity
        sev = self.analysis.get('severity', {})
        if sev.get('distribution', {}).get('UNKNOWN', {}).get('count', 0) > 0:
            recommendations.append({
                'step': 'Filter UNKNOWN severity',
                'reason': 'No ground truth label available',
                'records_affected': sev['distribution']['UNKNOWN']['count']
            })
        
        # Based on descriptions
        desc = self.analysis.get('descriptions', {})
        prob = desc.get('problematic_records', {})
        
        if prob.get('rejected_cves', 0) > 0:
            recommendations.append({
                'step': 'Filter rejected CVEs',
                'reason': 'These are invalid/withdrawn vulnerabilities',
                'records_affected': prob['rejected_cves']
            })
        
        if prob.get('reserved_cves', 0) > 0:
            recommendations.append({
                'step': 'Filter reserved CVEs',
                'reason': 'No description available yet',
                'records_affected': prob['reserved_cves']
            })
        
        if desc.get('length_distribution', {}).get('very_short_1_4_words', 0) > 0:
            recommendations.append({
                'step': 'Filter very short descriptions',
                'reason': 'Insufficient text for meaningful classification',
                'records_affected': desc['length_distribution']['very_short_1_4_words']
            })
        
        # Preprocessing steps
        if desc.get('content_patterns', {}).get('contains_html', 0) > 0:
            recommendations.append({
                'step': 'Clean HTML tags',
                'reason': 'Remove markup that adds noise',
                'records_affected': desc['content_patterns']['contains_html']
            })
        
        if desc.get('content_patterns', {}).get('contains_url', 0) > 0:
            recommendations.append({
                'step': 'Normalize URLs',
                'reason': 'Replace with [URL] token',
                'records_affected': desc['content_patterns']['contains_url']
            })
        
        # Balancing
        if sev.get('is_imbalanced', False):
            recommendations.append({
                'step': 'Handle class imbalance',
                'reason': f"Imbalance ratio: {sev.get('imbalance_ratio')}x",
                'options': ['Class weights', 'SMOTE oversampling', 'Random undersampling']
            })
        
        self.analysis['recommendations'] = recommendations
    
    def print_report(self):
        """Print a formatted analysis report."""
        
        if not self.analysis:
            print("No analysis available. Run analyze() first.")
            return
        
        # Header
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                       CVE DATA ANALYSIS REPORT                                ║
║                    Step 1: Understand Your Data                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        # Metadata
        meta = self.analysis.get('metadata', {})
        print(f"📁 Data File: {meta.get('data_file')}")
        print(f"📊 Total Records: {meta.get('total_records'):,}")
        print(f"💾 File Size: {meta.get('file_size_mb'):.1f} MB")
        print(f"🕐 Analysis Time: {meta.get('analysis_timestamp')}")
        
        # 1. Severity Distribution
        print("\n" + "="*80)
        print("1. SEVERITY DISTRIBUTION (Target Variable)")
        print("="*80)
        
        sev = self.analysis.get('severity', {})
        dist = sev.get('distribution', {})
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']:
            if severity in dist:
                info = dist[severity]
                bar = "█" * int(info['percentage'] / 2)
                print(f"   {severity:<10}: {info['count']:>10,} ({info['percentage']:>5.1f}%) {bar}")
        
        print(f"\n   📈 Imbalance Ratio: {sev.get('imbalance_ratio', 0):.1f}x")
        print(f"   🔺 Majority Class: {sev.get('majority_class')}")
        print(f"   🔻 Minority Class: {sev.get('minority_class')}")
        
        if sev.get('is_imbalanced'):
            print("   ⚠️  WARNING: Data is IMBALANCED! Will need special handling.")
        else:
            print("   ✅ Class distribution is acceptable.")
        
        # 2. Missing Values
        print("\n" + "="*80)
        print("2. MISSING VALUES")
        print("="*80)
        
        missing = self.analysis.get('missing_values', {})
        fields = missing.get('fields_with_missing', {})
        
        if fields:
            for field, info in sorted(fields.items(), key=lambda x: -x[1]['percentage']):
                print(f"   {field:<20}: {info['total_missing']:>8,} ({info['percentage']:>5.1f}% missing)")
        else:
            print("   ✅ No significant missing values!")
        
        # 3. Description Statistics
        print("\n" + "="*80)
        print("3. DESCRIPTION ANALYSIS (Model Input)")
        print("="*80)
        
        desc = self.analysis.get('descriptions', {})
        stats = desc.get('statistics', {})
        
        print("\n   📏 Length Statistics:")
        char_stats = stats.get('char_length', {})
        print(f"      Characters: mean={char_stats.get('mean'):.0f}, median={char_stats.get('median'):.0f}, max={char_stats.get('max')}")
        
        word_stats = stats.get('word_count', {})
        print(f"      Words: mean={word_stats.get('mean'):.0f}, median={word_stats.get('median'):.0f}, max={word_stats.get('max')}")
        
        print("\n   📊 Length Distribution:")
        len_dist = desc.get('length_distribution', {})
        for name, count in len_dist.items():
            if count > 0:
                pct = 100 * count / meta.get('total_records', 1)
                print(f"      {name.replace('_', ' ').title()}: {count:,} ({pct:.1f}%)")
        
        # 4. Data Quality Issues
        print("\n" + "="*80)
        print("4. DATA QUALITY ISSUES")
        print("="*80)
        
        prob = desc.get('problematic_records', {})
        content = desc.get('content_patterns', {})
        
        issues_found = False
        
        if prob.get('rejected_cves', 0) > 0:
            print(f"   ⚠️  Rejected CVEs: {prob['rejected_cves']:,}")
            issues_found = True
        if prob.get('reserved_cves', 0) > 0:
            print(f"   ⚠️  Reserved CVEs: {prob['reserved_cves']:,}")
            issues_found = True
        if prob.get('disputed_cves', 0) > 0:
            print(f"   ⚠️  Disputed CVEs: {prob['disputed_cves']:,}")
            issues_found = True
        if len_dist.get('empty', 0) > 0:
            print(f"   ⚠️  Empty descriptions: {len_dist['empty']:,}")
            issues_found = True
        
        if content.get('contains_html', 0) > 0:
            print(f"   📝 Contains HTML (needs cleaning): {content['contains_html']:,}")
        if content.get('contains_url', 0) > 0:
            print(f"   📝 Contains URLs (will normalize): {content['contains_url']:,}")
        
        if not issues_found:
            print("   ✅ No major data quality issues!")
        
        # 5. CVSS Analysis
        print("\n" + "="*80)
        print("5. CVSS SCORE ANALYSIS")
        print("="*80)
        
        cvss = self.analysis.get('cvss', {})
        coverage = cvss.get('coverage', {})
        
        print(f"   📊 Coverage: {coverage.get('has_score'):,} / {meta.get('total_records'):,} ({coverage.get('coverage_percentage'):.1f}%)")
        print(f"   ❌ Missing scores: {coverage.get('missing_score'):,}")
        
        cvss_stats = cvss.get('statistics', {})
        print(f"\n   📈 Score Statistics:")
        print(f"      Mean: {cvss_stats.get('mean'):.2f}")
        print(f"      Median: {cvss_stats.get('median'):.2f}")
        print(f"      Range: {cvss_stats.get('min'):.1f} - {cvss_stats.get('max'):.1f}")
        
        print(f"\n   📋 CVSS Versions: {cvss.get('versions', {})}")
        
        # 6. CWE Analysis
        print("\n" + "="*80)
        print("6. CWE (WEAKNESS TYPE) ANALYSIS")
        print("="*80)
        
        cwe = self.analysis.get('cwe', {})
        cwe_cov = cwe.get('coverage', {})
        
        print(f"   📊 Coverage: {cwe_cov.get('has_cwe'):,} records ({cwe_cov.get('coverage_percentage'):.1f}%)")
        print(f"   🔢 Unique CWEs: {cwe.get('unique_cwes')}")
        
        print(f"\n   🏆 Top 10 CWEs:")
        top_cwes = list(cwe.get('top_20_cwes', {}).items())[:10]
        for cwe_id, count in top_cwes:
            print(f"      {cwe_id}: {count:,}")
        
        # 7. Temporal Analysis
        print("\n" + "="*80)
        print("7. TEMPORAL DISTRIBUTION")
        print("="*80)
        
        temporal = self.analysis.get('temporal', {})
        year_range = temporal.get('year_range', {})
        
        print(f"   📅 Year Range: {year_range.get('earliest')} - {year_range.get('latest')}")
        print(f"   📈 Trend: {temporal.get('trend', 'unknown').upper()}")
        
        print(f"\n   📊 Recent 5 Years:")
        for year, count in temporal.get('recent_5_years', {}).items():
            bar = "█" * (count // 2000)
            print(f"      {year}: {count:>8,} {bar}")
        
        # 8. Recommendations
        print("\n" + "="*80)
        print("8. PREPROCESSING RECOMMENDATIONS")
        print("="*80)
        
        recommendations = self.analysis.get('recommendations', [])
        
        for i, rec in enumerate(recommendations, 1):
            print(f"\n   {i}. {rec.get('step')}")
            print(f"      Reason: {rec.get('reason')}")
            if 'records_affected' in rec:
                print(f"      Records affected: {rec['records_affected']:,}")
            if 'options' in rec:
                print(f"      Options: {', '.join(rec['options'])}")
        
        # Summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        
        # Calculate usable records
        total = meta.get('total_records', 0)
        unusable = (
            dist.get('UNKNOWN', {}).get('count', 0) +
            prob.get('rejected_cves', 0) +
            prob.get('reserved_cves', 0) +
            len_dist.get('empty', 0)
        )
        usable = total - unusable
        
        print(f"""
   📊 Total Records: {total:,}
   ❌ Unusable (UNKNOWN/rejected/empty): ~{unusable:,}
   ✅ Usable Records: ~{usable:,}
   
   🎯 After preprocessing, expect ~{usable:,} training samples
   
   Next Step: Run 02_preprocess_data.py to clean and prepare the data
        """)
    
    def save_report(self, output_path: str):
        """Save analysis to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.analysis, f, indent=2, default=str)
        logger.info(f"Analysis saved to: {output_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze CVE data before preprocessing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all data
  python ml/01_analyze_data.py
  
  # Quick analysis on 10K samples
  python ml/01_analyze_data.py --sample 10000
  
  # Specify input file
  python ml/01_analyze_data.py --input data/nvd_full/all_cves.jsonl
  
  # Save analysis to file
  python ml/01_analyze_data.py --output analysis_report.json
        """
    )
    
    parser.add_argument(
        "--input", "-i",
        type=str,
        default="./data/nvd_full/all_cves.jsonl",
        help="Path to input data file (JSON Lines format)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Path to save analysis JSON (optional)"
    )
    parser.add_argument(
        "--sample", "-n",
        type=int,
        default=None,
        help="Analyze only N records (for quick testing)"
    )
    
    args = parser.parse_args()
    
    try:
        # Create analyzer
        analyzer = CVEDataAnalyzer(args.input)
        
        # Load data
        analyzer.load_data(max_records=args.sample)
        
        # Run analysis
        analyzer.analyze()
        
        # Print report
        analyzer.print_report()
        
        # Save if requested
        if args.output:
            analyzer.save_report(args.output)
        
        print("\n✅ Analysis complete!")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()

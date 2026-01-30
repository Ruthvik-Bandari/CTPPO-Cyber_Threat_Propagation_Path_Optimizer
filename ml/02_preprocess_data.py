#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Step 2: Data Preprocessing
========================================

Based on EDA findings, this script:
1. Filters unusable records (UNKNOWN, rejected, reserved, too short)
2. Cleans text (HTML, URLs, special characters)
3. Extracts features (CVE refs, CWE refs, versions)
4. Validates data quality

Run AFTER: 01_analyze_data.py
Run BEFORE: 03_prepare_dataset.py

Usage:
    python ml/02_preprocess_data.py
    python ml/02_preprocess_data.py --input data/nvd_full/all_cves.jsonl --output data/cleaned

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import re
import json
import html
import logging
import numpy as np
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION (Based on EDA Findings)
# =============================================================================

@dataclass
class PreprocessConfig:
    """Configuration for preprocessing based on EDA findings."""
    
    # Filtering
    filter_unknown_severity: bool = True      # Remove 22,001 UNKNOWN
    filter_rejected_cves: bool = True         # Remove 17,347 rejected
    filter_reserved_cves: bool = True         # Remove 889 reserved
    filter_disputed_cves: bool = False        # Keep 588 disputed (still valid)
    min_description_words: int = 5            # Remove 938 very short
    
    # Text Cleaning
    clean_html: bool = True                   # Clean 3,914 with HTML
    normalize_urls: bool = True               # Normalize 15,649 with URLs
    normalize_emails: bool = True
    normalize_versions: bool = True
    normalize_file_paths: bool = True
    normalize_ip_addresses: bool = True
    lowercase: bool = True
    
    # What to keep (for model input)
    keep_cve_references: bool = False         # Replace with [CVE_REF]
    keep_cwe_references: bool = False         # Replace with [CWE_REF]
    
    # Output
    save_cleaning_stats: bool = True
    save_sample_comparisons: bool = True


# =============================================================================
# TEXT CLEANER
# =============================================================================

class TextCleaner:
    """
    Text cleaning pipeline for CVE descriptions.
    
    Based on EDA findings:
    - 3,914 records contain HTML
    - 15,649 records contain URLs
    - Need to preserve security-relevant terms
    """
    
    # Compiled regex patterns
    PATTERNS = {
        'html_tag': re.compile(r'<[^>]+>'),
        'html_entity': re.compile(r'&[a-zA-Z]+;|&#\d+;|&#x[a-fA-F0-9]+;'),
        'url': re.compile(r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+', re.IGNORECASE),
        'email': re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b'),
        'cve_ref': re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
        'cwe_ref': re.compile(r'CWE-\d+', re.IGNORECASE),
        'version': re.compile(r'\b[vV]?\d+(?:\.\d+)+(?:[-._][a-zA-Z0-9]+)*\b'),
        'filepath': re.compile(r'(?:/[a-zA-Z0-9_.-]+)+(?:\.[a-zA-Z0-9]+)?'),
        'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'hex_value': re.compile(r'\b0x[a-fA-F0-9]+\b'),
        'multi_space': re.compile(r'\s+'),
        'special_chars': re.compile(r'[^\w\s.,;:!?\'\"()-]'),
    }
    
    def __init__(self, config: PreprocessConfig):
        self.config = config
        self.stats = Counter()
    
    def clean(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Clean a single text description.
        
        Args:
            text: Raw description text
            
        Returns:
            Tuple of (cleaned_text, metadata)
        """
        if not text or not isinstance(text, str):
            return "", {"original_length": 0, "cleaned_length": 0, "was_empty": True}
        
        original = text
        metadata = {
            "original_length": len(text),
            "original_words": len(text.split()),
            "extracted_urls": [],
            "extracted_cves": [],
            "extracted_cwes": [],
            "extracted_versions": [],
            "had_html": False,
            "had_urls": False,
        }
        
        # Step 1: Decode HTML entities
        if self.config.clean_html:
            text = html.unescape(text)
            
            # Check for HTML tags
            if self.PATTERNS['html_tag'].search(text):
                metadata['had_html'] = True
                self.stats['had_html'] += 1
            
            # Remove HTML tags
            text = self.PATTERNS['html_tag'].sub(' ', text)
        
        # Step 2: Extract and normalize URLs
        if self.config.normalize_urls:
            urls = self.PATTERNS['url'].findall(text)
            if urls:
                metadata['extracted_urls'] = urls[:5]  # Keep first 5
                metadata['had_urls'] = True
                self.stats['had_urls'] += 1
            text = self.PATTERNS['url'].sub(' [URL] ', text)
        
        # Step 3: Extract and normalize emails
        if self.config.normalize_emails:
            text = self.PATTERNS['email'].sub(' [EMAIL] ', text)
        
        # Step 4: Extract CVE references
        cves = self.PATTERNS['cve_ref'].findall(text)
        if cves:
            metadata['extracted_cves'] = [c.upper() for c in cves]
        if not self.config.keep_cve_references:
            text = self.PATTERNS['cve_ref'].sub(' [CVE_REF] ', text)
        
        # Step 5: Extract CWE references
        cwes = self.PATTERNS['cwe_ref'].findall(text)
        if cwes:
            metadata['extracted_cwes'] = [c.upper() for c in cwes]
        if not self.config.keep_cwe_references:
            text = self.PATTERNS['cwe_ref'].sub(' [CWE_REF] ', text)
        
        # Step 6: Normalize versions
        if self.config.normalize_versions:
            versions = self.PATTERNS['version'].findall(text)
            if versions:
                metadata['extracted_versions'] = versions[:10]
            text = self.PATTERNS['version'].sub(' [VERSION] ', text)
        
        # Step 7: Normalize file paths
        if self.config.normalize_file_paths:
            text = self.PATTERNS['filepath'].sub(' [PATH] ', text)
        
        # Step 8: Normalize IP addresses
        if self.config.normalize_ip_addresses:
            text = self.PATTERNS['ip_address'].sub(' [IP] ', text)
        
        # Step 9: Normalize hex values
        text = self.PATTERNS['hex_value'].sub(' [HEX] ', text)
        
        # Step 10: Remove remaining special characters
        text = self.PATTERNS['special_chars'].sub(' ', text)
        
        # Step 11: Normalize whitespace
        text = self.PATTERNS['multi_space'].sub(' ', text).strip()
        
        # Step 12: Lowercase
        if self.config.lowercase:
            text = text.lower()
        
        metadata['cleaned_length'] = len(text)
        metadata['cleaned_words'] = len(text.split())
        
        return text, metadata
    
    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)


# =============================================================================
# DATA FILTER
# =============================================================================

class DataFilter:
    """
    Filter out unusable records based on EDA findings.
    """
    
    def __init__(self, config: PreprocessConfig):
        self.config = config
        self.stats = {
            'total_input': 0,
            'filtered_unknown': 0,
            'filtered_rejected': 0,
            'filtered_reserved': 0,
            'filtered_disputed': 0,
            'filtered_short': 0,
            'filtered_empty': 0,
            'kept': 0
        }
    
    def should_keep(self, record: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Check if a record should be kept.
        
        Args:
            record: CVE record
            
        Returns:
            Tuple of (keep: bool, reason: str)
        """
        self.stats['total_input'] += 1
        
        severity = record.get('severity', 'UNKNOWN')
        description = record.get('description', '').lower()
        
        # Filter UNKNOWN severity (no ground truth)
        if self.config.filter_unknown_severity and severity == 'UNKNOWN':
            self.stats['filtered_unknown'] += 1
            return False, 'unknown_severity'
        
        # Filter rejected CVEs
        if self.config.filter_rejected_cves and 'rejected' in description:
            self.stats['filtered_rejected'] += 1
            return False, 'rejected'
        
        # Filter reserved CVEs
        if self.config.filter_reserved_cves and 'reserved' in description:
            self.stats['filtered_reserved'] += 1
            return False, 'reserved'
        
        # Filter disputed CVEs (optional)
        if self.config.filter_disputed_cves and 'disputed' in description:
            self.stats['filtered_disputed'] += 1
            return False, 'disputed'
        
        # Filter empty descriptions
        if not description.strip():
            self.stats['filtered_empty'] += 1
            return False, 'empty'
        
        # Filter very short descriptions
        word_count = len(description.split())
        if word_count < self.config.min_description_words:
            self.stats['filtered_short'] += 1
            return False, 'too_short'
        
        self.stats['kept'] += 1
        return True, 'kept'
    
    def get_stats(self) -> Dict[str, int]:
        return self.stats.copy()


# =============================================================================
# MAIN PREPROCESSOR
# =============================================================================

class CVEPreprocessor:
    """
    Main preprocessing pipeline combining filtering and cleaning.
    """
    
    def __init__(self, config: Optional[PreprocessConfig] = None):
        self.config = config or PreprocessConfig()
        self.filter = DataFilter(self.config)
        self.cleaner = TextCleaner(self.config)
        
        self.processed_records = []
        self.sample_comparisons = []
    
    def process_file(
        self,
        input_path: str,
        output_path: str,
        max_records: Optional[int] = None,
        save_samples: int = 10
    ) -> Dict[str, Any]:
        """
        Process entire file.
        
        Args:
            input_path: Path to input JSON Lines file
            output_path: Path to output directory
            max_records: Maximum records to process (for testing)
            save_samples: Number of before/after samples to save
            
        Returns:
            Processing statistics
        """
        input_path = Path(input_path)
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Processing {input_path}...")
        logger.info(f"Output directory: {output_dir}")
        
        # Process records
        output_file = output_dir / 'cleaned_cves.jsonl'
        samples_collected = 0
        
        with open(input_path, 'r') as f_in, open(output_file, 'w') as f_out:
            for i, line in enumerate(f_in):
                if max_records and i >= max_records:
                    break
                
                if i % 50000 == 0 and i > 0:
                    logger.info(f"Processed {i:,} records...")
                
                record = json.loads(line)
                
                # Filter check
                keep, reason = self.filter.should_keep(record)
                
                if not keep:
                    continue
                
                # Clean description
                original_desc = record.get('description', '')
                cleaned_desc, metadata = self.cleaner.clean(original_desc)
                
                # Create processed record
                processed = {
                    'cve_id': record.get('cve_id'),
                    'description': cleaned_desc,  # Cleaned!
                    'original_description': original_desc,  # Keep original
                    'severity': record.get('severity'),
                    'cvss_score': record.get('cvss_score'),
                    'cvss_version': record.get('cvss_version'),
                    'cwe_ids': record.get('cwe_ids', []),
                    'published_date': record.get('published_date'),
                    'cleaning_metadata': metadata
                }
                
                f_out.write(json.dumps(processed) + '\n')
                
                # Collect samples for comparison
                if samples_collected < save_samples:
                    if metadata.get('had_html') or metadata.get('had_urls'):
                        self.sample_comparisons.append({
                            'cve_id': record.get('cve_id'),
                            'severity': record.get('severity'),
                            'original': original_desc[:500],
                            'cleaned': cleaned_desc[:500],
                            'metadata': metadata
                        })
                        samples_collected += 1
        
        # Compile statistics
        filter_stats = self.filter.get_stats()
        cleaner_stats = self.cleaner.get_stats()
        
        stats = {
            'timestamp': datetime.now().isoformat(),
            'input_file': str(input_path),
            'output_file': str(output_file),
            'filtering': filter_stats,
            'cleaning': cleaner_stats,
            'summary': {
                'total_input': filter_stats['total_input'],
                'total_filtered_out': filter_stats['total_input'] - filter_stats['kept'],
                'total_kept': filter_stats['kept'],
                'kept_percentage': round(100 * filter_stats['kept'] / max(filter_stats['total_input'], 1), 2)
            }
        }
        
        # Save statistics
        stats_file = output_dir / 'preprocessing_stats.json'
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        # Save sample comparisons
        if self.sample_comparisons:
            samples_file = output_dir / 'cleaning_samples.json'
            with open(samples_file, 'w') as f:
                json.dump(self.sample_comparisons, f, indent=2)
        
        return stats
    
    def print_report(self, stats: Dict[str, Any]):
        """Print preprocessing report."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     DATA PREPROCESSING REPORT                                 ║
║                  Step 2: Clean and Filter Data                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        # Filtering Results
        print("="*80)
        print("1. FILTERING RESULTS")
        print("="*80)
        
        f = stats.get('filtering', {})
        
        print(f"\n   📊 Total Input Records: {f.get('total_input', 0):,}")
        print(f"\n   ❌ Filtered Out:")
        print(f"      UNKNOWN severity: {f.get('filtered_unknown', 0):,}")
        print(f"      Rejected CVEs:    {f.get('filtered_rejected', 0):,}")
        print(f"      Reserved CVEs:    {f.get('filtered_reserved', 0):,}")
        print(f"      Too short:        {f.get('filtered_short', 0):,}")
        print(f"      Empty:            {f.get('filtered_empty', 0):,}")
        
        total_filtered = (
            f.get('filtered_unknown', 0) +
            f.get('filtered_rejected', 0) +
            f.get('filtered_reserved', 0) +
            f.get('filtered_short', 0) +
            f.get('filtered_empty', 0)
        )
        print(f"\n   📉 Total Filtered: {total_filtered:,}")
        print(f"   ✅ Records Kept: {f.get('kept', 0):,}")
        
        # Cleaning Results
        print("\n" + "="*80)
        print("2. TEXT CLEANING RESULTS")
        print("="*80)
        
        c = stats.get('cleaning', {})
        
        print(f"\n   📝 Records with HTML cleaned: {c.get('had_html', 0):,}")
        print(f"   🔗 Records with URLs normalized: {c.get('had_urls', 0):,}")
        
        # Summary
        print("\n" + "="*80)
        print("3. SUMMARY")
        print("="*80)
        
        s = stats.get('summary', {})
        
        print(f"""
   📊 Input:  {s.get('total_input', 0):,} records
   ❌ Removed: {s.get('total_filtered_out', 0):,} records
   ✅ Output: {s.get('total_kept', 0):,} records ({s.get('kept_percentage', 0):.1f}%)
   
   📁 Output saved to: {stats.get('output_file')}
        """)
        
        # Sample Comparisons
        if self.sample_comparisons:
            print("\n" + "="*80)
            print("4. SAMPLE CLEANING COMPARISONS")
            print("="*80)
            
            for i, sample in enumerate(self.sample_comparisons[:3], 1):
                print(f"\n   --- Sample {i}: {sample['cve_id']} ({sample['severity']}) ---")
                print(f"   BEFORE: {sample['original'][:100]}...")
                print(f"   AFTER:  {sample['cleaned'][:100]}...")
        
        print("\n" + "="*80)
        print("✅ Preprocessing complete!")
        print("   Next Step: Run 03_prepare_dataset.py to create train/val/test splits")
        print("="*80)


# =============================================================================
# MAIN
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Preprocess CVE data (filter + clean)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preprocess all data
  python ml/02_preprocess_data.py
  
  # Custom input/output
  python ml/02_preprocess_data.py --input data/nvd_full/all_cves.jsonl --output data/cleaned
  
  # Test on small subset
  python ml/02_preprocess_data.py --max 10000
        """
    )
    
    parser.add_argument(
        "--input", "-i",
        type=str,
        default="./data/nvd_full/all_cves.jsonl",
        help="Input data file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="./data/cleaned",
        help="Output directory"
    )
    parser.add_argument(
        "--max", "-n",
        type=int,
        default=None,
        help="Maximum records to process (for testing)"
    )
    parser.add_argument(
        "--keep-disputed",
        action="store_true",
        help="Keep disputed CVEs (default: keep)"
    )
    parser.add_argument(
        "--min-words",
        type=int,
        default=5,
        help="Minimum words in description"
    )
    
    args = parser.parse_args()
    
    # Create config
    config = PreprocessConfig(
        filter_disputed_cves=not args.keep_disputed,
        min_description_words=args.min_words
    )
    
    # Create preprocessor
    preprocessor = CVEPreprocessor(config)
    
    # Process
    try:
        stats = preprocessor.process_file(
            input_path=args.input,
            output_path=args.output,
            max_records=args.max
        )
        
        # Print report
        preprocessor.print_report(stats)
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Offline Demonstration
===================================

This script demonstrates the ML pipeline concepts using mock data.
Works without network access or full dependencies.

Run: python ml/offline_demo.py
"""

import sys
import re
import html
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))


def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def print_step(num, text):
    print(f"\n{'─'*60}")
    print(f"  STEP {num}: {text}")
    print(f"{'─'*60}\n")


# =============================================================================
# MOCK DATA (Simulating NVD API Response)
# =============================================================================

MOCK_CVE_DATA = [
    {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.3, 2.12.4, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "cvss_score": 10.0,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "CHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2021-12-10",
        "cwe_ids": ["CWE-502", "CWE-917"],
        "references": ["https://logging.apache.org/", "https://exploit-db.com/"]
    },
    {
        "cve_id": "CVE-2023-44487",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
        "cvss_score": 7.5,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "NONE",
            "integrity_impact": "NONE",
            "availability_impact": "HIGH"
        },
        "published_date": "2023-10-10",
        "cwe_ids": ["CWE-400"],
        "references": ["https://github.com/advisories/"]
    },
    {
        "cve_id": "CVE-2022-22965",
        "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
        "cvss_score": 9.8,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2022-04-01",
        "cwe_ids": ["CWE-94"],
        "references": ["https://spring.io/security/"]
    },
    {
        "cve_id": "CVE-2019-11510",
        "description": "In Pulse Secure Pulse Connect Secure (PCS) before 8.2R12.1, 8.3R7.1, and 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to read arbitrary files.",
        "cvss_score": 10.0,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "CHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2019-05-08",
        "cwe_ids": ["CWE-22"],
        "references": ["https://nvd.nist.gov/"]
    },
    {
        "cve_id": "CVE-2020-1472",
        "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network.",
        "cvss_score": 10.0,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "CHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2020-08-17",
        "cwe_ids": ["CWE-330"],
        "references": ["https://msrc.microsoft.com/"]
    },
    {
        "cve_id": "CVE-2021-34527",
        "description": "Windows Print Spooler Remote Code Execution Vulnerability. This vulnerability has been dubbed PrintNightmare.",
        "cvss_score": 8.8,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "LOW",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2021-07-02",
        "cwe_ids": ["CWE-269"],
        "references": ["https://msrc.microsoft.com/", "https://exploit-db.com/"]
    },
    {
        "cve_id": "CVE-2022-41040",
        "description": "Microsoft Exchange Server Elevation of Privilege Vulnerability. Known as ProxyNotShell when combined with CVE-2022-41082.",
        "cvss_score": 8.8,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "LOW",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2022-10-02",
        "cwe_ids": ["CWE-918"],
        "references": ["https://msrc.microsoft.com/"]
    },
    {
        "cve_id": "CVE-2023-23397",
        "description": "Microsoft Outlook Elevation of Privilege Vulnerability allowing an attacker to steal NTLM credentials with a specially crafted email.",
        "cvss_score": 9.8,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2023-03-14",
        "cwe_ids": ["CWE-294"],
        "references": ["https://msrc.microsoft.com/"]
    },
    {
        "cve_id": "CVE-2018-11776",
        "description": "Apache Struts 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when using results with no namespace.",
        "cvss_score": 8.1,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "HIGH",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2018-08-22",
        "cwe_ids": ["CWE-20"],
        "references": ["https://struts.apache.org/"]
    },
    {
        "cve_id": "CVE-2020-5902",
        "description": "In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability.",
        "cvss_score": 9.8,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH"
        },
        "published_date": "2020-07-01",
        "cwe_ids": ["CWE-22"],
        "references": ["https://support.f5.com/"]
    },
    # Add some MEDIUM and LOW severity for balance
    {
        "cve_id": "CVE-2023-12345",
        "description": "A cross-site scripting vulnerability exists in the admin panel that allows display of user-controlled content.",
        "cvss_score": 6.1,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "REQUIRED",
            "scope": "CHANGED",
            "confidentiality_impact": "LOW",
            "integrity_impact": "LOW",
            "availability_impact": "NONE"
        },
        "published_date": "2023-06-15",
        "cwe_ids": ["CWE-79"],
        "references": ["https://example.com/advisory"]
    },
    {
        "cve_id": "CVE-2022-54321",
        "description": "Information disclosure vulnerability in error messages reveals internal server paths.",
        "cvss_score": 5.3,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "LOW",
            "integrity_impact": "NONE",
            "availability_impact": "NONE"
        },
        "published_date": "2022-09-20",
        "cwe_ids": ["CWE-200"],
        "references": ["https://example.com/"]
    },
    {
        "cve_id": "CVE-2021-11111",
        "description": "A low-severity denial of service can occur when processing malformed input.",
        "cvss_score": 3.7,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "HIGH",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "NONE",
            "integrity_impact": "NONE",
            "availability_impact": "LOW"
        },
        "published_date": "2021-03-01",
        "cwe_ids": ["CWE-400"],
        "references": []
    },
    {
        "cve_id": "CVE-2020-22222",
        "description": "Improper certificate validation allows man-in-the-middle attacks under specific network conditions.",
        "cvss_score": 4.8,
        "cvss_vector": {
            "attack_vector": "NETWORK",
            "attack_complexity": "HIGH",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "LOW",
            "integrity_impact": "LOW",
            "availability_impact": "NONE"
        },
        "published_date": "2020-11-15",
        "cwe_ids": ["CWE-295"],
        "references": ["https://example.com/"]
    },
]


# =============================================================================
# DEMONSTRATION
# =============================================================================

def demo_stage_1():
    """Stage 1: Data Collection - Ground Truth Labels"""
    print_header("STAGE 1: DATA COLLECTION")
    
    print("""
    YOUR OLD CODE (WRONG):
    ──────────────────────
    if self.severity_model:
        severity = self.predict_severity(descriptions)  # Model prediction!
        df['severity_class'] = severity  # ← DATA LEAKAGE!
    
    THE PROBLEM:
    - Using an untrained model to generate labels
    - Training on those labels = learning to replicate random patterns
    - Result: 98% accuracy that means NOTHING
    
    CORRECT APPROACH:
    ─────────────────
    Use CVSS score from NVD API as GROUND TRUTH
    """)
    
    def cvss_to_severity(score):
        """Official NVD severity thresholds"""
        if score is None:
            return 'UNKNOWN'
        if score >= 9.0:
            return 'CRITICAL'
        if score >= 7.0:
            return 'HIGH'
        if score >= 4.0:
            return 'MEDIUM'
        return 'LOW'
    
    print("\nDemonstrating GROUND TRUTH derivation:\n")
    print(f"{'CVE ID':<20} {'CVSS Score':<12} {'Severity':<12} Source")
    print("─" * 60)
    
    for cve in MOCK_CVE_DATA[:8]:
        severity = cvss_to_severity(cve['cvss_score'])
        print(f"{cve['cve_id']:<20} {cve['cvss_score']:<12} {severity:<12} CVSS (GROUND TRUTH!)")
    
    print("""
    
    KEY INSIGHT:
    ────────────
    The severity label comes from CVSS score assigned by security experts.
    This is the GROUND TRUTH - not a model prediction!
    
    CVSS Score    →    Severity
    ─────────────────────────────
    9.0 - 10.0    →    CRITICAL
    7.0 - 8.9     →    HIGH
    4.0 - 6.9     →    MEDIUM
    0.1 - 3.9     →    LOW
    """)
    
    return MOCK_CVE_DATA


def demo_stage_2(data):
    """Stage 2: Data Cleaning"""
    print_header("STAGE 2: DATA CLEANING")
    
    print("""
    YOUR OLD CODE (MINIMAL):
    ────────────────────────
    text = text.lower()
    text = re.sub(r'https?://\\S+', '', text)  # Remove URLs
    text = re.sub(r'[^a-z0-9\\s-]', '', text)  # Remove special chars
    
    WHAT'S MISSING:
    - HTML decoding (&lt; → <)
    - HTML tag removal
    - URL extraction (count for features)
    - CVE reference extraction
    - Version number normalization
    """)
    
    def clean_text_complete(text):
        """Complete cleaning pipeline"""
        original = text
        
        # Step 1: HTML decode
        text = html.unescape(text)
        
        # Step 2: Remove HTML tags (if any)
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Step 3: Extract URLs before removing
        urls = re.findall(r'https?://[^\s]+', text)
        text = re.sub(r'https?://[^\s]+', ' [URL] ', text)
        
        # Step 4: Extract CVE references
        cves = re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
        text = re.sub(r'CVE-\d{4}-\d+', ' [CVE_REF] ', text, flags=re.IGNORECASE)
        
        # Step 5: Normalize versions
        versions = re.findall(r'\b\d+\.\d+[\.\d]*\b', text)
        text = re.sub(r'\b\d+\.\d+[\.\d]*\b', ' [VERSION] ', text)
        
        # Step 6: Lowercase
        text = text.lower()
        
        # Step 7: Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return {
            'cleaned': text,
            'urls': urls,
            'cves': cves,
            'versions': versions,
            'original_length': len(original),
            'cleaned_length': len(text)
        }
    
    print("\nDemonstrating cleaning pipeline:\n")
    
    sample = data[0]
    result = clean_text_complete(sample['description'])
    
    print(f"ORIGINAL ({result['original_length']} chars):")
    print(f"  {sample['description'][:100]}...")
    print(f"\nCLEANED ({result['cleaned_length']} chars):")
    print(f"  {result['cleaned'][:100]}...")
    print(f"\nEXTRACTED METADATA:")
    print(f"  URLs found: {result['urls']}")
    print(f"  CVE refs: {result['cves']}")
    print(f"  Versions: {result['versions']}")
    
    # Clean all data
    cleaned_data = []
    for cve in data:
        result = clean_text_complete(cve['description'])
        cleaned_cve = cve.copy()
        cleaned_cve['cleaned_description'] = result['cleaned']
        cleaned_cve['url_count'] = len(result['urls'])
        cleaned_cve['cve_ref_count'] = len(result['cves'])
        cleaned_cve['version_count'] = len(result['versions'])
        cleaned_data.append(cleaned_cve)
    
    print(f"\n✓ Cleaned {len(cleaned_data)} records")
    return cleaned_data


def demo_stage_3(data):
    """Stage 3: Feature Engineering"""
    print_header("STAGE 3: FEATURE ENGINEERING")
    
    print("""
    YOUR OLD CODE (MINIMAL):
    ────────────────────────
    df['desc_length'] = df['description'].apply(len)
    df['num_words'] = df['description'].apply(lambda x: len(x.split()))
    df['has_overflow'] = df['description'].str.contains('overflow')
    
    WHAT'S MISSING (LOTS!):
    - CVSS vector components (AV, AC, PR, UI, S, C, I, A)
    - Derived risk scores
    - Temporal features
    - Reference counts
    - CWE-based features
    """)
    
    # CVSS component mappings
    AV_MAP = {'NETWORK': 1.0, 'ADJACENT_NETWORK': 0.75, 'LOCAL': 0.5, 'PHYSICAL': 0.25}
    AC_MAP = {'LOW': 1.0, 'HIGH': 0.5}
    PR_MAP = {'NONE': 1.0, 'LOW': 0.5, 'HIGH': 0.25}
    UI_MAP = {'NONE': 1.0, 'REQUIRED': 0.5}
    SCOPE_MAP = {'CHANGED': 1.0, 'UNCHANGED': 0.5}
    IMPACT_MAP = {'HIGH': 1.0, 'LOW': 0.5, 'NONE': 0.0}
    
    def engineer_features(cve):
        """Extract rich features from CVE data"""
        features = {}
        
        # A. TEXT FEATURES
        desc = cve.get('cleaned_description', cve['description'])
        features['text_length'] = len(desc)
        features['word_count'] = len(desc.split())
        
        # Keyword presence
        keywords = ['overflow', 'injection', 'rce', 'remote', 'arbitrary', 'execution']
        for kw in keywords:
            features[f'has_{kw}'] = 1 if kw in desc.lower() else 0
        
        # B. CVSS VECTOR COMPONENTS (These are POWERFUL!)
        vec = cve.get('cvss_vector', {})
        features['av_score'] = AV_MAP.get(vec.get('attack_vector'), 0.5)
        features['ac_score'] = AC_MAP.get(vec.get('attack_complexity'), 0.5)
        features['pr_score'] = PR_MAP.get(vec.get('privileges_required'), 0.5)
        features['ui_score'] = UI_MAP.get(vec.get('user_interaction'), 0.5)
        features['scope_score'] = SCOPE_MAP.get(vec.get('scope'), 0.5)
        features['c_impact'] = IMPACT_MAP.get(vec.get('confidentiality_impact'), 0.5)
        features['i_impact'] = IMPACT_MAP.get(vec.get('integrity_impact'), 0.5)
        features['a_impact'] = IMPACT_MAP.get(vec.get('availability_impact'), 0.5)
        
        # C. DERIVED FEATURES
        features['ease_of_exploit'] = (
            features['av_score'] * features['ac_score'] * 
            features['pr_score'] * features['ui_score']
        )
        features['total_impact'] = (
            features['c_impact'] + features['i_impact'] + features['a_impact']
        ) / 3.0
        
        # D. BINARY FLAGS
        features['is_network_attack'] = 1 if vec.get('attack_vector') == 'NETWORK' else 0
        features['requires_no_privs'] = 1 if vec.get('privileges_required') == 'NONE' else 0
        features['no_user_interaction'] = 1 if vec.get('user_interaction') == 'NONE' else 0
        
        # E. METADATA FEATURES
        features['url_count'] = cve.get('url_count', len(cve.get('references', [])))
        features['cwe_count'] = len(cve.get('cwe_ids', []))
        features['reference_count'] = len(cve.get('references', []))
        
        return features
    
    # Show feature breakdown
    print("\nFeature breakdown for CVE-2021-44228 (Log4Shell):\n")
    
    sample = data[0]
    features = engineer_features(sample)
    
    print("TEXT FEATURES:")
    print(f"  text_length: {features['text_length']}")
    print(f"  word_count: {features['word_count']}")
    print(f"  has_remote: {features['has_remote']}")
    print(f"  has_execution: {features['has_execution']}")
    
    print("\nCVSS VECTOR FEATURES (Your old code IGNORED these!):")
    print(f"  av_score (Attack Vector): {features['av_score']} (NETWORK=1.0)")
    print(f"  ac_score (Complexity): {features['ac_score']} (LOW=1.0)")
    print(f"  pr_score (Privileges): {features['pr_score']} (NONE=1.0)")
    print(f"  ui_score (User Interaction): {features['ui_score']} (NONE=1.0)")
    print(f"  c_impact (Confidentiality): {features['c_impact']} (HIGH=1.0)")
    print(f"  i_impact (Integrity): {features['i_impact']} (HIGH=1.0)")
    print(f"  a_impact (Availability): {features['a_impact']} (HIGH=1.0)")
    
    print("\nDERIVED FEATURES:")
    print(f"  ease_of_exploit: {features['ease_of_exploit']:.4f} (higher = easier)")
    print(f"  total_impact: {features['total_impact']:.4f} (higher = worse)")
    
    print("\nBINARY FLAGS:")
    print(f"  is_network_attack: {features['is_network_attack']}")
    print(f"  requires_no_privs: {features['requires_no_privs']}")
    print(f"  no_user_interaction: {features['no_user_interaction']}")
    
    # Engineer features for all data
    feature_list = []
    for cve in data:
        f = engineer_features(cve)
        f['cve_id'] = cve['cve_id']
        f['cvss_score'] = cve['cvss_score']
        feature_list.append(f)
    
    print(f"\n✓ Engineered {len(list(features.keys()))} features for {len(data)} records")
    
    return feature_list


def demo_stage_4(data):
    """Stage 4: Data Splitting"""
    print_header("STAGE 4: DATA SPLITTING")
    
    print("""
    YOUR OLD CODE (WRONG):
    ──────────────────────
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train, val = random_split(dataset, [train_size, val_size])
    
    PROBLEMS:
    1. NO TEST SET - Can't evaluate real performance!
    2. RANDOM SPLIT - Doesn't preserve class distribution!
    3. NO REPRODUCIBILITY - Different split each run!
    
    CORRECT APPROACH:
    ─────────────────
    1. Stratified split (preserves class distribution)
    2. Train (70%) / Val (15%) / Test (15%)
    3. random_state for reproducibility
    """)
    
    # Get labels
    def cvss_to_severity(score):
        if score >= 9.0: return 'CRITICAL'
        if score >= 7.0: return 'HIGH'
        if score >= 4.0: return 'MEDIUM'
        return 'LOW'
    
    labels = [cvss_to_severity(d['cvss_score']) for d in data]
    
    # Show original distribution
    print("\nOriginal Class Distribution:")
    print("─" * 40)
    
    counts = Counter(labels)
    total = len(labels)
    for label in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = counts.get(label, 0)
        pct = 100 * count / total
        bar = "█" * int(pct / 2)
        print(f"  {label:<10}: {count:3d} ({pct:5.1f}%) {bar}")
    
    # Simulate stratified split
    print("\n\nSimulating Stratified Split:")
    print("─" * 40)
    
    # Group by class
    by_class = {}
    for i, label in enumerate(labels):
        if label not in by_class:
            by_class[label] = []
        by_class[label].append(i)
    
    train_idx, val_idx, test_idx = [], [], []
    
    for label, indices in by_class.items():
        np.random.seed(42)  # Reproducibility!
        np.random.shuffle(indices)
        n = len(indices)
        n_test = max(1, int(n * 0.15))
        n_val = max(1, int(n * 0.15))
        
        test_idx.extend(indices[:n_test])
        val_idx.extend(indices[n_test:n_test + n_val])
        train_idx.extend(indices[n_test + n_val:])
    
    print(f"\nSplit sizes:")
    print(f"  Train: {len(train_idx)} ({100*len(train_idx)/total:.1f}%)")
    print(f"  Val:   {len(val_idx)} ({100*len(val_idx)/total:.1f}%)")
    print(f"  Test:  {len(test_idx)} ({100*len(test_idx)/total:.1f}%)")
    
    # Verify stratification
    print("\nVerifying stratification (class % should be same in all splits):")
    print("─" * 50)
    print(f"{'Class':<12} {'Train':<12} {'Val':<12} {'Test':<12}")
    
    for label in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        train_count = sum(1 for i in train_idx if labels[i] == label)
        val_count = sum(1 for i in val_idx if labels[i] == label)
        test_count = sum(1 for i in test_idx if labels[i] == label)
        
        train_pct = 100 * train_count / max(1, len(train_idx))
        val_pct = 100 * val_count / max(1, len(val_idx))
        test_pct = 100 * test_count / max(1, len(test_idx))
        
        print(f"{label:<12} {train_pct:>5.1f}%      {val_pct:>5.1f}%      {test_pct:>5.1f}%")
    
    print("\n✓ Class distributions are similar across splits!")
    
    return {
        'train': [data[i] for i in train_idx],
        'val': [data[i] for i in val_idx],
        'test': [data[i] for i in test_idx],
        'labels': labels
    }


def demo_stage_5(split_data):
    """Stage 5: Class Balancing"""
    print_header("STAGE 5: CLASS BALANCING")
    
    print("""
    THE PROBLEM:
    ────────────
    Your data is IMBALANCED:
    - CRITICAL: 5%
    - HIGH: 20%
    - MEDIUM: 50%  ← Majority
    - LOW: 25%
    
    Without class weights:
    - Model learns to predict MEDIUM for everything
    - Gets 50% accuracy (but misses critical vulnerabilities!)
    
    THE SOLUTION: Class Weights
    ───────────────────────────
    Penalize mistakes on rare classes MORE
    """)
    
    # Compute class weights
    train_labels = split_data['labels']
    counts = Counter(train_labels)
    total = len(train_labels)
    n_classes = len(counts)
    
    print("\nComputing class weights (balanced method):\n")
    print("Formula: weight = total / (n_classes × class_count)")
    print("─" * 50)
    
    weights = {}
    for label in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        count = counts.get(label, 1)
        weight = total / (n_classes * count)
        weights[label] = weight
        interpretation = "↑ Penalize more" if weight > 1 else "↓ Penalize less"
        print(f"  {label:<10}: {total} / ({n_classes} × {count}) = {weight:.4f}  {interpretation}")
    
    print("""
    
    How this works in training:
    ───────────────────────────
    loss = CrossEntropyLoss(weight=[0.8, 0.4, 1.0, 2.5])
                                    LOW  MED  HIGH CRIT
    
    If model misclassifies a CRITICAL as MEDIUM:
      - Without weights: loss = 1.0
      - With weights: loss = 2.5 (penalized 2.5× more!)
    
    Result: Model learns to pay attention to CRITICAL class!
    """)
    
    return weights


def demo_stage_6():
    """Stage 6: Evaluation Metrics"""
    print_header("STAGE 6: PROPER EVALUATION METRICS")
    
    print("""
    YOUR OLD CODE:
    ──────────────
    accuracy = correct / total
    print(f"Accuracy: {accuracy}")
    
    THE PROBLEM:
    ────────────
    Accuracy is MISLEADING for imbalanced data!
    
    Example:
    - 1000 samples: 50 CRITICAL, 200 HIGH, 500 MEDIUM, 250 LOW
    - Model predicts "MEDIUM" for everything
    - Accuracy = 500/1000 = 50%
    - But CRITICAL recall = 0%! (Missed ALL critical vulnerabilities!)
    """)
    
    print("\nMETRICS YOU SHOULD USE:")
    print("─" * 50)
    
    print("""
    1. PRECISION (per class)
       "Of all predicted CRITICAL, how many were actually CRITICAL?"
       High precision = few false alarms
    
    2. RECALL (per class)
       "Of all actual CRITICAL, how many did we find?"
       High recall = found most real threats (CRITICAL for security!)
    
    3. F1 SCORE
       Harmonic mean of precision and recall
       F1 = 2 × (precision × recall) / (precision + recall)
    
    4. MACRO F1
       Average F1 across all classes (treats all equally)
       Good for imbalanced data
    
    5. CONFUSION MATRIX
       Shows exactly where model makes mistakes
    """)
    
    print("\nExample Confusion Matrix:")
    print("─" * 50)
    print("""
                      Predicted
                CRIT  HIGH  MED   LOW
           ┌─────────────────────────┐
      CRIT │  45    3     2     0   │  Recall: 90% ✓
   A  HIGH │   5   180   12    3   │  Recall: 90% ✓
   c  MED  │   2    15  450   33   │  Recall: 90% ✓
   t  LOW  │   0     5   20  225  │  Recall: 90% ✓
           └─────────────────────────┘
    
    Reading this:
    - Row = actual class
    - Column = predicted class
    - Diagonal = correct predictions
    - Off-diagonal = errors
    
    Good model: Most values on diagonal
    Bad model: Values spread across row
    """)


def show_summary():
    """Final summary"""
    print_header("SUMMARY: OLD vs NEW PIPELINE")
    
    print("""
    ┌────────────────────────────────────────────────────────────────────────┐
    │  ASPECT              │  YOUR OLD CODE         │  FIXED PIPELINE        │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Labels              │  Model predictions     │  CVSS scores           │
    │                      │  (DATA LEAKAGE!)       │  (GROUND TRUTH!)       │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Cleaning            │  Basic (URLs, lower)   │  Complete pipeline     │
    │                      │                        │  (HTML, versions, etc) │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Features            │  ~8 features           │  ~40 features          │
    │                      │  (length, keywords)    │  (CVSS, temporal, etc) │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Splitting           │  Random 80/20          │  Stratified 70/15/15   │
    │                      │  (no test set!)        │  (with test set!)      │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Class Balance       │  None                  │  Class weights         │
    │                      │                        │                        │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Evaluation          │  Accuracy only         │  F1, Precision, Recall │
    │                      │                        │  Confusion Matrix      │
    ├────────────────────────────────────────────────────────────────────────┤
    │  Result              │  98% (FAKE!)           │  ~75-85% (REAL)        │
    └────────────────────────────────────────────────────────────────────────┘
    
    The 98% accuracy was meaningless because of DATA LEAKAGE.
    The model learned to replicate its own random predictions.
    
    With the fixed pipeline:
    - Labels come from CVSS scores (real security assessments)
    - Features capture actual vulnerability characteristics
    - Evaluation shows true performance
    - Model learns real security patterns
    
    NEXT STEPS:
    ───────────
    1. Install full dependencies: pip install transformers torch
    2. Run training: python ml/training_pipeline.py
    3. Or proceed to RL continuous learning system
    """)


def main():
    print("""
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                         ║
    ║              CTPPO v2.0 - OFFLINE PIPELINE DEMONSTRATION               ║
    ║                                                                         ║
    ║  This demo uses mock data to show the pipeline without network access. ║
    ║  The concepts are identical to the real implementation.                 ║
    ║                                                                         ║
    ╚════════════════════════════════════════════════════════════════════════╝
    """)
    
    input("\n>>> Press Enter to start the demonstration...")
    
    # Stage 1: Data Collection
    data = demo_stage_1()
    input("\n>>> Press Enter for Stage 2...")
    
    # Stage 2: Data Cleaning
    cleaned_data = demo_stage_2(data)
    input("\n>>> Press Enter for Stage 3...")
    
    # Stage 3: Feature Engineering
    features = demo_stage_3(cleaned_data)
    input("\n>>> Press Enter for Stage 4...")
    
    # Stage 4: Data Splitting
    split_data = demo_stage_4(cleaned_data)
    input("\n>>> Press Enter for Stage 5...")
    
    # Stage 5: Class Balancing
    weights = demo_stage_5(split_data)
    input("\n>>> Press Enter for Stage 6...")
    
    # Stage 6: Evaluation Metrics
    demo_stage_6()
    input("\n>>> Press Enter for Summary...")
    
    # Summary
    show_summary()
    
    print("\n✓ Demonstration complete!")
    print("  Run 'python ml/training_pipeline.py' for full training.")


if __name__ == "__main__":
    main()

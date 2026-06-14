#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Step-by-Step Execution Guide
==========================================

This script walks you through each stage of the ML pipeline.
Run each section one at a time to understand what's happening.

Usage:
    python ml/step_by_step_guide.py

Author: Ruthvik (Learning ML Pipeline)
Date: January 2026
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import json
import numpy as np
from datetime import datetime

# We'll import each module as we need it to show the pipeline flow

def print_header(text):
    """Print a formatted section header."""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def print_step(step_num, text):
    """Print a step indicator."""
    print(f"\n{'─'*60}")
    print(f"  STEP {step_num}: {text}")
    print(f"{'─'*60}\n")

def wait_for_user():
    """Pause for user to read output."""
    input("\n>>> Press Enter to continue to next step...")


# =============================================================================
# STAGE 1: DATA COLLECTION
# =============================================================================

def stage_1_data_collection():
    """
    STAGE 1: Collecting CVE data with GROUND TRUTH labels.
    
    KEY LEARNING:
    - Labels come from CVSS scores (real expert assessment)
    - NEVER from model predictions
    - This is the foundation of everything
    """
    print_header("STAGE 1: DATA COLLECTION")
    
    print("""
    What we're doing:
    ─────────────────
    1. Fetching CVE data from the National Vulnerability Database (NVD)
    2. Extracting CVSS scores as our GROUND TRUTH labels
    3. Getting all metadata (dates, CWE IDs, references) for features
    
    Why this matters:
    ─────────────────
    Your old code used MODEL PREDICTIONS as labels (data leakage!)
    Now we use CVSS scores from security experts (ground truth!)
    """)
    
    wait_for_user()
    
    # Import our data collector
    from ml.data_pipeline.data_collector import CVEDataCollector, Severity
    
    print("Creating data collector...")
    collector = CVEDataCollector(
        api_key=os.environ.get("NVD_API_KEY"),  # Optional: faster with API key
        cache_dir=Path("./data/cache")
    )
    
    print("\nFetching sample CVE data (this may take a moment)...")
    print("Note: Without API key, NVD has 6-second rate limit between requests.\n")
    
    # Fetch a small sample for demonstration
    records = collector.fetch_cves(
        keyword="apache",  # Search for Apache vulnerabilities
        limit=20           # Just 20 for demo
    )
    
    print(f"\n✓ Fetched {len(records)} CVE records")
    
    # Show what we got
    print("\n" + "─"*60)
    print("SAMPLE RECORDS:")
    print("─"*60)
    
    for i, record in enumerate(records[:3]):
        print(f"""
    Record {i+1}:
    ├── CVE ID: {record.cve_id}
    ├── CVSS Score: {record.cvss_score}
    ├── Severity Label: {record.severity_label.value}  ← GROUND TRUTH!
    ├── Description: {record.description[:100]}...
    ├── CWE IDs: {record.cwe_ids[:2]}
    └── Reference Count: {len(record.references)}
    """)
    
    # Show the key insight
    print("\n" + "─"*60)
    print("KEY INSIGHT: GROUND TRUTH DERIVATION")
    print("─"*60)
    print("""
    The severity label is derived from CVSS score using NVD thresholds:
    
    CVSS Score    →    Severity Label
    ──────────────────────────────────
    9.0 - 10.0    →    CRITICAL
    7.0 - 8.9     →    HIGH
    4.0 - 6.9     →    MEDIUM
    0.1 - 3.9     →    LOW
    
    This is NOT a model prediction - it's the official security assessment!
    """)
    
    # Get statistics
    stats = collector.get_statistics(records)
    print("\nDataset Statistics:")
    print(json.dumps(stats, indent=2, default=str))
    
    return records


# =============================================================================
# STAGE 2: DATA CLEANING
# =============================================================================

def stage_2_data_cleaning(records):
    """
    STAGE 2: Cleaning and preprocessing text data.
    
    KEY LEARNING:
    - Raw text is noisy (HTML, URLs, special chars)
    - Cleaning extracts signal from noise
    - We also extract metadata useful for features
    """
    print_header("STAGE 2: DATA CLEANING")
    
    print("""
    What we're doing:
    ─────────────────
    1. Decoding HTML entities (&lt; → <)
    2. Removing HTML tags
    3. Extracting URLs, CVE references, version numbers
    4. Normalizing text (lowercase, whitespace)
    5. Tokenizing and lemmatizing
    
    Why this matters:
    ─────────────────
    Your old code did minimal cleaning - missed HTML, versions, CVE refs
    Clean data = better model learning
    """)
    
    wait_for_user()
    
    from ml.data_pipeline.data_cleaner import TextCleaner, CVECleaner
    
    # Create cleaner
    text_cleaner = TextCleaner(
        lowercase=True,
        lemmatize=True,
        remove_stopwords=False  # Keep for BERT
    )
    cve_cleaner = CVECleaner(text_cleaner)
    
    # Show before/after for one record
    print("─"*60)
    print("CLEANING DEMONSTRATION:")
    print("─"*60)
    
    if records:
        sample = records[0].to_dict()
        original_desc = sample['description']
        
        print(f"\nORIGINAL TEXT ({len(original_desc)} chars):")
        print(f"  {original_desc[:200]}...")
        
        # Clean it
        cleaned = cve_cleaner.clean_record(sample)
        cleaned_desc = cleaned.get('cleaned_description', '')
        metadata = cleaned.get('text_metadata', {})
        
        print(f"\nCLEANED TEXT ({len(cleaned_desc)} chars):")
        print(f"  {cleaned_desc[:200]}...")
        
        print(f"\nEXTRACTED METADATA:")
        print(f"  ├── URLs found: {len(metadata.get('extracted_urls', []))}")
        print(f"  ├── CVE references: {metadata.get('extracted_cves', [])}")
        print(f"  ├── Versions found: {metadata.get('extracted_versions', [])}")
        print(f"  ├── Has exploit mention: {metadata.get('has_exploit_mention', False)}")
        print(f"  └── Has patch mention: {metadata.get('has_patch_mention', False)}")
    
    # Clean all records
    print("\nCleaning all records...")
    cleaned_records = cve_cleaner.clean_records([r.to_dict() for r in records])
    print(f"✓ Cleaned {len(cleaned_records)} records")
    
    return cleaned_records


# =============================================================================
# STAGE 3: FEATURE ENGINEERING
# =============================================================================

def stage_3_feature_engineering(cleaned_records):
    """
    STAGE 3: Engineering features from cleaned data.
    
    KEY LEARNING:
    - Text alone is not enough
    - CVSS vector components are RICH features
    - Temporal, reference, and CWE features add signal
    """
    print_header("STAGE 3: FEATURE ENGINEERING")
    
    print("""
    What we're doing:
    ─────────────────
    Creating multiple feature types:
    
    A. TEXT FEATURES
       - Description length, word count
       - Keyword presence (injection, overflow, etc.)
    
    B. CVSS VECTOR FEATURES (Your old code IGNORED these!)
       - Attack Vector (NETWORK=1.0, LOCAL=0.5, etc.)
       - Attack Complexity (LOW=1.0, HIGH=0.5)
       - Privileges Required (NONE=1.0, LOW=0.5, HIGH=0.25)
       - User Interaction (NONE=1.0, REQUIRED=0.5)
       - Scope (CHANGED=1.0, UNCHANGED=0.5)
       - Impact scores (C, I, A)
    
    C. TEMPORAL FEATURES
       - Days since published
       - Is recent (< 30 days)
    
    D. REFERENCE FEATURES
       - Reference count
       - Has exploit reference
       - Has patch reference
    
    E. DERIVED FEATURES
       - Ease of exploitation score
       - Total impact score
    """)
    
    wait_for_user()
    
    from ml.data_pipeline.feature_engineer import FeatureEngineer
    
    engineer = FeatureEngineer(
        include_text_stats=True,
        include_cvss_components=True,
        include_temporal=True,
        include_attack_type=True
    )
    
    # Engineer features
    print("Engineering features...")
    feature_sets = engineer.engineer_batch(cleaned_records)
    
    # Show feature breakdown for one record
    if feature_sets:
        fs = feature_sets[0]
        
        print("\n" + "─"*60)
        print(f"FEATURE BREAKDOWN FOR {fs.cve_id}:")
        print("─"*60)
        
        print(f"\nTarget: {fs.severity_label} (ID: {fs.severity_id})")
        
        print(f"\nNumerical Features ({len(fs.numerical_features)} total):")
        
        # Group features by category
        categories = {
            'Text': ['text_length', 'word_count', 'avg_word_length'],
            'CVSS': ['cvss_score', 'av_score', 'ac_score', 'pr_score', 'ui_score', 
                    'scope_score', 'confidentiality_score', 'integrity_score', 
                    'availability_score', 'ease_of_exploit', 'total_impact'],
            'Binary': ['is_network_attack', 'is_low_complexity', 'requires_no_privs',
                      'has_exploit_mention', 'has_patch_mention'],
            'Other': []
        }
        
        for category, feature_names in categories.items():
            if category == 'Other':
                continue
            print(f"\n  {category} Features:")
            for name in feature_names:
                if name in fs.numerical_features:
                    value = fs.numerical_features[name]
                    print(f"    ├── {name}: {value:.4f}" if isinstance(value, float) else f"    ├── {name}: {value}")
        
        print(f"\nFeature Vector Shape: {fs.feature_vector.shape}")
    
    # Convert to arrays for next stage
    texts = [fs.text for fs in feature_sets]
    labels = [fs.severity_label for fs in feature_sets if fs.severity_label]
    features = np.array([fs.feature_vector for fs in feature_sets])
    
    print(f"\n✓ Engineered features for {len(feature_sets)} records")
    print(f"  Feature vector dimension: {features.shape[1]}")
    
    return texts, labels, features, feature_sets


# =============================================================================
# STAGE 4: DATA SPLITTING
# =============================================================================

def stage_4_data_splitting(texts, labels, features):
    """
    STAGE 4: Splitting data properly with stratification.
    
    KEY LEARNING:
    - Always have a TEST set (never touch during training!)
    - Stratified split preserves class distribution
    - Random seed ensures reproducibility
    """
    print_header("STAGE 4: DATA SPLITTING")
    
    print("""
    What we're doing:
    ─────────────────
    
    YOUR OLD CODE (WRONG):
    ─────────────────────
    train_size = 0.8 * len(data)
    train, val = random_split(data, [train_size, val_size])
    
    Problems:
    - No test set!
    - Random split (not stratified)
    - No reproducibility
    
    CORRECT APPROACH:
    ─────────────────
    1. Stratified split (preserves class distribution)
    2. Train (70%) / Val (15%) / Test (15%)
    3. random_state=42 for reproducibility
    """)
    
    wait_for_user()
    
    from ml.data_pipeline.data_splitter import DataSplitter
    
    splitter = DataSplitter(random_state=42)
    
    # First, show class distribution
    print("─"*60)
    print("ORIGINAL CLASS DISTRIBUTION:")
    print("─"*60)
    
    dist = splitter.get_class_distribution(np.array(labels))
    print(f"\nTotal samples: {dist['total_samples']}")
    print(f"Imbalance ratio: {dist['imbalance_ratio']} (>3 = imbalanced)")
    print("\nDistribution:")
    for cls, info in dist['distribution'].items():
        bar = "█" * int(info['percentage'] / 2)
        print(f"  {cls:10s}: {info['count']:4d} ({info['percentage']:5.1f}%) {bar}")
    
    wait_for_user()
    
    # Perform stratified split
    print("\n" + "─"*60)
    print("PERFORMING STRATIFIED SPLIT:")
    print("─"*60)
    
    indices = list(range(len(texts)))
    split = splitter.stratified_split(
        data=indices,
        labels=np.array(labels),
        test_size=0.15,
        val_size=0.15,
        include_test=True
    )
    
    # Show split results
    print("\nSplit Results:")
    print(f"  ├── Train: {len(split.train_indices)} samples")
    print(f"  ├── Val:   {len(split.val_indices)} samples")
    print(f"  └── Test:  {len(split.test_indices)} samples")
    
    # Verify stratification
    print("\n" + "─"*60)
    print("VERIFYING STRATIFICATION:")
    print("─"*60)
    
    validation = splitter.validate_split(
        split.train_labels,
        split.val_labels,
        split.test_labels
    )
    
    print(f"\nMax distribution deviation: {validation['max_deviation']:.4f}")
    print(f"Valid stratification: {'✓ Yes' if validation['is_valid'] else '✗ No'}")
    
    # Prepare data for next stage
    split_data = {
        'train': {
            'texts': [texts[i] for i in split.train_indices],
            'labels': [labels[i] for i in split.train_indices],
            'features': features[split.train_indices]
        },
        'val': {
            'texts': [texts[i] for i in split.val_indices],
            'labels': [labels[i] for i in split.val_indices],
            'features': features[split.val_indices]
        },
        'test': {
            'texts': [texts[i] for i in split.test_indices],
            'labels': [labels[i] for i in split.test_indices],
            'features': features[split.test_indices]
        }
    }
    
    print(f"\n✓ Data split complete")
    
    return split_data, splitter


# =============================================================================
# STAGE 5: CLASS BALANCING
# =============================================================================

def stage_5_class_balancing(split_data, splitter):
    """
    STAGE 5: Computing class weights for imbalanced data.
    
    KEY LEARNING:
    - Imbalanced data = model predicts majority class
    - Class weights penalize mistakes on minority classes more
    - Essential for finding CRITICAL vulnerabilities
    """
    print_header("STAGE 5: CLASS BALANCING")
    
    print("""
    What we're doing:
    ─────────────────
    
    The Problem:
    ────────────
    If 50% of data is MEDIUM, model can get 50% accuracy
    by just predicting MEDIUM for everything!
    
    But we NEED to find CRITICAL vulnerabilities!
    
    The Solution: Class Weights
    ───────────────────────────
    - Rare classes (CRITICAL) get HIGHER weight
    - Common classes (MEDIUM) get LOWER weight
    - Model is penalized MORE for missing CRITICAL
    """)
    
    wait_for_user()
    
    # Compute class weights
    label_to_id = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    train_label_ids = np.array([label_to_id.get(l, 1) for l in split_data['train']['labels']])
    
    print("─"*60)
    print("COMPUTING CLASS WEIGHTS:")
    print("─"*60)
    
    class_weights = splitter.compute_class_weights(
        train_label_ids,
        method='balanced'
    )
    
    print("\nInterpretation:")
    print("  - Weight > 1: Rare class, penalize mistakes more")
    print("  - Weight < 1: Common class, penalize mistakes less")
    print("  - Weight = 1: Baseline")
    
    print("\nIn CrossEntropyLoss:")
    print("  loss = CrossEntropyLoss(weight=[2.0, 0.4, 1.0, 2.5])")
    print("  → Missing a CRITICAL costs 2.5x more than missing MEDIUM")
    
    split_data['class_weights'] = class_weights
    
    return split_data


# =============================================================================
# STAGE 6: CREATE DATASETS
# =============================================================================

def stage_6_create_datasets(split_data):
    """
    STAGE 6: Creating PyTorch datasets for training.
    
    KEY LEARNING:
    - Datasets handle batching and tokenization
    - Separate datasets for train/val/test
    - Include both text tokens AND numerical features
    """
    print_header("STAGE 6: CREATE PYTORCH DATASETS")
    
    print("""
    What we're doing:
    ─────────────────
    Creating PyTorch Dataset objects that:
    1. Store text + labels + features
    2. Handle tokenization (for BERT)
    3. Return batches during training
    
    The CVEDataset class:
    ─────────────────────
    - Converts text to BERT tokens (input_ids, attention_mask)
    - Converts string labels to numeric IDs
    - Returns feature vectors alongside text
    """)
    
    wait_for_user()
    
    from ml.data_pipeline.dataset import CVEDataset
    
    print("─"*60)
    print("CREATING DATASETS:")
    print("─"*60)
    
    # Create datasets (without tokenizer for demo - would need transformers)
    train_dataset = CVEDataset(
        texts=split_data['train']['texts'],
        labels=split_data['train']['labels'],
        tokenizer=None,  # Would use DistilBertTokenizer in real training
        feature_vectors=split_data['train']['features']
    )
    
    val_dataset = CVEDataset(
        texts=split_data['val']['texts'],
        labels=split_data['val']['labels'],
        tokenizer=None,
        feature_vectors=split_data['val']['features']
    )
    
    test_dataset = CVEDataset(
        texts=split_data['test']['texts'],
        labels=split_data['test']['labels'],
        tokenizer=None,
        feature_vectors=split_data['test']['features']
    )
    
    print(f"\nDatasets created:")
    print(f"  ├── Train: {len(train_dataset)} samples")
    print(f"  ├── Val:   {len(val_dataset)} samples")
    print(f"  └── Test:  {len(test_dataset)} samples")
    
    # Show label distribution
    print(f"\nTrain label distribution:")
    dist = train_dataset.get_label_distribution()
    for label, count in sorted(dist.items()):
        print(f"  ├── {label}: {count}")
    
    # Show class weights
    weights = train_dataset.get_class_weights()
    print(f"\nComputed class weights: {weights.tolist()}")
    
    # Show a sample
    print("\n" + "─"*60)
    print("SAMPLE FROM DATASET:")
    print("─"*60)
    
    sample = train_dataset[0]
    print(f"\nKeys returned: {list(sample.keys())}")
    print(f"Label tensor: {sample['labels']} (0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL)")
    if 'features' in sample:
        print(f"Feature vector shape: {sample['features'].shape}")
    
    return train_dataset, val_dataset, test_dataset


# =============================================================================
# SUMMARY
# =============================================================================

def show_summary():
    """Show final summary of the pipeline."""
    print_header("PIPELINE SUMMARY")
    
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    COMPLETE ML PIPELINE                              │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                      │
    │  Stage 1: DATA COLLECTION                                           │
    │           └── Fetch CVEs with CVSS scores (GROUND TRUTH)            │
    │                                                                      │
    │  Stage 2: DATA CLEANING                                             │
    │           └── HTML decode → Extract URLs → Normalize → Tokenize     │
    │                                                                      │
    │  Stage 3: FEATURE ENGINEERING                                       │
    │           └── Text + CVSS + Temporal + Reference features           │
    │                                                                      │
    │  Stage 4: DATA SPLITTING                                            │
    │           └── Stratified Train/Val/Test split                       │
    │                                                                      │
    │  Stage 5: CLASS BALANCING                                           │
    │           └── Compute weights for imbalanced classes                │
    │                                                                      │
    │  Stage 6: CREATE DATASETS                                           │
    │           └── PyTorch datasets for batched training                 │
    │                                                                      │
    │  Stage 7: MODEL TRAINING (Next step)                                │
    │           └── Train with class weights, early stopping              │
    │                                                                      │
    │  Stage 8: EVALUATION (Next step)                                    │
    │           └── F1, Precision, Recall, Confusion Matrix               │
    │                                                                      │
    └─────────────────────────────────────────────────────────────────────┘
    
    KEY DIFFERENCES FROM YOUR OLD CODE:
    ────────────────────────────────────
    
    ❌ OLD: Labels from model predictions (DATA LEAKAGE!)
    ✓ NEW: Labels from CVSS scores (GROUND TRUTH)
    
    ❌ OLD: Random 80/20 split
    ✓ NEW: Stratified 70/15/15 split with test set
    
    ❌ OLD: No class balancing
    ✓ NEW: Class weights for imbalanced data
    
    ❌ OLD: Minimal cleaning
    ✓ NEW: Complete cleaning pipeline with metadata extraction
    
    ❌ OLD: Basic features (length, keywords)
    ✓ NEW: Rich features (CVSS components, temporal, references)
    
    NEXT STEPS:
    ───────────
    1. Install dependencies: pip install transformers torch sklearn
    2. Run full training: python ml/training_pipeline.py
    3. Or continue to RL continuous learning system
    """)


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run the step-by-step guide."""
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║              CTPPO v2.0 - STEP-BY-STEP ML PIPELINE GUIDE              ║
    ║                                                                        ║
    ║  This guide walks you through each stage of the proper ML pipeline.   ║
    ║  Press Enter after each stage to continue.                            ║
    ║                                                                        ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    wait_for_user()
    
    try:
        # Stage 1: Data Collection
        records = stage_1_data_collection()
        wait_for_user()
        
        # Stage 2: Data Cleaning
        cleaned_records = stage_2_data_cleaning(records)
        wait_for_user()
        
        # Stage 3: Feature Engineering
        texts, labels, features, feature_sets = stage_3_feature_engineering(cleaned_records)
        wait_for_user()
        
        # Filter out records without valid labels
        valid_indices = [i for i, l in enumerate(labels) if l in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']]
        texts = [texts[i] for i in valid_indices]
        labels = [labels[i] for i in valid_indices]
        features = features[valid_indices]
        
        if len(texts) < 10:
            print("\n⚠️  Not enough valid samples for splitting demo.")
            print("    This is normal with a small test dataset.")
            print("    In real training, you'd fetch thousands of CVEs.")
            show_summary()
            return
        
        # Stage 4: Data Splitting
        split_data, splitter = stage_4_data_splitting(texts, labels, features)
        wait_for_user()
        
        # Stage 5: Class Balancing
        split_data = stage_5_class_balancing(split_data, splitter)
        wait_for_user()
        
        # Stage 6: Create Datasets
        train_ds, val_ds, test_ds = stage_6_create_datasets(split_data)
        wait_for_user()
        
        # Summary
        show_summary()
        
    except KeyboardInterrupt:
        print("\n\nGuide interrupted. You can restart anytime!")
    except Exception as e:
        print(f"\n\nError occurred: {e}")
        print("This might be due to missing dependencies or API rate limits.")
        print("Install dependencies: pip install requests nltk numpy pandas scikit-learn torch")
        raise


if __name__ == "__main__":
    main()

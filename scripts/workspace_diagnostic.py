#!/usr/bin/env python3
"""
Varaksha Workspace Diagnostic Report
Analyzes data directory state, dataset characteristics, and data leakage indicators
"""

from pathlib import Path
import sys
from datetime import datetime

# Suppress warnings
import warnings
warnings.filterwarnings('ignore')

print("\n" + "="*80)
print("  VARAKSHA WORKSPACE DIAGNOSTIC REPORT")
print("  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print("="*80 + "\n")

# ==============================================================================
# SECTION 1: FILE TREE & INVENTORY
# ==============================================================================

print("\n" + "█"*80)
print("█ SECTION 1: WORKSPACE FILE INVENTORY")
print("█"*80 + "\n")

workspace_root = Path(__file__).parent.parent
datasets_path = workspace_root / "datasets_copy"

def build_file_tree(path, prefix="", max_depth=4, current_depth=0, exclude_dirs={".venv", "__pycache__", ".git", ".pytest_cache", "*.egg-info"}):
    """Recursively build file tree with descriptions"""
    if current_depth >= max_depth:
        return []
    
    items = []
    try:
        entries = sorted(path.iterdir())
    except PermissionError:
        return items
    
    dirs = [e for e in entries if e.is_dir() and e.name not in exclude_dirs]
    files = [e for e in entries if e.is_file()]
    
    # Process files
    for f in files:
        size_mb = f.stat().st_size / (1024*1024)
        size_str = f"{size_mb:.1f}MB" if size_mb > 1 else f"{f.stat().st_size/1024:.1f}KB"
        items.append(f"  {prefix}📄 {f.name:<40} {size_str:>10}")
    
    # Process directories
    for d in dirs:
        items.append(f"  {prefix}📁 {d.name}/")
        sub_items = build_file_tree(d, prefix + "   ", max_depth, current_depth+1, exclude_dirs)
        items.extend(sub_items)
    
    return items

print("PROJECT ROOT STRUCTURE:")
print(f"  📍 {workspace_root}\n")
tree_items = build_file_tree(workspace_root, max_depth=3)
for item in tree_items[:100]:  # Limit output
    print(item)

if len(tree_items) > 100:
    print(f"  ... and {len(tree_items)-100} more items")

# ==============================================================================
# SECTION 2: DATASET FILES DISCOVERY
# ==============================================================================

print("\n" + "█"*80)
print("█ SECTION 2: DATASET FILES DISCOVERY")
print("█"*80 + "\n")

parquet_files = {}
for pqt in datasets_path.rglob("*.parquet"):
    rel_path = pqt.relative_to(datasets_path)
    size_mb = pqt.stat().st_size / (1024*1024)
    parquet_files[str(rel_path)] = {
        "path": pqt,
        "size_mb": size_mb,
        "rows": "?"  # Will populate if we can load
    }

print(f"Found {len(parquet_files)} Parquet files:\n")
for name, info in sorted(parquet_files.items()):
    print(f"  📊 {name:<60} {info['size_mb']:>8.1f} MB")

# ==============================================================================
# SECTION 3: DATASET LOADING & ANALYSIS
# ==============================================================================

print("\n" + "█"*80)
print("█ SECTION 3: DATASET LOADING & ANALYSIS")
print("█"*80 + "\n")

try:
    import polars as pl
    print("✅ Using Polars for data loading\n")
    use_polars = True
except ImportError:
    try:
        import pandas as pd
        print("✅ Using Pandas for data loading\n")
        use_polars = False
    except ImportError:
        print("❌ ERROR: Neither Polars nor Pandas installed")
        sys.exit(1)

# Find training and holdout files
training_file = None
holdout_file = None

# Look for phase7 enriched files
for pqt_path in sorted(parquet_files.keys()):
    if "phase7_enriched" in pqt_path and "holdout" not in pqt_path:
        training_file = parquet_files[pqt_path]["path"]
    elif "phase7_holdout" in pqt_path or ("holdout" in pqt_path and "enriched" in pqt_path):
        holdout_file = parquet_files[pqt_path]["path"]

print(f"📖 Training Dataset: {training_file.relative_to(datasets_path) if training_file else 'NOT FOUND'}")
print(f"📖 Holdout Dataset:  {holdout_file.relative_to(datasets_path) if holdout_file else 'NOT FOUND'}\n")

if not training_file or not holdout_file:
    print("❌ ERROR: Could not find both training and holdout datasets")
    sys.exit(1)

# Load datasets
print("Loading datasets...\n")

if use_polars:
    df_train = pl.read_parquet(training_file)
    df_holdout = pl.read_parquet(holdout_file)
else:
    df_train = pd.read_parquet(training_file)
    df_holdout = pd.read_parquet(holdout_file)

# ==============================================================================
# SECTION 4: ROW & TARGET COUNTS
# ==============================================================================

print("█"*80)
print("█ SECTION 4: ROW & TARGET COUNTS")
print("█"*80 + "\n")

if use_polars:
    train_rows = len(df_train)
    train_fraud = df_train.filter(pl.col("fraud_flag") == 1).shape[0]
    train_legit = train_rows - train_fraud
    
    holdout_rows = len(df_holdout)
    holdout_fraud = df_holdout.filter(pl.col("fraud_flag") == 1).shape[0]
    holdout_legit = holdout_rows - holdout_fraud
else:
    train_rows = len(df_train)
    train_fraud = (df_train["fraud_flag"] == 1).sum()
    train_legit = train_rows - train_fraud
    
    holdout_rows = len(df_holdout)
    holdout_fraud = (df_holdout["fraud_flag"] == 1).sum()
    holdout_legit = holdout_rows - holdout_fraud

print("TRAINING DATASET:")
print(f"  Total rows:        {train_rows:>12,}")
print(f"  Fraud (flag=1):    {train_fraud:>12,}  ({100*train_fraud/train_rows:>5.2f}%)")
print(f"  Legitimate (0):    {train_legit:>12,}  ({100*train_legit/train_rows:>5.2f}%)\n")

print("HOLDOUT TEST DATASET:")
print(f"  Total rows:        {holdout_rows:>12,}")
print(f"  Fraud (flag=1):    {holdout_fraud:>12,}  ({100*holdout_fraud/holdout_rows:>5.2f}%)")
print(f"  Legitimate (0):    {holdout_legit:>12,}  ({100*holdout_legit/holdout_rows:>5.2f}%)\n")

# ==============================================================================
# SECTION 5: LEAKAGE CHECK - KEY FEATURES
# ==============================================================================

print("█"*80)
print("█ SECTION 5: DATA LEAKAGE CHECK - FRAUD CASE FEATURES")
print("█"*80 + "\n")

# Check for key features that might indicate leakage
key_features = ["receiver_unique_senders", "device_unique_receivers", "is_new_corridor"]

print("TRAINING SET - FRAUD CASES ONLY (fraud_flag == 1):\n")

if use_polars:
    df_train_fraud = df_train.filter(pl.col("fraud_flag") == 1)
    df_holdout_fraud = df_holdout.filter(pl.col("fraud_flag") == 1)
else:
    df_train_fraud = df_train[df_train["fraud_flag"] == 1]
    df_holdout_fraud = df_holdout[df_holdout["fraud_flag"] == 1]

for feature in key_features:
    if use_polars:
        if feature in df_train.columns:
            vals = df_train_fraud.select(feature).to_series().value_counts().sort("counts", descending=True)
            print(f"  Feature: {feature}")
            if len(vals) <= 10:
                print(vals.to_pandas().to_string().replace("\n", "\n    "))
            else:
                print(f"    [Top 10 of {len(vals)} unique values]")
                for idx, row in enumerate(vals.head(10).to_pandas().itertuples()):
                    print(f"    {row[0]:<20} : {row[1]:>6} cases")
            print()
    else:
        if feature in df_train.columns:
            vals = df_train_fraud[feature].value_counts()
            print(f"  Feature: {feature}")
            if len(vals) <= 10:
                for val, count in vals.head(10).items():
                    print(f"    {val:<20} : {count:>6} cases")
            else:
                print(f"    [Top 10 of {len(vals)} unique values]")
                for val, count in vals.head(10).items():
                    print(f"    {val:<20} : {count:>6} cases")
            print()

print("\nHOLDOUT SET - FRAUD CASES ONLY (fraud_flag == 1):\n")

for feature in key_features:
    if use_polars:
        if feature in df_holdout.columns:
            vals = df_holdout_fraud.select(feature).to_series().value_counts().sort("counts", descending=True)
            print(f"  Feature: {feature}")
            if len(vals) <= 10:
                print(vals.to_pandas().to_string().replace("\n", "\n    "))
            else:
                print(f"    [All {len(vals)} unique values]")
                for idx, row in enumerate(vals.to_pandas().itertuples()):
                    print(f"    {row[0]:<20} : {row[1]:>6} cases")
            print()
    else:
        if feature in df_holdout.columns:
            vals = df_holdout_fraud[feature].value_counts()
            print(f"  Feature: {feature}")
            if len(vals) <= 10:
                for val, count in vals.head(10).items():
                    print(f"    {val:<20} : {count:>6} cases")
            else:
                print(f"    [All {len(vals)} unique values]")
                for val, count in vals.items():
                    print(f"    {val:<20} : {count:>6} cases")
            print()

# ==============================================================================
# SECTION 6: DEVICE OVERLAP CHECK
# ==============================================================================

print("█"*80)
print("█ SECTION 6: DEVICE OVERLAP CHECK (GENERALIZATION RISK)")
print("█"*80 + "\n")

if use_polars:
    if "device_surrogate" in df_train.columns:
        train_devices = set(df_train.select("device_surrogate").to_series().unique().to_list())
        holdout_devices = set(df_holdout.select("device_surrogate").to_series().unique().to_list())
    else:
        print("❌ device_surrogate column not found")
        train_devices = set()
        holdout_devices = set()
else:
    if "device_surrogate" in df_train.columns:
        train_devices = set(df_train["device_surrogate"].unique())
        holdout_devices = set(df_holdout["device_surrogate"].unique())
    else:
        print("❌ device_surrogate column not found")
        train_devices = set()
        holdout_devices = set()

overlap = train_devices.intersection(holdout_devices)
new_devices = holdout_devices - train_devices

print(f"Training devices (unique device_surrogate):  {len(train_devices):>6,}")
print(f"Holdout devices (unique device_surrogate):   {len(holdout_devices):>6,}")
print(f"\nDevice overlap analysis:")
print(f"  Devices in BOTH train & holdout: {len(overlap):>6,}  ({100*len(overlap)/len(holdout_devices):>5.1f}% of holdout)")
print(f"  NEW devices in holdout:          {len(new_devices):>6,}  ({100*len(new_devices)/len(holdout_devices):>5.1f}% of holdout)")

if len(new_devices) == 0:
    print("\n  ⚠️  WARNING: 0% new devices in holdout!")
    print("      All holdout transactions use devices seen in training.")
    print("      This prevents testing generalization to new devices.")
else:
    print(f"\n  ✅ Good: Holdout contains {len(new_devices)} new devices for generalization testing.")

# ==============================================================================
# SECTION 7: FRAUD DEVICE ANALYSIS
# ==============================================================================

print("\n" + "█"*80)
print("█ SECTION 7: FRAUD DEVICE ANALYSIS")
print("█"*80 + "\n")

if use_polars:
    if "device_surrogate" in df_train_fraud.columns:
        train_fraud_devices = set(df_train_fraud.select("device_surrogate").to_series().unique().to_list())
        holdout_fraud_devices = set(df_holdout_fraud.select("device_surrogate").to_series().unique().to_list())
    else:
        train_fraud_devices = set()
        holdout_fraud_devices = set()
else:
    if "device_surrogate" in df_train_fraud.columns:
        train_fraud_devices = set(df_train_fraud["device_surrogate"].unique())
        holdout_fraud_devices = set(df_holdout_fraud["device_surrogate"].unique())
    else:
        train_fraud_devices = set()
        holdout_fraud_devices = set()

fraud_overlap = train_fraud_devices.intersection(holdout_fraud_devices)
new_fraud_devices = holdout_fraud_devices - train_fraud_devices

print(f"Training fraud cases (device_surrogate):     {len(train_fraud_devices):>6,} unique devices")
print(f"Holdout fraud cases (device_surrogate):      {len(holdout_fraud_devices):>6,} unique devices")
print(f"\nFraud device overlap:")
print(f"  Devices with fraud in BOTH:  {len(fraud_overlap):>6,}  ({100*len(fraud_overlap)/max(len(holdout_fraud_devices),1):>5.1f}% of holdout fraud)")
print(f"  NEW devices with fraud:      {len(new_fraud_devices):>6,}  ({100*len(new_fraud_devices)/max(len(holdout_fraud_devices),1):>5.1f}% of holdout fraud)")

# ==============================================================================
# SECTION 8: COLUMN SCHEMA
# ==============================================================================

print("\n" + "█"*80)
print("█ SECTION 8: DATASET COLUMN SCHEMA")
print("█"*80 + "\n")

if use_polars:
    cols = df_train.columns
    dtypes = [str(df_train[c].dtype) for c in cols]
else:
    cols = df_train.columns.tolist()
    dtypes = [str(df_train[c].dtype) for c in cols]

print(f"Total columns: {len(cols)}\n")
print("TRAINING DATASET SCHEMA:")
for i, (col, dtype) in enumerate(zip(cols, dtypes), 1):
    print(f"  {i:>2}. {col:<40} ({dtype})")

# ==============================================================================
# SECTION 9: SUMMARY & RECOMMENDATIONS
# ==============================================================================

print("\n" + "█"*80)
print("█ SECTION 9: DIAGNOSTIC SUMMARY & RECOMMENDATIONS")
print("█"*80 + "\n")

issues = []
warnings_list = []

# Check for data leakage
if use_polars:
    holdout_fraud_receivers = df_holdout_fraud.select("receiver_unique_senders").to_series().unique()
    if len(holdout_fraud_receivers) == 1:
        issues.append("🔴 CRITICAL: Holdout fraud cases have identical receiver_unique_senders value!")
        issues.append(f"    All {holdout_fraud} fraud cases have receiver_unique_senders = {holdout_fraud_receivers[0]}")
else:
    holdout_fraud_receivers = df_holdout_fraud["receiver_unique_senders"].unique()
    if len(holdout_fraud_receivers) == 1:
        issues.append("🔴 CRITICAL: Holdout fraud cases have identical receiver_unique_senders value!")
        issues.append(f"    All {holdout_fraud} fraud cases have receiver_unique_senders = {holdout_fraud_receivers[0]}")

if len(new_devices) == 0:
    issues.append("🔴 CRITICAL: 0% new devices in holdout - prevents generalization testing")

if len(new_devices) < len(holdout_devices) * 0.1:
    warnings_list.append(f"⚠️  Only {100*len(new_devices)/len(holdout_devices):.1f}% new devices in holdout")

if holdout_fraud * 0.01 > 1:  # Less than 1% fraud
    warnings_list.append(f"⚠️  Holdout fraud rate very low ({100*holdout_fraud/holdout_rows:.3f}%)")

print("ISSUES FOUND:")
if issues:
    for issue in issues:
        print(f"  {issue}")
else:
    print("  ✅ No critical issues detected")

print("\nWARNINGS:")
if warnings_list:
    for warning in warnings_list:
        print(f"  {warning}")
else:
    print("  ✅ No warnings")

print("\n\nRECOMMENDATIONS:")
if issues:
    print("  1. ⛔ DO NOT DEPLOY with current holdout test set")
    print("  2. 🔧 Create new holdout containing:")
    print("     • 50+ new devices NOT in training set")
    print("     • Future time period (don't reuse training dates)")
    print("     • Realistic fraud distribution (~0.1-1%)")
    print("  3. 🔄 Re-run model training with new holdout")
    print("  4. 📊 Compare new results to current 95.45% recall baseline")
    print("     (Expected realistic performance: 90-93%)")
else:
    print("  ✅ Workspace is ready for next steps")
    print("  1. Run ablation study (Model A vs B)")
    print("  2. Evaluate results")
    print("  3. Plan deployment")

print("\n" + "="*80)
print("  END OF DIAGNOSTIC REPORT")
print("="*80 + "\n")

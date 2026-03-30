#!/usr/bin/env python3
"""
Varaksha V2 — 01_compile_physics.py
Feature Physics Compiler

Pipeline:
    1. Load raw CSV from ../datasets/generated/ (UPI, PaySim, or simulator output).
  2. Hash PII columns -> sender_hash, receiver_hash. Drop raw IDs.
  3. Chronological sort -> strict 80/20 temporal split (no shuffle).
    4. Engineer 24-column feature vector:
       - 14 strictly causal behavioural rolling window features
       - 5 ordinal-encoded categorical features (encoder fit on train only)
       - 1 derived corridor risk flag (fit on train only)
       - 2 pre-computed simulator features (txn_frequency, days_since_last_txn)
    5. Export train_clean.parquet and holdout_clean.parquet to ../datasets/generated/.
  6. Save global_stats.json (global amount stats + ordinal maps + corridor set)
     to ./models/ for use by Scripts 2 & 3.

FEATURE CONTRACT (24 columns, order is canonical):
  amount, hour_of_day, day_of_week, is_weekend,
    device_txn_count_10m,
  device_txn_count_1h, device_txn_count_6h, device_txn_count_24h,
  device_amount_zscore_24h,
    receiver_unique_senders_10m,
  receiver_txn_count_1h, receiver_txn_count_24h,
  receiver_unique_senders_1h,
  amount_zscore_global,
  is_new_device, is_new_receiver,
  enc_transaction_type, enc_device_type, enc_network_type,
  enc_sender_bank, enc_receiver_bank,
  is_high_risk_corridor,
  txn_frequency, days_since_last_txn
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent
DATASETS_DIR = SCRIPT_DIR.parent / "datasets" / "generated"
MODELS_DIR = SCRIPT_DIR.parent / "models"

OUT_TRAIN = DATASETS_DIR / "train_clean.parquet"
OUT_HOLDOUT = DATASETS_DIR / "holdout_clean.parquet"
GLOBAL_STATS_PATH = MODELS_DIR / "global_stats.json"

TRAIN_FRACTION = 0.80
EPSILON = 1e-9

# Corridors with fraud rate above this threshold are flagged
CORRIDOR_FRAUD_THRESHOLD = 0.003  # 0.3%

# ---------------------------------------------------------------------------
# Column alias map — dataset-agnostic detection
# ---------------------------------------------------------------------------
COLUMN_ALIASES: dict[str, list[str]] = {
    "timestamp":        ["timestamp", "step", "time", "date", "datetime", "trans_date_trans_time"],
    "amount":           ["amount", "amount (inr)", "amount(inr)", "amount_inr", "amt"],
    "sender_id":        ["nameorig", "sender_id", "device_surrogate", "device_id",
                         "from_account", "sender", "account_id", "nameorg", "customer_id"],
    "receiver_id":      ["namedest", "receiver_id", "receiver_bank", "to_account",
                         "receiver", "merchant", "namedest", "merchant_id"],
    "fraud_flag":       ["isfraud", "fraud_flag", "label", "is_fraud", "fraudulent",
                         "class", "fraud"],
    # Optional — grabbed if present, used as categorical features
    "transaction_type": ["transaction type", "transaction_type", "type", "trans_type"],
    "device_type":      ["device_type", "device type", "devicetype", "device_os"],
    "network_type":     ["network_type", "network type", "networktype"],
    "sender_bank":      ["sender_bank", "sender bank", "from_bank"],
    "receiver_bank":    ["receiver_bank", "receiver bank", "to_bank"],
    # Pre-computed simulator passthrough features
    "txn_frequency":       ["txn_frequency", "transaction_frequency"],
    "days_since_last_txn": ["days_since_last_txn", "days_since_last_transaction"],
}

OPTIONAL_COLS = [
    "transaction_type", "device_type", "network_type", "sender_bank", "receiver_bank",
    "txn_frequency", "days_since_last_txn",
]

# Canonical feature column order — DO NOT REORDER. Scripts 2 & 3 mirror this.
FEATURE_COLS = [
    # Behavioural rolling windows
    "amount",
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "device_txn_count_10m",
    "device_txn_count_1h",
    "device_txn_count_6h",
    "device_txn_count_24h",
    "device_amount_zscore_24h",
    "receiver_unique_senders_10m",
    "receiver_txn_count_1h",
    "receiver_txn_count_24h",
    "receiver_unique_senders_1h",
    "amount_zscore_global",
    "is_new_device",
    "is_new_receiver",
    # Ordinal-encoded categoricals
    "enc_transaction_type",
    "enc_device_type",
    "enc_network_type",
    "enc_sender_bank",
    "enc_receiver_bank",
    # Derived risk signal
    "is_high_risk_corridor",
    # Pre-computed simulator passthrough features (0.0 for non-simulator data)
    "txn_frequency",
    "days_since_last_txn",
]

LABEL_COL = "fraud_flag"
N_FEATURES = len(FEATURE_COLS)  # 24


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[COMPILE] {msg}", flush=True)


def log_section(title: str) -> None:
    bar = "=" * 64
    print(f"\n{bar}\n[COMPILE] {title}\n{bar}", flush=True)


# ---------------------------------------------------------------------------
# Step 1: Detect and load CSV
# ---------------------------------------------------------------------------
def find_csv(datasets_dir: Path) -> Path:
    candidates = list(datasets_dir.glob("*.csv"))
    if not candidates:
        raise FileNotFoundError(f"No CSV found in {datasets_dir}. Place upi_raw.csv there.")
    if len(candidates) == 1:
        return candidates[0]
    for name in ("upi_raw.csv", "paysim.csv", "transactions.csv"):
        match = datasets_dir / name
        if match.exists():
            return match
    log(f"Multiple CSVs found; using first: {candidates[0].name}")
    return candidates[0]


def detect_column(df: pd.DataFrame, internal_name: str) -> Optional[str]:
    col_lower = {c.lower(): c for c in df.columns}
    for alias in COLUMN_ALIASES[internal_name]:
        if alias in col_lower:
            return col_lower[alias]
    return None


def load_and_normalise(csv_path: Path) -> pd.DataFrame:
    log_section("STEP 1 — Load & normalise")
    log(f"Source: {csv_path}")

    df = pd.read_csv(csv_path, low_memory=False)
    log(f"Loaded {len(df):,} rows, {len(df.columns)} columns")

    # Simulator schema has separate Date + Time columns — combine into timestamp
    col_lower_map = {c.lower(): c for c in df.columns}
    if "date" in col_lower_map and "time" in col_lower_map and "timestamp" not in col_lower_map:
        date_col = col_lower_map["date"]
        time_col = col_lower_map["time"]
        df["timestamp"] = df[date_col].astype(str) + " " + df[time_col].astype(str)
        df = df.drop(columns=[date_col, time_col])
        log("Combined 'Date' + 'Time' columns into 'timestamp'.")

    rename_map: dict[str, str] = {}
    # Track which source column each required field came from
    required_sources: dict[str, str] = {}
    for internal in ("timestamp", "amount", "sender_id", "receiver_id", "fraud_flag"):
        found = detect_column(df, internal)
        if found is None:
            raise ValueError(
                f"Cannot find a column mapping for '{internal}' in {list(df.columns)}. "
                f"Expected one of: {COLUMN_ALIASES[internal]}"
            )
        required_sources[internal] = found
        if found != internal:
            rename_map[found] = internal

    # Optional categoricals — add to rename_map if not already consumed
    for col in OPTIONAL_COLS:
        found = detect_column(df, col)
        if found and found != col and found not in rename_map:
            rename_map[found] = col

    df = df.rename(columns=rename_map)

    # Restore any optional categorical that was consumed by a required rename.
    # e.g. receiver_bank -> receiver_id rename; receiver_bank is still needed as a feature.
    for col in OPTIONAL_COLS:
        if col not in df.columns:
            # Find which required column this was sourced from and copy it back
            for src, dst in rename_map.items():
                if src.lower() in [a.lower() for a in COLUMN_ALIASES.get(col, [])]:
                    if dst in df.columns:
                        df[col] = df[dst]
                        break

    # PaySim uses integer `step` (hours) -> real datetime
    if pd.api.types.is_numeric_dtype(df["timestamp"]):
        log("Detected integer timestamp (PaySim step). Converting to datetime.")
        df["timestamp"] = pd.Timestamp("2024-01-01") + pd.to_timedelta(
            df["timestamp"].astype(int), unit="h"
        )
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    n_bad_ts = df["timestamp"].isna().sum()
    if n_bad_ts:
        log(f"WARNING: {n_bad_ts} rows have unparseable timestamps — dropping.")
        df = df.dropna(subset=["timestamp"])

    df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0.0)
    df["fraud_flag"] = pd.to_numeric(df["fraud_flag"], errors="coerce").fillna(0).astype(np.int8)

    # Fill missing optional cols with "UNKNOWN"
    for col in OPTIONAL_COLS:
        if col not in df.columns:
            df[col] = "UNKNOWN"

    log(f"Fraud rate: {df['fraud_flag'].mean()*100:.3f}%  ({df['fraud_flag'].sum():,} fraud rows)")
    return df


# ---------------------------------------------------------------------------
# Step 2: Hash PII
# ---------------------------------------------------------------------------
def _sha_hex(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def hash_pii(df: pd.DataFrame) -> pd.DataFrame:
    log_section("STEP 2 — Hash PII")
    df["sender_hash"]   = df["sender_id"].astype(str).apply(_sha_hex)
    df["receiver_hash"] = df["receiver_id"].astype(str).apply(_sha_hex)
    df = df.drop(columns=["sender_id", "receiver_id"], errors="ignore")
    log("sender_id and receiver_id replaced with 12-char SHA-256 hashes.")
    return df


# ---------------------------------------------------------------------------
# Step 3: Chronological sort + 80/20 temporal split
# ---------------------------------------------------------------------------
def temporal_split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    log_section("STEP 3 — Chronological sort + 80/20 temporal split")
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    cut = int(len(df) * TRAIN_FRACTION)
    train   = df.iloc[:cut].copy()
    holdout = df.iloc[cut:].copy()
    log(f"Train:   {len(train):,} rows | max ts = {train['timestamp'].max()}")
    log(f"Holdout: {len(holdout):,} rows | min ts = {holdout['timestamp'].min()}")
    assert holdout["timestamp"].min() >= train["timestamp"].max(), (
        "Temporal split violated: holdout contains rows earlier than train max timestamp."
    )
    log(f"Fraud in train: {train['fraud_flag'].sum():,} | holdout: {holdout['fraud_flag'].sum():,}")
    return train, holdout


# ---------------------------------------------------------------------------
# Step 4a: Behavioural rolling window features (strictly causal)
# ---------------------------------------------------------------------------
def _rolling_count(group: pd.DataFrame, window: str) -> np.ndarray:
    g = group.set_index("timestamp")
    return g["amount"].rolling(window, closed="left").count().values.astype(np.float32)


def _rolling_mean_std(group: pd.DataFrame, window: str) -> tuple[np.ndarray, np.ndarray]:
    g = group.set_index("timestamp")
    roll = g["amount"].rolling(window, closed="left")
    return roll.mean().values, roll.std(ddof=1).fillna(0.0).values


def _rolling_nunique(group: pd.DataFrame, window: str, col: str) -> np.ndarray:
    """O(n) sliding-window distinct count. Row i sees rows 0..i-1 only."""
    from collections import Counter, deque as _deque
    times_ns  = group["timestamp"].values.astype(np.int64)
    vals      = group[col].values
    result    = np.zeros(len(group), dtype=np.float32)
    window_ns = int(pd.Timedelta(window).value)
    dq: _deque = _deque()
    counts: Counter = Counter()
    for i in range(len(group)):
        cutoff = times_ns[i] - window_ns
        while dq and dq[0][0] < cutoff:
            _, old_val = dq.popleft()
            counts[old_val] -= 1
            if counts[old_val] <= 0:
                del counts[old_val]
        result[i] = float(len(counts))
        dq.append((times_ns[i], vals[i]))
        counts[vals[i]] += 1
    return result


def engineer_behavioural(df: pd.DataFrame, global_mean: float, global_std: float) -> pd.DataFrame:
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)

    df["hour_of_day"] = df["timestamp"].dt.hour.astype(np.int8)
    df["day_of_week"] = df["timestamp"].dt.dayofweek.astype(np.int8)
    df["is_weekend"]  = (df["day_of_week"] >= 5).astype(np.int8)
    df["is_new_device"]   = (df.groupby("sender_hash").cumcount() == 0).astype(np.int8)
    df["is_new_receiver"] = (df.groupby("receiver_hash").cumcount() == 0).astype(np.int8)

    log("  Device rolling windows (10m / 1h / 6h / 24h)...")
    cnt_10m, cnt_1h, cnt_6h, cnt_24h, m24, s24 = [], [], [], [], [], []
    for _, grp in df.groupby("sender_hash", sort=False):
        idx = grp.index
        cnt_10m.append(pd.Series(_rolling_count(grp, "10min"), index=idx))
        cnt_1h.append(pd.Series(_rolling_count(grp, "1h"),  index=idx))
        cnt_6h.append(pd.Series(_rolling_count(grp, "6h"),  index=idx))
        cnt_24h.append(pd.Series(_rolling_count(grp, "24h"), index=idx))
        mu, sig = _rolling_mean_std(grp, "24h")
        m24.append(pd.Series(mu,  index=idx))
        s24.append(pd.Series(sig, index=idx))

    df["device_txn_count_10m"] = pd.concat(cnt_10m).reindex(df.index).fillna(0)
    df["device_txn_count_1h"]  = pd.concat(cnt_1h).reindex(df.index).fillna(0)
    df["device_txn_count_6h"]  = pd.concat(cnt_6h).reindex(df.index).fillna(0)
    df["device_txn_count_24h"] = pd.concat(cnt_24h).reindex(df.index).fillna(0)
    mean_24h = pd.concat(m24).reindex(df.index).fillna(df["amount"].mean())
    std_24h  = pd.concat(s24).reindex(df.index).fillna(EPSILON)
    raw_zscore = (df["amount"] - mean_24h) / (std_24h + EPSILON)
    # Clip: z-score only meaningful when at least 2 prior obs exist; else 0
    has_history = df["device_txn_count_24h"] >= 2
    df["device_amount_zscore_24h"] = np.where(has_history, raw_zscore.clip(-10, 10), 0.0).astype(np.float32)

    log("  Receiver rolling windows (1h / 24h) + unique senders (10m / 1h)...")
    rcnt_1h, rcnt_24h, runiq_10m, runiq_1h = [], [], [], []
    for _, grp in df.groupby("receiver_hash", sort=False):
        idx = grp.index
        rcnt_1h.append(pd.Series(_rolling_count(grp, "1h"),   index=idx))
        rcnt_24h.append(pd.Series(_rolling_count(grp, "24h"), index=idx))
        runiq_10m.append(pd.Series(_rolling_nunique(grp, "10min", "sender_hash"), index=idx))
        runiq_1h.append(pd.Series(_rolling_nunique(grp, "1h", "sender_hash"), index=idx))

    df["receiver_txn_count_1h"]      = pd.concat(rcnt_1h).reindex(df.index).fillna(0)
    df["receiver_txn_count_24h"]     = pd.concat(rcnt_24h).reindex(df.index).fillna(0)
    df["receiver_unique_senders_10m"] = pd.concat(runiq_10m).reindex(df.index).fillna(0)
    df["receiver_unique_senders_1h"] = pd.concat(runiq_1h).reindex(df.index).fillna(0)
    df["amount_zscore_global"] = ((df["amount"] - global_mean) / (global_std + EPSILON)).astype(np.float32)

    # Passthrough pre-computed features (simulator only; default to 0 for other datasets)
    if "txn_frequency" not in df.columns:
        df["txn_frequency"] = np.float32(0.0)
    if "days_since_last_txn" not in df.columns:
        df["days_since_last_txn"] = np.float32(0.0)

    return df


# ---------------------------------------------------------------------------
# Step 4b: Categorical encoding (fit on train only; apply to both)
# ---------------------------------------------------------------------------
def build_ordinal_maps(train: pd.DataFrame) -> dict[str, dict[str, int]]:
    """Return {col: {category: int}} maps fit on training data only."""
    maps: dict[str, dict[str, int]] = {}
    for col in OPTIONAL_COLS:
        categories = sorted(train[col].astype(str).unique().tolist())
        maps[col] = {cat: i for i, cat in enumerate(categories)}
    return maps


def apply_ordinal(df: pd.DataFrame, maps: dict[str, dict[str, int]]) -> pd.DataFrame:
    """Map known categories; unknowns get -1."""
    col_map = {
        "transaction_type": "enc_transaction_type",
        "device_type":      "enc_device_type",
        "network_type":     "enc_network_type",
        "sender_bank":      "enc_sender_bank",
        "receiver_bank":    "enc_receiver_bank",
    }
    for src_col, enc_col in col_map.items():
        m = maps[src_col]
        df[enc_col] = df[src_col].astype(str).map(m).fillna(-1).astype(np.float32)
    return df


# ---------------------------------------------------------------------------
# Step 4c: High-risk corridor flag (fit on train only)
# ---------------------------------------------------------------------------
def build_corridor_set(train: pd.DataFrame) -> set[str]:
    """
    Compute fraud rate per (sender_bank x receiver_bank) corridor on train.
    Returns the set of 'sender_bank|receiver_bank' corridors with fraud rate
    above CORRIDOR_FRAUD_THRESHOLD — computed purely from training data.
    """
    if "sender_bank" not in train.columns or "receiver_bank" not in train.columns:
        return set()
    corridor = (
        train.groupby(["sender_bank", "receiver_bank"])["fraud_flag"]
        .agg(["sum", "count"])
        .reset_index()
    )
    corridor["fraud_rate"] = corridor["sum"] / corridor["count"].clip(lower=1)
    high_risk = corridor[corridor["fraud_rate"] > CORRIDOR_FRAUD_THRESHOLD]
    return {f"{r.sender_bank}|{r.receiver_bank}" for r in high_risk.itertuples()}


def apply_corridor_flag(df: pd.DataFrame, high_risk_corridors: set[str]) -> pd.DataFrame:
    corridor_key = df["sender_bank"].astype(str) + "|" + df["receiver_bank"].astype(str)
    df["is_high_risk_corridor"] = corridor_key.isin(high_risk_corridors).astype(np.float32)
    return df


# ---------------------------------------------------------------------------
# Global amount stats
# ---------------------------------------------------------------------------
def compute_global_stats(train: pd.DataFrame) -> tuple[float, float]:
    amounts = train["amount"].dropna().values.astype(np.float64)
    return float(amounts.mean()), float(amounts.std(ddof=1))


# ---------------------------------------------------------------------------
# Assemble final parquets
# ---------------------------------------------------------------------------
def assemble(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise RuntimeError(f"Missing features after engineering: {missing}")
    out = df[FEATURE_COLS + [LABEL_COL]].copy()
    out[FEATURE_COLS] = out[FEATURE_COLS].astype(np.float32)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load
    csv_path = find_csv(DATASETS_DIR)
    df = load_and_normalise(csv_path)

    # 2. Hash PII
    df = hash_pii(df)

    # 3. Split
    train_raw, holdout_raw = temporal_split(df)

    # 4. Fit global stats + encoders + corridor set on TRAIN only
    global_mean, global_std = compute_global_stats(train_raw)
    log(f"Global stats (train): mean={global_mean:.4f}, std={global_std:.4f}")

    ordinal_maps = build_ordinal_maps(train_raw)
    for col, m in ordinal_maps.items():
        log(f"  Ordinal map [{col}]: {len(m)} categories")

    high_risk_corridors = build_corridor_set(train_raw)
    log(f"  High-risk corridors (fraud rate > {CORRIDOR_FRAUD_THRESHOLD*100:.1f}%): {len(high_risk_corridors)}")

    # Serialisable corridor list for manifest
    corridor_list = sorted(high_risk_corridors)

    # Save all stats to global_stats.json for Scripts 2 & 3
    stats_payload = {
        "global_mean": global_mean,
        "global_std":  global_std,
        "ordinal_maps": ordinal_maps,
        "high_risk_corridors": corridor_list,
        "feature_cols": FEATURE_COLS,
        "n_features": N_FEATURES,
    }
    with open(GLOBAL_STATS_PATH, "w") as f:
        json.dump(stats_payload, f, indent=2)
    log(f"Saved global stats -> {GLOBAL_STATS_PATH}")

    # 5. Feature engineering — TRAIN
    log_section("STEP 4 — Feature engineering: TRAIN")
    train_feat = engineer_behavioural(train_raw.copy(), global_mean, global_std)
    train_feat = apply_ordinal(train_feat, ordinal_maps)
    train_feat = apply_corridor_flag(train_feat, high_risk_corridors)

    # 6. Feature engineering — HOLDOUT (frozen train stats)
    log_section("STEP 4 — Feature engineering: HOLDOUT")
    holdout_feat = engineer_behavioural(holdout_raw.copy(), global_mean, global_std)
    holdout_feat = apply_ordinal(holdout_feat, ordinal_maps)
    holdout_feat = apply_corridor_flag(holdout_feat, high_risk_corridors)

    # 7. Assemble and export
    log_section("STEP 5 — Export Parquet")
    train_out   = assemble(train_feat)
    holdout_out = assemble(holdout_feat)

    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    train_out.to_parquet(OUT_TRAIN,   index=False)
    holdout_out.to_parquet(OUT_HOLDOUT, index=False)

    log(f"train_clean.parquet   -> {OUT_TRAIN}  shape={train_out.shape}")
    log(f"holdout_clean.parquet -> {OUT_HOLDOUT}  shape={holdout_out.shape}")

    assert train_out.shape[1]   == N_FEATURES + 1, "Column count mismatch in train."
    assert holdout_out.shape[1] == N_FEATURES + 1, "Column count mismatch in holdout."
    assert list(train_out.columns[:N_FEATURES]) == FEATURE_COLS, "Feature order mismatch."

    log_section("DONE")
    log(f"Feature contract: {N_FEATURES} columns -> {FEATURE_COLS}")


if __name__ == "__main__":
    main()

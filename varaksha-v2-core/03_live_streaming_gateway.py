#!/usr/bin/env python3
"""
Varaksha V2 — 03_live_streaming_gateway.py
Stateless Live Streaming Gateway & Adversarial Pitch Demonstrator

Simulates an Open Banking API ingesting an unseen CSV row-by-row through
the 3-Layer Gauntlet:

  Layer 1 — Topology (networkx DiGraph): Fan-In breach detection.
  Layer 2 — Anomaly (IsolationForest ONNX): Unsupervised shape anomaly.
  Layer 3 — Sweeper (LightGBM ONNX): Binary fraud probability.

Usage:
    python 03_live_streaming_gateway.py --csv ../datasets/demo/synthetic_attack.csv
    python 03_live_streaming_gateway.py --csv ../datasets/demo/real_traffic.csv
    python 03_live_streaming_gateway.py --csv ../datasets/demo/real_traffic.csv --debug

All feature calculations in this script mirror 01_compile_physics.py
EXACTLY using only internal state dictionaries — no parquet lookups.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

import networkx as nx
import numpy as np
import pandas as pd

# ONNX Runtime — required for inference
try:
    import onnxruntime as ort
except ImportError:
    print("[GATEWAY] ERROR: onnxruntime not installed. Run: pip install onnxruntime")
    sys.exit(1)

# Optional: colorama for Windows ANSI support
try:
    import colorama
    colorama.init(autoreset=True)
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent
MODELS_DIR = SCRIPT_DIR.parent / "models"
MANIFEST_PATH = MODELS_DIR / "feature_manifest.json"

# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"

VERDICT_COLOR = {
    "ALLOW":    _GREEN,
    "FLAG":     _YELLOW,
    "BLOCK":    _RED,
}

EPSILON = 1e-9
FAN_IN_THRESHOLD_10M = 10       # Layer 1: distinct senders in 10-minute window
VELOCITY_THRESHOLD_10M = 12     # Layer 1: sender txn count in 10-minute window
STREAM_DELAY_S   = 0.05


# ---------------------------------------------------------------------------
# Column alias detection (mirrors Script 1)
# ---------------------------------------------------------------------------
COLUMN_ALIASES: dict[str, list[str]] = {
    "timestamp":        ["timestamp", "step", "time", "date", "datetime", "trans_date_trans_time"],
    "amount":           ["amount", "amount (inr)", "amount(inr)", "amount_inr", "amt"],
    "sender_id":        ["nameorig", "sender_id", "device_surrogate", "device_id",
                        "from_account", "sender", "account_id", "nameorg", "customer_id"],
    "receiver_id":      ["namedest", "receiver_id", "receiver_bank", "to_account",
                        "receiver", "merchant", "namedest", "merchant_id"],
    "transaction_type": ["transaction type", "transaction_type", "type", "trans_type"],
    "device_type":      ["device_type", "device type", "devicetype", "device_os"],
    "network_type":     ["network_type", "network type", "networktype"],
    "sender_bank":      ["sender_bank", "sender bank", "from_bank"],
    "receiver_bank":    ["receiver_bank", "receiver bank", "to_bank"],
    "txn_frequency":       ["txn_frequency", "transaction_frequency"],
    "days_since_last_txn": ["days_since_last_txn", "days_since_last_transaction"],
}

OPTIONAL_COLS = [
    "transaction_type", "device_type", "network_type", "sender_bank", "receiver_bank",
    "txn_frequency", "days_since_last_txn",
]


def _sha_hex(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def detect_column(df: pd.DataFrame, internal_name: str) -> Optional[str]:
    col_lower = {c.lower(): c for c in df.columns}
    for alias in COLUMN_ALIASES[internal_name]:
        if alias in col_lower:
            return col_lower[alias]
    return None


def load_and_normalise_csv(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path, low_memory=False)

    # Simulator schema has separate Date + Time columns — combine into timestamp
    col_lower_map = {c.lower(): c for c in df.columns}
    if "date" in col_lower_map and "time" in col_lower_map and "timestamp" not in col_lower_map:
        date_col = col_lower_map["date"]
        time_col = col_lower_map["time"]
        df["timestamp"] = df[date_col].astype(str) + " " + df[time_col].astype(str)
        df = df.drop(columns=[date_col, time_col])

    rename_map: dict[str, str] = {}
    for internal in ("timestamp", "amount", "sender_id", "receiver_id"):
        found = detect_column(df, internal)
        if found is None:
            raise ValueError(
                f"Cannot find column '{internal}' in {list(df.columns)}. "
                f"Expected one of: {COLUMN_ALIASES[internal]}"
            )
        if found != internal:
            rename_map[found] = internal

    # Optional categoricals — add to rename_map if not already consumed
    for col in OPTIONAL_COLS:
        found = detect_column(df, col)
        if found and found != col and found not in rename_map:
            rename_map[found] = col

    df = df.rename(columns=rename_map)

    # Restore any optional categorical consumed by a required rename
    for col in OPTIONAL_COLS:
        if col not in df.columns:
            for src, dst in rename_map.items():
                if src.lower() in [a.lower() for a in COLUMN_ALIASES.get(col, [])]:
                    if dst in df.columns:
                        df[col] = df[dst]
                        break

    # Fill missing optional cols (categoricals -> "UNKNOWN"; numerics -> 0.0)
    _numeric_optional = {"txn_frequency", "days_since_last_txn"}
    for col in OPTIONAL_COLS:
        if col not in df.columns:
            df[col] = 0.0 if col in _numeric_optional else "UNKNOWN"

    if pd.api.types.is_numeric_dtype(df["timestamp"]):
        df["timestamp"] = pd.Timestamp("2024-01-01") + pd.to_timedelta(
            df["timestamp"].astype(int), unit="h"
        )
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df = df.dropna(subset=["timestamp"]).reset_index(drop=True)
    df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0.0)
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Live state — mirrors all rolling window logic from Script 1 exactly
# ---------------------------------------------------------------------------
class LiveState:
    """
    In-memory state cache for stateless per-row feature computation.
    All time windows are maintained as deques of (timestamp_ns, value) tuples.
    """

    def __init__(self, global_mean: float, global_std: float,
                 ordinal_maps: dict, high_risk_corridors: set) -> None:
        self.global_mean = global_mean
        self.global_std  = global_std
        self.ordinal_maps = ordinal_maps                  # {col: {cat: int}}
        self.high_risk_corridors = high_risk_corridors    # set of "sender_bank|receiver_bank"

        # sender_hash -> deque of (ts_ns, amount)
        self.device_history: dict[str, deque] = defaultdict(deque)
        # receiver_hash -> deque of (ts_ns, sender_hash)
        self.receiver_history: dict[str, deque] = defaultdict(deque)

        # Cold-start tracking
        self.seen_devices:   set[str] = set()
        self.seen_receivers: set[str] = set()

        # Welford running stats for live amount z-score
        self._wf_n:    int   = 0
        self._wf_mean: float = 0.0
        self._wf_M2:   float = 0.0

        # Layer 1: live graph
        self.graph: nx.DiGraph = nx.DiGraph()

    # --- Welford online algorithm ---
    def _welford_update(self, x: float) -> None:
        self._wf_n += 1
        delta = x - self._wf_mean
        self._wf_mean += delta / self._wf_n
        self._wf_M2 += delta * (x - self._wf_mean)

    def _welford_std(self) -> float:
        if self._wf_n < 2:
            return EPSILON
        return math.sqrt(self._wf_M2 / (self._wf_n - 1))

    # --- Eviction helpers ---
    def _evict(self, dq: deque, cutoff_ns: int) -> None:
        while dq and dq[0][0] < cutoff_ns:
            dq.popleft()

    def _encode(self, col: str, value: str) -> float:
        """Ordinal-encode a categorical value. Unknowns -> -1."""
        return float(self.ordinal_maps.get(col, {}).get(value, -1))

    # --- Feature computation for one row (BEFORE updating state) ---
    def compute_features(self, ts: pd.Timestamp, amount: float,
                         sender_hash: str, receiver_hash: str,
                         feature_cols: list[str],
                         transaction_type: str = "UNKNOWN",
                         device_type: str = "UNKNOWN",
                         network_type: str = "UNKNOWN",
                         sender_bank: str = "UNKNOWN",
                         receiver_bank: str = "UNKNOWN",
                         txn_frequency: float = 0.0,
                         days_since_last_txn: float = 0.0) -> np.ndarray:
        ts_ns  = ts.value  # nanoseconds since epoch
        ns_10m = pd.Timedelta("10min").value
        ns_1h  = pd.Timedelta("1h").value
        ns_6h  = pd.Timedelta("6h").value
        ns_24h = pd.Timedelta("24h").value

        # ---- Temporal features ----
        hour_of_day = float(ts.hour)
        day_of_week = float(ts.dayofweek)
        is_weekend  = float(day_of_week >= 5)

        # ---- Cold-start flags ----
        is_new_device   = float(sender_hash not in self.seen_devices)
        is_new_receiver = float(receiver_hash not in self.seen_receivers)

        # ---- Device velocity (look at state BEFORE current row) ----
        dev_dq = self.device_history[sender_hash]

        cutoff_10m = ts_ns - ns_10m
        cutoff_1h  = ts_ns - ns_1h
        cutoff_6h  = ts_ns - ns_6h
        cutoff_24h = ts_ns - ns_24h

        # Count within each window (left-closed: rows with ts_ns >= cutoff AND < current ts_ns)
        device_txn_count_10m = float(sum(1 for t, _ in dev_dq if t >= cutoff_10m))
        device_txn_count_1h  = float(sum(1 for t, _ in dev_dq if t >= cutoff_1h))
        device_txn_count_6h  = float(sum(1 for t, _ in dev_dq if t >= cutoff_6h))
        device_txn_count_24h = float(sum(1 for t, _ in dev_dq if t >= cutoff_24h))

        amounts_24h = [a for t, a in dev_dq if t >= cutoff_24h]
        if amounts_24h:
            mu_24h  = float(np.mean(amounts_24h))
            std_24h = float(np.std(amounts_24h, ddof=1)) if len(amounts_24h) > 1 else EPSILON
        else:
            mu_24h, std_24h = self.global_mean, self.global_std

        device_amount_zscore_24h = (amount - mu_24h) / (std_24h + EPSILON)

        # ---- Receiver velocity ----
        rec_dq = self.receiver_history[receiver_hash]

        receiver_txn_count_1h  = float(sum(1 for t, _ in rec_dq if t >= cutoff_1h))
        receiver_txn_count_24h = float(sum(1 for t, _ in rec_dq if t >= cutoff_24h))

        unique_senders_10m = float(len({s for t, s in rec_dq if t >= cutoff_10m}))
        unique_senders_1h = float(len({s for t, s in rec_dq if t >= cutoff_1h}))

        # ---- Global z-score (frozen train stats from manifest) ----
        amount_zscore_global = (amount - self.global_mean) / (self.global_std + EPSILON)

        # ---- Ordinal-encoded categoricals ----
        enc_transaction_type = self._encode("transaction_type", transaction_type)
        enc_device_type      = self._encode("device_type",      device_type)
        enc_network_type     = self._encode("network_type",     network_type)
        enc_sender_bank      = self._encode("sender_bank",      sender_bank)
        enc_receiver_bank    = self._encode("receiver_bank",    receiver_bank)

        # ---- High-risk corridor flag (lookup, no computation needed) ----
        corridor_key = f"{sender_bank}|{receiver_bank}"
        is_high_risk_corridor = float(corridor_key in self.high_risk_corridors)

        feature_map = {
            "amount": amount,
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "device_txn_count_10m": device_txn_count_10m,
            "device_txn_count_1h": device_txn_count_1h,
            "device_txn_count_6h": device_txn_count_6h,
            "device_txn_count_24h": device_txn_count_24h,
            "device_amount_zscore_24h": device_amount_zscore_24h,
            "receiver_unique_senders_10m": unique_senders_10m,
            "receiver_txn_count_1h": receiver_txn_count_1h,
            "receiver_txn_count_24h": receiver_txn_count_24h,
            "receiver_unique_senders_1h": unique_senders_1h,
            "amount_zscore_global": amount_zscore_global,
            "is_new_device": is_new_device,
            "is_new_receiver": is_new_receiver,
            "enc_transaction_type": enc_transaction_type,
            "enc_device_type": enc_device_type,
            "enc_network_type": enc_network_type,
            "enc_sender_bank": enc_sender_bank,
            "enc_receiver_bank": enc_receiver_bank,
            "is_high_risk_corridor": is_high_risk_corridor,
            "txn_frequency": txn_frequency,
            "days_since_last_txn": days_since_last_txn,
        }

        missing = [c for c in feature_cols if c not in feature_map]
        if missing:
            raise ValueError(f"Missing runtime features required by manifest: {missing}")

        return np.array([feature_map[c] for c in feature_cols], dtype=np.float32)

    def update_state(self, ts: pd.Timestamp, amount: float,
                     sender_hash: str, receiver_hash: str) -> None:
        """Update all state dicts AFTER feature computation for this row."""
        ts_ns = ts.value
        ns_24h = pd.Timedelta("24h").value

        # Evict stale entries (> 24h)
        self._evict(self.device_history[sender_hash], ts_ns - ns_24h)
        self._evict(self.receiver_history[receiver_hash], ts_ns - ns_24h)

        # Append current row
        self.device_history[sender_hash].append((ts_ns, amount))
        self.receiver_history[receiver_hash].append((ts_ns, sender_hash))

        # Cold-start
        self.seen_devices.add(sender_hash)
        self.seen_receivers.add(receiver_hash)

        # Welford
        self._welford_update(amount)

        # Graph
        self.graph.add_edge(sender_hash, receiver_hash, amount=amount)

    def topology_signal(self, ts: pd.Timestamp, sender_hash: str, receiver_hash: str) -> dict[str, float | bool]:
        """
        Left-closed L1 signals in a 10-minute window to isolate short attack bursts
        from broader 1-hour background traffic.
        """
        ts_ns = ts.value
        cutoff_10m = ts_ns - pd.Timedelta("10min").value

        dev_dq = self.device_history[sender_hash]
        rec_dq = self.receiver_history[receiver_hash]

        sender_txn_10m = float(sum(1 for t, _ in dev_dq if t >= cutoff_10m))
        receiver_unique_senders_10m = float(len({s for t, s in rec_dq if t >= cutoff_10m}))

        fan_in_flag = receiver_unique_senders_10m >= float(FAN_IN_THRESHOLD_10M)
        velocity_flag = sender_txn_10m >= float(VELOCITY_THRESHOLD_10M)
        high_confidence = bool(fan_in_flag or velocity_flag)

        return {
            "fan_in_10m": receiver_unique_senders_10m,
            "sender_txn_10m": sender_txn_10m,
            "fan_in_flag": fan_in_flag,
            "velocity_flag": velocity_flag,
            "high_confidence": high_confidence,
        }


# ---------------------------------------------------------------------------
# ONNX inference helpers
# ---------------------------------------------------------------------------
def load_onnx_session(path: Path) -> ort.InferenceSession:
    if not path.exists():
        raise FileNotFoundError(
            f"ONNX model not found: {path}\n"
            "Run 02_forge_the_brain.py first."
        )
    return ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])


def infer_lgbm(session: ort.InferenceSession, features: np.ndarray) -> float:
    """Returns fraud probability in [0, 1]."""
    x = features.reshape(1, -1)
    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: x})
    # LightGBM ONNX output: [label, probabilities_map]
    # probabilities_map is a list of dicts; class 1 probability is what we want
    prob_map = outputs[1]
    if isinstance(prob_map, list) and isinstance(prob_map[0], dict):
        return float(prob_map[0].get(1, prob_map[0].get("1", 0.0)))
    # Fallback: if output[1] is ndarray shape [1,2]
    if hasattr(prob_map, "shape") and prob_map.ndim == 2:
        return float(prob_map[0, 1])
    return 0.0


def infer_isolation_forest(session: ort.InferenceSession, features: np.ndarray) -> float:
    """
    Returns anomaly score normalised to [0, 1].
    IsolationForest raw score: higher (less negative) = more normal.
    We invert and normalise: score=1 means maximally anomalous.
    Raw scores typically range ≈ [−0.5, 0.5].
    """
    x = features.reshape(1, -1)
    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: x})
    # skl2onnx IsolationForest output: [label (-1/1), scores]
    # scores[0] is the raw anomaly score
    raw = float(outputs[1][0])
    # Normalise: raw ∈ [−0.5, 0.5] -> invert -> anomaly ∈ [0, 1]
    # score = −0.5 (most anomalous) -> 1.0; score = 0.5 (most normal) -> 0.0
    normalised = max(0.0, min(1.0, (-raw + 0.5)))
    return normalised


# ---------------------------------------------------------------------------
# Score fusion + verdict
# ---------------------------------------------------------------------------
def fuse_scores(lgbm_prob: float, anomaly_score: float, topology_signal: dict,
                manifest: dict) -> tuple[float, str]:
    weights = manifest["score_fusion"]
    topology_flag = bool(topology_signal.get("high_confidence", False))
    risk = (
        weights["lgbm_weight"]     * lgbm_prob
        + weights["anomaly_weight"]  * anomaly_score
        + weights["topology_weight"] * float(topology_flag)
    )
    risk = max(0.0, min(1.0, risk))

    verdicts = manifest["verdicts"]
    baseline_threshold = float(manifest.get("baseline_threshold", verdicts["FLAG"][0]))
    l1_l3_confirm_floor = float(manifest.get("l1_l3_confirm_floor", 0.25))

    # Layer Fusion: L1 is a high-confidence filter over L3 predictions.
    # If topology strongly indicates coordinated behaviour and L3 is non-trivial,
    # avoid letting the case fall below baseline escalation.
    if topology_flag and lgbm_prob >= l1_l3_confirm_floor:
        risk = max(risk, min(0.99, baseline_threshold + 0.10))

    # If topology is high confidence and L3 already crosses baseline,
    # promote directly to block range.
    if topology_flag and lgbm_prob >= baseline_threshold:
        risk = max(risk, float(verdicts["BLOCK"][0]))

    if risk < verdicts["FLAG"][0]:
        verdict = "ALLOW"
    elif risk < verdicts["BLOCK"][0]:
        verdict = "FLAG"
    else:
        verdict = "BLOCK"

    return risk, verdict


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
def _risk_bar(risk: float, width: int = 10) -> str:
    filled = round(risk * width)
    return "█" * filled + "░" * (width - filled)


def print_header(csv_path: Path, n_rows: int) -> None:
    print(f"\n{_BOLD}{_CYAN}{'─' * 80}{_RESET}")
    print(f"{_BOLD}{_CYAN}  VARAKSHA V2  |  Live Streaming Gateway  |  3-Layer Gauntlet{_RESET}")
    print(f"{_CYAN}{'─' * 80}{_RESET}")
    print(f"  Source: {csv_path.name}  ({n_rows:,} rows)")
    print(
        f"  L1 thresholds: fan-in10m>={FAN_IN_THRESHOLD_10M}, velocity10m>={VELOCITY_THRESHOLD_10M}"
        f"  |  Stream delay: {STREAM_DELAY_S*1000:.0f}ms/row"
    )
    print(f"{_CYAN}{'─' * 80}{_RESET}\n")
    print(
        f"{'Timestamp':<22} {'TX Hash':>8} {'RX Hash':>8} "
        f"{'Amount':>12} {'L2-Anom':>8} {'L3-Prob':>8} "
        f"{'Risk':>6} {'Bar':>12}  Verdict"
    )
    print("─" * 100)


def print_row(ts: pd.Timestamp, sender_hash: str, receiver_hash: str,
              amount: float, anomaly: float, lgbm_prob: float,
              risk: float, verdict: str, topology_flag: bool,
              debug: bool, features: np.ndarray, feature_cols: list[str]) -> None:
    color = VERDICT_COLOR.get(verdict, _RESET)
    topo_marker = " [TOPO]" if topology_flag else ""

    line = (
        f"{str(ts)[:19]:<22} "
        f"TX:{sender_hash[:6]:>6} "
        f"RX:{receiver_hash[:6]:>6} "
        f"₹{amount:>11,.2f} "
        f"{anomaly:>8.4f} "
        f"{lgbm_prob:>8.4f} "
        f"{risk:>6.3f} "
        f"{_risk_bar(risk):>12}  "
        f"{color}{_BOLD}{verdict}{_RESET}{topo_marker}"
    )
    print(line)

    if debug:
        print(f"  {_DIM}Features: { {k: round(float(v), 4) for k, v in zip(feature_cols, features)} }{_RESET}")


def print_summary(counters: dict[str, int], n_total: int, elapsed: float) -> None:
    print(f"\n{'─' * 100}")
    print(f"{_BOLD}STREAM SUMMARY{_RESET}")
    print(f"  Total rows processed : {n_total:,}")
    print(f"  Elapsed              : {elapsed:.2f}s  ({n_total/elapsed:.1f} rows/s)")
    for verdict in ("ALLOW", "FLAG", "BLOCK"):
        count = counters.get(verdict, 0)
        pct = count / max(n_total, 1) * 100
        color = VERDICT_COLOR[verdict]
        print(f"  {color}{verdict:<10}{_RESET}: {count:>6,}  ({pct:.1f}%)")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Varaksha V2 — Live Streaming Gateway (3-Layer Gauntlet)"
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=SCRIPT_DIR.parent / "datasets" / "demo" / "real_traffic.csv",
        help="Path to the CSV to stream (default: ../datasets/demo/real_traffic.csv)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print feature vector for each row (for parity verification with Script 1)",
    )
    parser.add_argument(
        "--no-delay",
        action="store_true",
        help="Disable 50ms sleep per row (full speed)",
    )
    args = parser.parse_args()

    # --- Load manifest ---
    if not MANIFEST_PATH.exists():
        print(f"[GATEWAY] ERROR: manifest not found at {MANIFEST_PATH}")
        print("Run 02_forge_the_brain.py first.")
        sys.exit(1)

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    feature_cols: list[str]       = manifest["feature_cols"]
    global_mean:  float           = manifest["global_mean"]
    global_std:   float           = manifest["global_std"]
    n_features:   int             = manifest["n_features"]
    ordinal_maps: dict            = manifest.get("ordinal_maps", {})
    high_risk_corridors: set[str] = set(manifest.get("high_risk_corridors", []))

    # --- Load ONNX sessions ---
    lgbm_session = load_onnx_session(MODELS_DIR / manifest["lgbm_onnx"])
    if_session   = load_onnx_session(MODELS_DIR / manifest["if_onnx"])

    # --- Load CSV ---
    if not args.csv.exists():
        print(f"[GATEWAY] ERROR: CSV not found: {args.csv}")
        sys.exit(1)

    df = load_and_normalise_csv(args.csv)

    print_header(args.csv, len(df))

    # --- Initialise live state ---
    state = LiveState(
        global_mean=global_mean, global_std=global_std,
        ordinal_maps=ordinal_maps, high_risk_corridors=high_risk_corridors,
    )
    counters: dict[str, int] = {"ALLOW": 0, "FLAG": 0, "BLOCK": 0}

    t_start = time.perf_counter()

    for _, row in df.iterrows():
        ts:           pd.Timestamp = row["timestamp"]
        amount:       float        = float(row["amount"])
        sender_raw:   str          = str(row["sender_id"])
        receiver_raw: str          = str(row["receiver_id"])

        sender_hash   = _sha_hex(sender_raw)
        receiver_hash = _sha_hex(receiver_raw)

        # Grab optional categoricals from row (filled "UNKNOWN" if missing)
        txn_type    = str(row.get("transaction_type", "UNKNOWN"))
        dev_type    = str(row.get("device_type",      "UNKNOWN"))
        net_type    = str(row.get("network_type",     "UNKNOWN"))
        s_bank      = str(row.get("sender_bank",      "UNKNOWN"))
        r_bank      = str(row.get("receiver_bank",    "UNKNOWN"))
        txn_freq    = float(row.get("txn_frequency",      0.0))
        days_last   = float(row.get("days_since_last_txn", 0.0))

        # --- Compute features (state BEFORE this row) ---
        features = state.compute_features(
            ts, amount, sender_hash, receiver_hash,
            feature_cols=feature_cols,
            transaction_type=txn_type, device_type=dev_type,
            network_type=net_type, sender_bank=s_bank, receiver_bank=r_bank,
            txn_frequency=txn_freq, days_since_last_txn=days_last,
        )

        assert len(features) == n_features, (
            f"Feature vector length {len(features)} != manifest n_features {n_features}"
        )

        # --- Layer 1: Topology (strict left-closed 10-minute signals) ---
        topo_signal = state.topology_signal(ts, sender_hash, receiver_hash)
        topo_flag = bool(topo_signal["high_confidence"])

        # --- Layer 2: Anomaly (IsolationForest) ---
        anomaly_score = infer_isolation_forest(if_session, features)

        # --- Layer 3: Sweeper (LightGBM) ---
        lgbm_prob = infer_lgbm(lgbm_session, features)

        # --- Score fusion + verdict ---
        risk, verdict = fuse_scores(lgbm_prob, anomaly_score, topo_signal, manifest)

        # --- Update state (AFTER inference) ---
        state.update_state(ts, amount, sender_hash, receiver_hash)

        # --- Output ---
        print_row(
            ts, sender_hash, receiver_hash, amount,
            anomaly_score, lgbm_prob, risk, verdict,
            topo_flag, args.debug, features, feature_cols,
        )
        counters[verdict] = counters.get(verdict, 0) + 1

        if not args.no_delay:
            time.sleep(STREAM_DELAY_S)

    elapsed = time.perf_counter() - t_start
    print_summary(counters, len(df), elapsed)


if __name__ == "__main__":
    main()

"""
train_profiler.py — Train the IsolationForest on PaySim + BankSim
==================================================================
Run this ONCE after downloading the datasets (see datasets/README.md).

What it produces:
  models/isolation_forest.pkl   — joblib-serialised IsolationForest
  models/amount_stats.json      — mean + std of transaction amounts

Usage:
    python agents/train_profiler.py
    python agents/train_profiler.py --paysim datasets/paysim/PS_20174392719_1491204439457_log.csv
    python agents/train_profiler.py --paysim path/to/paysim.csv --banksim path/to/banksim.csv
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("train_profiler")

_BASE      = Path(__file__).resolve().parents[1]  # → Varaksha/
MODELS_DIR = _BASE / "data" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ─── Feature extraction ────────────────────────────────────────────────────────

MERCHANT_MAP = {
    "PAYMENT":  "utilities",
    "TRANSFER": "wire_transfer",
    "CASH_OUT": "cash_out",
    "CASH_IN":  "cash_in",
    "DEBIT":    "debit",
}

def load_paysim(path: str) -> pd.DataFrame:
    log.info("Loading PaySim from %s", path)
    df = pd.read_csv(path, dtype={"isFraud": int})
    df["merchant_category"] = df["type"].map(MERCHANT_MAP).fillna("other")
    return df


def load_banksim(path: str) -> pd.DataFrame:
    log.info("Loading BankSim from %s", path)
    df = pd.read_csv(path)
    # BankSim uses 'fraud' column
    df = df.rename(columns={"fraud": "isFraud", "amount": "amount"})
    df["merchant_category"] = df.get("category", "other")
    return df


def build_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Returns (X, y) where y=1 means fraud.
    Feature columns must match agent01_profiler.extract_features().
    """
    cat_codes = {c: i % 20 for i, c in enumerate(df["merchant_category"].unique())}
    df = df.copy()
    df["cat_code"] = df["merchant_category"].map(cat_codes).fillna(0)

    # Velocity proxy from step column (PaySim) or row order (BankSim)
    step_col = "step" if "step" in df.columns else None
    if step_col:
        # Velocity: count of same sender in same step bin (crude proxy)
        df["velocity_1h"] = df.groupby(["nameOrig" if "nameOrig" in df.columns else df.columns[0],
                                         step_col])["amount"].transform("count")
    else:
        df["velocity_1h"] = 1

    df["velocity_1h"] = df["velocity_1h"].clip(0, 200)

    X = np.column_stack([
        np.log1p(df["amount"].clip(lower=0.0).values),
        df["velocity_1h"].values.astype(float),
        np.zeros(len(df)),                              # gps_delta (not in dataset → 0)
        np.zeros(len(df)),                              # is_first_transfer (not available → 0)
        df["cat_code"].values.astype(float),
        np.zeros(len(df)),                              # upi_network_encoded (not available → 0)
    ])
    y = df["isFraud"].values
    return X, y


# ─── Training ─────────────────────────────────────────────────────────────────

def train(X_train: np.ndarray, contamination: float = 0.05) -> IsolationForest:
    log.info("Training IsolationForest: %d samples, contamination=%.3f", len(X_train), contamination)
    clf = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=contamination,
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    clf.fit(X_train)
    return clf


def evaluate(clf: IsolationForest, X: np.ndarray, y: np.ndarray) -> None:
    """Quick eval: treat IF outlier score as fraud probability."""
    # decision_function: more negative = more anomalous
    scores = -clf.decision_function(X)  # invert so higher = more anomalous
    # Threshold at median score of known frauds
    fraud_scores = scores[y == 1]
    if len(fraud_scores) == 0:
        log.warning("No fraud labels in eval set — skipping ROC-AUC")
        return

    try:
        auc = roc_auc_score(y, scores)
        log.info("ROC-AUC on eval set: %.4f", auc)
    except Exception as e:
        log.warning("ROC-AUC computation failed: %s", e)

    # Binary classification at 95th percentile of fraud scores
    thresh = float(np.percentile(fraud_scores, 5))  # 5th %ile of fraud → catch 95%
    y_pred = (scores >= thresh).astype(int)
    log.info("Classification report (threshold=%.4f):\n%s", thresh,
             classification_report(y, y_pred, target_names=["legit", "fraud"], zero_division=0))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--paysim",  default="datasets/paysim/PS_20174392719_1491204439457_log.csv")
    parser.add_argument("--banksim", default=None)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    frames   = []
    paysim_p = Path(args.paysim)
    if paysim_p.exists():
        frames.append(load_paysim(str(paysim_p)))
    else:
        log.warning("PaySim not found at %s — see datasets/README.md", paysim_p)

    if args.banksim:
        banksim_p = Path(args.banksim)
        if banksim_p.exists():
            frames.append(load_banksim(str(banksim_p)))
        else:
            log.warning("BankSim not found at %s", banksim_p)

    if not frames:
        log.warning("No datasets found — training on 10k synthetic samples as fallback")
        rng = np.random.default_rng(42)
        X_fake = rng.standard_normal((10_000, 6)).astype(np.float32)
        y_fake = (rng.random(10_000) < 0.05).astype(int)
        clf = train(X_fake, contamination=args.contamination)
        evaluate(clf, X_fake, y_fake)
    else:
        df_all = pd.concat(frames, ignore_index=True)
        log.info("Total samples: %d (fraud: %d)", len(df_all), df_all["isFraud"].sum())

        X, y = build_features(df_all)

        # Amount stats for Z-score in agent01
        stats = {"mean": float(np.mean(df_all["amount"])), "std": float(np.std(df_all["amount"]))}
        (MODELS_DIR / "amount_stats.json").write_text(json.dumps(stats))
        log.info("Amount stats: mean=%.2f  std=%.2f", stats["mean"], stats["std"])

        # Train on full dataset (IF does not require a separate train/test split for fitting,
        # but we evaluate on a held-out 20%)
        N = len(X)
        split = int(N * 0.8)
        clf = train(X[:split], contamination=args.contamination)
        evaluate(clf, X[split:], y[split:])

    model_path = MODELS_DIR / "isolation_forest.pkl"
    joblib.dump(clf, model_path)
    log.info("Model saved: %s", model_path)


if __name__ == "__main__":
    main()

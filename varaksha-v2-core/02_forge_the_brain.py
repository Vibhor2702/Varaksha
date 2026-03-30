#!/usr/bin/env python3
"""
Varaksha V2 - 02_forge_the_brain.py

One-command model trainer for V2 core.

Design goals:
- No dataset mutations.
- Real training and real metrics every run (no cached/memorized stats).
- Decision threshold is treated as a training-time selection hyperparameter.
- Clear, ML-centric terminal output.

Usage:
  py varaksha-v2-core/02_forge_the_brain.py
  py varaksha-v2-core/02_forge_the_brain.py --decision-threshold 0.46
"""

from __future__ import annotations

import argparse
import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType as SkFloatTensorType


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent
DATASETS_DIR = SCRIPT_DIR.parent / "datasets" / "generated"
MODELS_DIR = SCRIPT_DIR.parent / "models"

TRAIN_PATH = DATASETS_DIR / "train_clean.parquet"
HOLDOUT_PATH = DATASETS_DIR / "holdout_clean.parquet"

IF_ONNX_PATH = MODELS_DIR / "isolation_forest.onnx"
LGBM_ONNX_PATH = MODELS_DIR / "lgbm_sweeper.onnx"
MANIFEST_PATH = MODELS_DIR / "feature_manifest.json"
GLOBAL_STATS_PATH = MODELS_DIR / "global_stats.json"
TRAINING_STATS_PATH = MODELS_DIR / "training_stats.json"

LABEL_COL = "fraud_flag"

FEATURE_COLS = [
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
    "enc_transaction_type",
    "enc_device_type",
    "enc_network_type",
    "enc_sender_bank",
    "enc_receiver_bank",
    "is_high_risk_corridor",
    "txn_frequency",
    "days_since_last_txn",
]
N_FEATURES = len(FEATURE_COLS)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[FORGE] {msg}", flush=True)


def section(title: str) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n[FORGE] {title}\n{bar}", flush=True)


def suppress_noise() -> None:
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        message=r"X does not have valid feature names, but LGBMClassifier was fitted with feature names",
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train Varaksha V2 models with threshold-aware selection.")
    p.add_argument("--decision-threshold", type=float, default=0.46, help="Decision threshold hyperparameter for model selection.")
    p.add_argument("--seed", type=int, default=42, help="Random seed.")
    return p.parse_args()


def load_split(path: Path) -> tuple[pd.DataFrame, np.ndarray]:
    if not path.exists():
        raise FileNotFoundError(f"Missing parquet: {path}. Run 01_compile_physics.py first.")

    df = pd.read_parquet(path)
    missing = [c for c in FEATURE_COLS + [LABEL_COL] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in {path.name}: {missing}")

    X = df[FEATURE_COLS].astype(np.float32).copy()
    y = df[LABEL_COL].astype(np.int32).to_numpy()
    return X, y


def threshold_metrics(y_true: np.ndarray, proba: np.ndarray, threshold: float) -> dict:
    pred = (proba >= threshold).astype(np.int8)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    beta2 = 0.25
    f05 = ((1.0 + beta2) * precision * recall / (beta2 * precision + recall)) if (beta2 * precision + recall) > 0 else 0.0
    return {
        "threshold": float(threshold),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": float(precision),
        "recall": float(recall),
        "f0_5": float(f05),
    }


def temporal_train_val_split(X_train: pd.DataFrame, y_train: np.ndarray, frac: float = 0.8) -> tuple[pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray]:
    cut = int(len(X_train) * frac)
    X_tr = X_train.iloc[:cut].copy()
    y_tr = y_train[:cut]
    X_val = X_train.iloc[cut:].copy()
    y_val = y_train[cut:]
    return X_tr, y_tr, X_val, y_val


def candidate_params(scale_pos_weight: float, seed: int) -> list[dict]:
    return [
        {
            "objective": "binary",
            "n_estimators": 200,
            "max_depth": 6,
            "learning_rate": 0.05,
            "num_leaves": 63,
            "scale_pos_weight": scale_pos_weight,
            "random_state": seed,
            "n_jobs": -1,
            "verbose": -1,
        },
        {
            "objective": "binary",
            "n_estimators": 300,
            "max_depth": 7,
            "learning_rate": 0.04,
            "num_leaves": 95,
            "scale_pos_weight": scale_pos_weight,
            "random_state": seed,
            "n_jobs": -1,
            "verbose": -1,
        },
        {
            "objective": "binary",
            "n_estimators": 240,
            "max_depth": 5,
            "learning_rate": 0.06,
            "num_leaves": 47,
            "scale_pos_weight": scale_pos_weight,
            "random_state": seed,
            "n_jobs": -1,
            "verbose": -1,
        },
    ]


def select_lgbm_by_threshold(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    decision_threshold: float,
    seed: int,
) -> tuple[LGBMClassifier, dict, dict]:
    section("MODEL SELECTION (Threshold-Aware)")

    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    scale_pos_weight = float(n_neg / max(n_pos, 1))
    log(f"Train class balance: positives={n_pos:,}, negatives={n_neg:,}, scale_pos_weight={scale_pos_weight:.4f}")
    log(f"Selection target threshold: {decision_threshold:.4f}")

    X_tr, y_tr, X_val, y_val = temporal_train_val_split(X_train, y_train, frac=0.8)

    best_model: LGBMClassifier | None = None
    best_metrics: dict | None = None
    best_params: dict | None = None

    for i, params in enumerate(candidate_params(scale_pos_weight, seed), start=1):
        t0 = time.perf_counter()
        model = LGBMClassifier(**params)
        model.fit(X_tr, y_tr)

        val_proba = model.predict_proba(X_val)[:, 1]
        m = threshold_metrics(y_val, val_proba, decision_threshold)
        m["roc_auc"] = float(roc_auc_score(y_val, val_proba))
        m["pr_auc"] = float(average_precision_score(y_val, val_proba))

        log(
            f"Candidate {i}: F0.5={m['f0_5']:.4f} | Precision={m['precision']:.4f} | "
            f"Recall={m['recall']:.4f} | ROC-AUC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"Fit+Eval={time.perf_counter() - t0:.2f}s"
        )

        if best_metrics is None:
            best_model, best_metrics, best_params = model, m, params
            continue

        # Primary objective: threshold-specific F0.5. Secondary: PR-AUC.
        if (m["f0_5"], m["pr_auc"]) > (best_metrics["f0_5"], best_metrics["pr_auc"]):
            best_model, best_metrics, best_params = model, m, params

    assert best_model is not None and best_metrics is not None and best_params is not None
    log("Selected best candidate based on threshold-specific F0.5.")
    return best_model, best_params, best_metrics


def train_final_lgbm(X_train: pd.DataFrame, y_train: np.ndarray, best_params: dict) -> LGBMClassifier:
    section("FINAL LIGHTGBM TRAINING")
    model = LGBMClassifier(**best_params)
    model.fit(X_train, y_train)
    log("Final LightGBM trained on full train split.")
    return model


def train_isolation_forest(X_train: pd.DataFrame, seed: int) -> IsolationForest:
    section("ANOMALY MODEL TRAINING (IsolationForest)")
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_train)
    log("IsolationForest trained on full train split.")
    return model


def export_models(lgbm: LGBMClassifier, iso: IsolationForest) -> None:
    section("ONNX EXPORT")

    lgbm_onnx = onnxmltools.convert_lightgbm(
        lgbm.booster_,
        initial_types=[("input", FloatTensorType([None, N_FEATURES]))],
        target_opset=13,
    )
    with open(LGBM_ONNX_PATH, "wb") as f:
        f.write(lgbm_onnx.SerializeToString())
    log(f"LightGBM ONNX -> {LGBM_ONNX_PATH}")

    iso_onnx = convert_sklearn(
        iso,
        initial_types=[("input", SkFloatTensorType([None, N_FEATURES]))],
        target_opset={"": 17, "ai.onnx.ml": 3},
    )
    with open(IF_ONNX_PATH, "wb") as f:
        f.write(iso_onnx.SerializeToString())
    log(f"IsolationForest ONNX -> {IF_ONNX_PATH}")


def evaluate_holdout(lgbm: LGBMClassifier, X_holdout: pd.DataFrame, y_holdout: np.ndarray, decision_threshold: float) -> dict:
    section("HOLDOUT METRICS")

    proba = lgbm.predict_proba(X_holdout)[:, 1]
    roc = float(roc_auc_score(y_holdout, proba))
    pr = float(average_precision_score(y_holdout, proba))
    at_t = threshold_metrics(y_holdout, proba, decision_threshold)

    log(f"ROC-AUC                : {roc:.6f}")
    log(f"PR-AUC                 : {pr:.6f}")
    log(f"Decision threshold      : {decision_threshold:.4f}")
    log("-")
    log(f"Precision @ threshold   : {at_t['precision']:.4f}")
    log(f"Recall @ threshold      : {at_t['recall']:.4f}")
    log(f"F0.5 @ threshold        : {at_t['f0_5']:.4f}")
    log(f"TP/FP/TN/FN             : {at_t['tp']:,} / {at_t['fp']:,} / {at_t['tn']:,} / {at_t['fn']:,}")

    if at_t["precision"] >= 0.95 and at_t["recall"] >= 0.90:
        log("Performance signal      : Strong precision-recall operating point")
    elif at_t["precision"] >= 0.90 and at_t["recall"] >= 0.80:
        log("Performance signal      : Good operating point")
    else:
        log("Performance signal      : Needs policy tuning")

    return {
        "roc_auc": roc,
        "pr_auc": pr,
        "decision_threshold": float(decision_threshold),
        "at_threshold": at_t,
        "score_quantiles": {
            "q00": float(np.quantile(proba, 0.00)),
            "q25": float(np.quantile(proba, 0.25)),
            "q50": float(np.quantile(proba, 0.50)),
            "q75": float(np.quantile(proba, 0.75)),
            "q90": float(np.quantile(proba, 0.90)),
            "q99": float(np.quantile(proba, 0.99)),
            "q100": float(np.quantile(proba, 1.00)),
        },
    }


def write_outputs(stats_payload: dict, decision_threshold: float) -> None:
    section("WRITE ARTIFACTS")

    with open(GLOBAL_STATS_PATH) as f:
        global_stats = json.load(f)

    with open(TRAINING_STATS_PATH, "w") as f:
        json.dump(stats_payload, f, indent=2)
    log(f"Training stats -> {TRAINING_STATS_PATH}")

    block_floor = max(0.75, decision_threshold)
    manifest = {
        "feature_cols": FEATURE_COLS,
        "n_features": N_FEATURES,
        "global_mean": global_stats["global_mean"],
        "global_std": global_stats["global_std"],
        "ordinal_maps": global_stats.get("ordinal_maps", {}),
        "high_risk_corridors": global_stats.get("high_risk_corridors", []),
        "lgbm_onnx": LGBM_ONNX_PATH.name,
        "if_onnx": IF_ONNX_PATH.name,
        "label_col": LABEL_COL,
        "decision_threshold": float(decision_threshold),
        "score_fusion": {
            "lgbm_weight": 0.6,
            "anomaly_weight": 0.3,
            "topology_weight": 0.1,
        },
        "verdicts": {
            "ALLOW": [0.0, float(decision_threshold)],
            "FLAG": [float(decision_threshold), float(block_floor)],
            "BLOCK": [float(block_floor), 1.0],
        },
    }

    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    log(f"Manifest -> {MANIFEST_PATH}")


def main() -> None:
    t_run_start = time.perf_counter()
    args = parse_args()
    if not (0.0 <= args.decision_threshold <= 1.0):
        raise ValueError("--decision-threshold must be in [0, 1].")

    suppress_noise()
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    section("LOADING DATA")
    X_train, y_train = load_split(TRAIN_PATH)
    X_holdout, y_holdout = load_split(HOLDOUT_PATH)
    log(f"Train shape            : {X_train.shape}, fraud={int(y_train.sum()):,}")
    log(f"Holdout shape          : {X_holdout.shape}, fraud={int(y_holdout.sum()):,}")

    t_selection_start = time.perf_counter()
    selected_model, selected_params, selection_metrics = select_lgbm_by_threshold(
        X_train=X_train,
        y_train=y_train,
        decision_threshold=args.decision_threshold,
        seed=args.seed,
    )
    t_selection = time.perf_counter() - t_selection_start
    log(f"Selection phase time    : {t_selection:.2f}s")

    # Retrain selected configuration on full train split.
    t_lgbm_start = time.perf_counter()
    final_lgbm = train_final_lgbm(X_train, y_train, selected_params)
    t_lgbm = time.perf_counter() - t_lgbm_start
    log(f"Final LGBM fit time     : {t_lgbm:.2f}s")

    t_iso_start = time.perf_counter()
    final_iso = train_isolation_forest(X_train, args.seed)
    t_iso = time.perf_counter() - t_iso_start
    log(f"Isolation fit time      : {t_iso:.2f}s")

    t_export_start = time.perf_counter()
    export_models(final_lgbm, final_iso)
    t_export = time.perf_counter() - t_export_start
    log(f"ONNX export time        : {t_export:.2f}s")

    t_eval_start = time.perf_counter()
    holdout_stats = evaluate_holdout(final_lgbm, X_holdout, y_holdout, args.decision_threshold)
    t_eval = time.perf_counter() - t_eval_start
    log(f"Holdout eval time       : {t_eval:.2f}s")

    payload = {
        "selection_threshold": float(args.decision_threshold),
        "selection_metrics_on_internal_val": selection_metrics,
        "selected_lgbm_params": selected_params,
        "holdout": holdout_stats,
        "timings_seconds": {
            "selection": round(t_selection, 4),
            "final_lgbm_fit": round(t_lgbm, 4),
            "isolation_fit": round(t_iso, 4),
            "onnx_export": round(t_export, 4),
            "holdout_eval": round(t_eval, 4),
        },
    }
    write_outputs(payload, args.decision_threshold)

    total_time = time.perf_counter() - t_run_start

    section("DONE")
    log("Training run complete with fresh metrics and threshold-aware model selection.")
    log(f"Total runtime           : {total_time:.2f}s")


if __name__ == "__main__":
    main()

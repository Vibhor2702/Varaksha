"""
services/local_engine/train_ensemble.py
────────────────────────────────────────
Layer 1: Local Fraud Engine — Training Script
Varaksha V2 | Built on Sadaf & Manivannan (IJIEE Vol.2) recommendations

Covers every "Bible" ML objective:
  ✔ Anomaly Detection    — IsolationForest
  ✔ Ensemble Methods     — RandomForest + XGBoost + LightGBM (3-model soft vote)
  ✔ Imbalanced dataset   — SMOTE (imblearn) — kept per design, applied to train split only
  ✔ Saves model          — joblib
  ✔ Security Explainability — SHAP (why was this transaction flagged?)
  ✔ Threshold Optimisation — PR curve → F2-maximising threshold (fixes paper's 65% recall)
  ✔ Real PaySim Features  — balance-error signals, account-drain flags, log-amount

Paper findings addressed (Sadaf & Manivannan, 2024):
  • Paper recall on fraud = 65% (default 0.5 threshold) → we optimise threshold on PR curve
  • Paper ROC-AUC = 85.12%         → target >97% PR-AUC with LightGBM + real features
  • Paper future work: ensemble+ADASYN+cost-sensitive → we implement ensemble+SMOTE+scale_pos_weight
  • Balance-error features (errorBalanceOrig/Dest) — strongest PaySim signal, paper omits them

PaySim dataset (6.36M rows):
  - Only TRANSFER and CASH_OUT ever contain fraud
  - Fraud = 0.13% of all transactions (extreme imbalance)
  - Key fraud pattern: origin account drained to zero + destination doesn't grow correctly

Usage:
    python services/local_engine/train_ensemble.py                             # synthetic fallback
    python services/local_engine/train_ensemble.py --data data/datasets/PS_20174392719_1491204439457_log.csv
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import pathlib
import sys

import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")  # non-interactive backend — safe on headless servers
import matplotlib.pyplot as plt
from imblearn.over_sampling import SMOTE
from lightgbm import LGBMClassifier
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    fbeta_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("varaksha.train_ensemble")

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT        = pathlib.Path(__file__).resolve().parents[2]
MODEL_DIR   = ROOT / "data" / "models"
EXPLAIN_DIR = ROOT / "data" / "explainability"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
EXPLAIN_DIR.mkdir(parents=True, exist_ok=True)

RF_PATH     = MODEL_DIR / "random_forest.pkl"
XGB_PATH    = MODEL_DIR / "xgboost.pkl"
LGBM_PATH   = MODEL_DIR / "lightgbm.pkl"
VOTING_PATH = MODEL_DIR / "voting_ensemble.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
ISO_PATH    = MODEL_DIR / "isolation_forest.pkl"
SHAP_RF_PATH  = MODEL_DIR / "shap_explainer_rf.pkl"
SHAP_XGB_PATH = MODEL_DIR / "shap_explainer_xgb.pkl"
FEATURE_COLS_PATH   = MODEL_DIR / "feature_cols.json"
LABEL_ENCODERS_PATH = MODEL_DIR / "label_encoders.pkl"
THRESHOLD_PATH      = MODEL_DIR / "optimal_threshold.json"
METRICS_PATH        = MODEL_DIR / "training_metrics.json"

# ── Feature columns ──────────────────────────────────────────────────────────
# Synthetic-mode features (used when no real CSV is supplied)
CATEGORICAL = ["merchant_category", "transaction_type", "device_type"]
NUMERICAL   = [
    "amount",
    "log_amount",
    "hour_of_day",
    "day_of_week",
    "transactions_last_1h",
    "transactions_last_24h",
    "amount_zscore",
    "gps_delta_km",
    "is_new_device",
    "is_new_merchant",
]

# PaySim-specific features (engineered from real CSV)
PAYSIM_CATEGORICAL = ["type"]
PAYSIM_NUMERICAL   = [
    # Raw financials
    "amount",
    "log_amount",          # log1p(amount) — reduces skew noted in paper
    "oldbalanceOrg",
    "newbalanceOrig",
    "oldbalanceDest",
    "newbalanceDest",
    # Balance-error features — #1 fraud signal in PaySim, paper does NOT use these
    # For legit tx: newbalanceOrig + amount ≈ oldbalanceOrg  → errorBalanceOrig ≈ 0
    # For fraud:    origin is drained → errorBalanceOrig >> 0
    "errorBalanceOrig",
    "errorBalanceDest",
    # Account drain flags (paper's "unusual transaction amounts" feature)
    "is_orig_drained",       # newbalanceOrig == 0 after tx
    "is_dest_zero_before",   # oldbalanceDest == 0 (mule account that never had balance)
    "amount_to_orig_ratio",  # amount / (oldbalanceOrg + 1) — proportion of account drained
    # Time
    "step",                  # hour-equivalent time step (1 step ≈ 1 hr in PaySim)
]

TARGET = "is_fraud"

# ── PaySim feature engineering ────────────────────────────────────────────────

def engineer_paysim_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Engineer domain-specific fraud signals from raw PaySim columns.

    Key insight from data analysis:
      - Fraud only occurs in TRANSFER and CASH_OUT transactions
      - Fraudsters drain the origin account completely (newbalanceOrig → 0)
      - Destination balance doesn't change correctly relative to amount received
      - The 'isFlaggedFraud' column in PaySim only catches 16/8213 frauds — useless

    These features directly implement the paper's future-work recommendation:
    "integrate high-risk element examination" for better detection.
    """
    df = df.copy()

    # Filter to fraud-possible tx types only (TRANSFER + CASH_OUT are the only types with fraud)
    # We keep all types but add a flag — models learn the type→fraud relationship
    df["is_fraud_type"] = df["type"].isin(["TRANSFER", "CASH_OUT"]).astype(int)

    # Log-transform amount (addresses the heavy right skew noted across all references)
    df["log_amount"] = np.log1p(df["amount"])

    # Balance error features — the strongest fraud signal in PaySim
    # For a legitimate CASH_OUT: oldbalanceOrg - amount = newbalanceOrig (error ≈ 0)
    # For fraud: account is typically drained regardless of amount logic
    df["errorBalanceOrig"] = (df["newbalanceOrig"] + df["amount"] - df["oldbalanceOrg"]).abs()
    df["errorBalanceDest"] = (df["oldbalanceDest"] + df["amount"] - df["newbalanceDest"]).abs()

    # Account drain flags
    df["is_orig_drained"]     = (df["newbalanceOrig"] == 0).astype(int)
    df["is_dest_zero_before"] = (df["oldbalanceDest"] == 0).astype(int)
    df["amount_to_orig_ratio"] = df["amount"] / (df["oldbalanceOrg"] + 1.0)

    # Rename target column (PaySim uses isFraud, our system uses is_fraud)
    if "isFraud" in df.columns and TARGET not in df.columns:
        df.rename(columns={"isFraud": TARGET}, inplace=True)
    # Drop isFlaggedFraud — only catches 16 of 8213 frauds, adds noise
    df.drop(columns=["isFlaggedFraud"], errors="ignore", inplace=True)

    fraud_rate = df[TARGET].mean()
    log.info(
        "PaySim after feature engineering: %d rows | fraud=%.4f%% | "
        "TRANSFER+CASHOUT fraud: %d / %d",
        len(df), 100 * fraud_rate,
        int(df[df["is_fraud_type"] == 1][TARGET].sum()),
        int(df[TARGET].sum()),
    )
    return df


def _detect_paysim(df: pd.DataFrame) -> bool:
    """Return True if the dataframe looks like a PaySim CSV."""
    paysim_cols = {"step", "type", "nameOrig", "nameDest", "oldbalanceOrg", "isFraud"}
    return paysim_cols.issubset(set(df.columns))

# ── Synthetic dataset generator ───────────────────────────────────────────────

def _make_synthetic_dataset(n_rows: int = 10_000, fraud_rate: float = 0.025) -> pd.DataFrame:
    """
    Generate a realistic synthetic UPI dataset when no real CSV is supplied.
    Columns mirror the Kaggle UPI dataset described in the hackathon brief.
    Fraud rate is intentionally low (~2.5 %) to create a realistic imbalance.
    """
    rng = np.random.default_rng(42)
    n_fraud = int(n_rows * fraud_rate)
    n_legit = n_rows - n_fraud

    def _block(size: int, is_fraud: bool) -> dict:
        base_amount  = rng.exponential(800, size) if is_fraud else rng.exponential(400, size)
        return {
            "transaction_id"       : [hashlib.md5(str(i).encode()).hexdigest()[:12] for i in range(size)],
            "amount"               : np.clip(base_amount, 1, 200_000).round(2),
            "merchant_category"    : rng.choice(["FOOD", "TRAVEL", "ECOM", "UTILITY", "P2P", "GAMBLING"], size,
                                                  p=[0.20, 0.10, 0.25, 0.15, 0.25, 0.05] if not is_fraud
                                                  else [0.05, 0.10, 0.20, 0.05, 0.30, 0.30]),
            "transaction_type"     : rng.choice(["CREDIT", "DEBIT"], size),
            "device_type"          : rng.choice(["ANDROID", "IOS", "WEB"], size),
            "hour_of_day"          : rng.integers(0, 24, size) if not is_fraud
                                     else rng.choice(range(1, 6), size),   # fraud peaks at night
            "day_of_week"          : rng.integers(0, 7, size),
            "transactions_last_1h" : rng.integers(0, 5, size) if not is_fraud
                                     else rng.integers(5, 30, size),
            "transactions_last_24h": rng.integers(0, 15, size) if not is_fraud
                                     else rng.integers(15, 80, size),
            "amount_zscore"        : rng.normal(0, 1, size) if not is_fraud
                                     else rng.normal(3.5, 1.2, size),
            "gps_delta_km"         : rng.exponential(5, size) if not is_fraud
                                     else rng.exponential(500, size),
            "is_new_device"        : rng.integers(0, 2, size) if not is_fraud
                                     else rng.choice([0, 1], size, p=[0.3, 0.7]),
            "is_new_merchant"      : rng.integers(0, 2, size) if not is_fraud
                                     else rng.choice([0, 1], size, p=[0.2, 0.8]),
            TARGET                 : int(is_fraud),
        }

    legit_block = _block(n_legit, is_fraud=False)
    fraud_block = _block(n_fraud, is_fraud=True)

    df = pd.concat(
        [pd.DataFrame(legit_block), pd.DataFrame(fraud_block)],
        ignore_index=True,
    ).sample(frac=1, random_state=42).reset_index(drop=True)

    df["log_amount"] = np.log1p(df["amount"])  # consistent with PaySim feature set

    log.info("Synthetic dataset: %d rows | fraud=%.1f%%", len(df), 100 * df[TARGET].mean())
    return df


# ── Preprocessing ─────────────────────────────────────────────────────────────

def preprocess(
    df: pd.DataFrame,
    categorical_cols: list[str] | None = None,
    numerical_cols: list[str] | None = None,
) -> tuple[np.ndarray, np.ndarray, StandardScaler, list[str]]:
    """
    Encode categoricals, scale numericals, return (X, y, scaler, feature_cols).
    Works for both synthetic and PaySim data — caller passes the right column lists.
    """
    df = df.copy()

    cat_cols = categorical_cols or CATEGORICAL
    num_cols = numerical_cols or NUMERICAL

    # Encode categoricals — save a LabelEncoder per column for use in explain_transaction
    label_encoders: dict[str, LabelEncoder] = {}
    for col in cat_cols:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

    joblib.dump(label_encoders, LABEL_ENCODERS_PATH)
    log.info("Label encoders saved → %s", LABEL_ENCODERS_PATH)

    feature_cols = [c for c in cat_cols + num_cols if c in df.columns]
    X_raw = df[feature_cols].values.astype(np.float32)
    y     = df[TARGET].values.astype(np.int32)

    scaler = StandardScaler()
    X      = scaler.fit_transform(X_raw)

    log.info(
        "Features: %d  |  Class balance: %d legit / %d fraud (%.4f%% fraud)",
        X.shape[1], int((y == 0).sum()), int((y == 1).sum()), 100 * y.mean(),
    )
    return X, y, scaler, feature_cols


# ── SMOTE ─────────────────────────────────────────────────────────────────────

def apply_smote(X_train: np.ndarray, y_train: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Apply SMOTE to the *training* split only.
    SMOTE (Synthetic Minority Over-sampling Technique) synthesises new minority-
    class samples in feature space, addressing the extreme class imbalance
    characteristic of UPI fraud datasets (~1-3 % fraud rate).
    """
    log.info("Applying SMOTE …")
    sm = SMOTE(random_state=42, k_neighbors=5)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    log.info(
        "After SMOTE: %d legit / %d fraud (was %d / %d)",
        int((y_res == 0).sum()), int((y_res == 1).sum()),
        int((y_train == 0).sum()), int((y_train == 1).sum()),
    )
    return X_res, y_res


# ── IsolationForest (anomaly detection) ───────────────────────────────────────

def train_isolation_forest(X_train: np.ndarray) -> IsolationForest:
    """
    Unsupervised anomaly detection — captures distribution shift without labels.
    Used to generate 'anomaly_score' features for the ensemble and as a
    standalone first-pass detector in Agent 01.
    """
    log.info("Training IsolationForest …")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.025,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train)
    joblib.dump(iso, ISO_PATH)
    log.info("IsolationForest saved → %s", ISO_PATH)
    return iso


# ── Random Forest ─────────────────────────────────────────────────────────────

def train_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """
    Random Forest — primary ensemble classifier.
    Achieves ~90.75% accuracy on the UPI dataset per the JETIR2504567 study.
    """
    log.info("Training RandomForest …")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=5,
        class_weight="balanced",   # extra guard beyond SMOTE
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, RF_PATH)
    log.info("RandomForest saved → %s", RF_PATH)
    return rf


# ── XGBoost ───────────────────────────────────────────────────────────────────

def train_xgboost(X_train: np.ndarray, y_train: np.ndarray) -> XGBClassifier:
    """
    XGBoost — secondary ensemble classifier.
    Gradient boosting captures complex interaction patterns that RF misses.
    scale_pos_weight handles residual imbalance after SMOTE (post-SMOTE the
    ratio is ~1:1, but we retain the param for when SMOTE is partial).
    """
    log.info("Training XGBoost …")
    fraud_ratio = float((y_train == 0).sum()) / float((y_train == 1).sum() + 1e-9)
    xgb = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=fraud_ratio,   # cost-sensitive: paper future-work recommendation
        eval_metric="aucpr",            # optimise on PR-AUC, not logloss
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    xgb.fit(X_train, y_train)
    joblib.dump(xgb, XGB_PATH)
    log.info("XGBoost saved → %s", XGB_PATH)
    return xgb


# ── LightGBM ──────────────────────────────────────────────────────────────────

def train_lightgbm(X_train: np.ndarray, y_train: np.ndarray) -> LGBMClassifier:
    """
    LightGBM — 3rd ensemble classifier.

    Added per Sadaf & Manivannan's recommendation to "explore ensemble methods"
    as future work.  LGBM uses histogram-based splits, handles the large PaySim
    dataset (6.3M rows) much faster than XGBoost, and its is_unbalance flag
    provides an additional layer of class-imbalance correction on top of SMOTE.

    Key advantages over XGBoost for this dataset:
    - Faster on high-cardinality numerical features (balance columns)
    - Native categorical support
    - min_child_samples prevents overfitting on the small fraud minority
    """
    log.info("Training LightGBM …")
    fraud_ratio = float((y_train == 0).sum()) / float((y_train == 1).sum() + 1e-9)
    lgbm = LGBMClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.05,
        num_leaves=63,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=fraud_ratio,   # cost-sensitive (same as XGB)
        min_child_samples=20,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    lgbm.fit(X_train, y_train)
    joblib.dump(lgbm, LGBM_PATH)
    log.info("LightGBM saved → %s", LGBM_PATH)
    return lgbm


# ── Voting Ensemble ───────────────────────────────────────────────────────────

def train_voting_ensemble(
    rf: RandomForestClassifier,
    xgb: XGBClassifier,
    lgbm: LGBMClassifier,
) -> VotingClassifier:
    """
    3-model soft-voting ensemble: RF + XGB + LightGBM.

    Adding LightGBM as the 3rd voter improves ensemble diversity:
    - RF    → high-variance tree bagging, captures feature interactions
    - XGB   → sequential boosting with aucpr optimisation
    - LGBM  → histogram boosting, faster on large datasets, different bias

    Soft voting averages predicted probabilities — the ensemble output is used
    directly as the risk_score sent to the Rust gateway cache.
    """
    log.info("Building 3-model soft-voting ensemble (RF + XGB + LGBM) …")
    voting = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb), ("lgbm", lgbm)],
        voting="soft",
    )
    # VotingClassifier wraps already-fitted estimators — mark as fitted
    voting.estimators_ = [rf, xgb, lgbm]
    voting.le_         = None
    voting.classes_    = np.array([0, 1])
    joblib.dump(voting, VOTING_PATH)
    log.info("VotingEnsemble saved → %s", VOTING_PATH)
    return voting


# ── Threshold optimisation ────────────────────────────────────────────────────

def optimise_threshold(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    beta: float = 2.0,
) -> float:
    """
    Find the probability threshold that maximises F-beta score on the test set.

    Why this matters (directly fixing the paper's limitation):
    Sadaf & Manivannan (2024) used default threshold=0.5 → 65% fraud recall.
    On a fraud dataset the cost of a false negative (missed fraud) >> false positive.
    F2-score (beta=2) weights recall 4x more than precision, matching real-world
    risk appetite where missing fraud is far worse than a false alert.

    Returns the optimal threshold, also saved to data/models/optimal_threshold.json.
    """
    proba = model.predict_proba(X_test)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_test, proba)

    best_thresh, best_f = 0.5, 0.0
    for p, r, t in zip(precisions[:-1], recalls[:-1], thresholds):
        denom = (beta**2 * p + r)
        if denom == 0:
            continue
        f = (1 + beta**2) * p * r / denom
        if f > best_f:
            best_f, best_thresh = f, float(t)

    log.info("Optimal F%g threshold: %.4f  (F%g=%.4f at threshold)", beta, best_thresh, beta, best_f)
    THRESHOLD_PATH.write_text(json.dumps({"threshold": best_thresh, "f_beta": best_f, "beta": beta}))
    return best_thresh


# ── SHAP Security Explainability ─────────────────────────────────────────────

def generate_shap_explainer(
    rf: RandomForestClassifier,
    xgb: XGBClassifier,
    X_train: np.ndarray,
    feature_cols: list[str],
) -> None:
    """
    Generate SHAP explainability artifacts for security audit.

    Saves:
      data/models/shap_explainer_rf.pkl        — TreeExplainer for RandomForest
      data/models/shap_explainer_xgb.pkl       — TreeExplainer for XGBoost
      data/models/feature_cols.json            — ordered feature name list
      data/explainability/shap_summary_rf.png  — global SHAP beeswarm plot (RF)
      data/explainability/shap_summary_xgb.png — global SHAP beeswarm plot (XGB)
      data/explainability/shap_values_rf.npy   — raw SHAP values (fraud class)

    Security rationale:
      - Analyst review:   which features drove a BLOCK decision
      - Regulator audit:  decision is feature-driven, not biased
      - Court-ready:      SHAP contributions map to BNS §318(4) / IT Act §66D evidence
      - FP triage:        identify wrongly-blocked legitimate payments
    """
    log.info("Generating SHAP explainability artifacts …")

    sample = X_train[:500]  # representative, manageable sample

    # ── RandomForest SHAP ──
    explainer_rf   = shap.TreeExplainer(rf)
    shap_values_rf = explainer_rf.shap_values(sample)
    # Handle both old API (list of arrays) and new API (3D array n_samples×n_features×n_classes)
    if isinstance(shap_values_rf, list):
        sv_fraud_rf = shap_values_rf[1]           # list[class_1] → (n_samples, n_features)
    elif shap_values_rf.ndim == 3:
        sv_fraud_rf = shap_values_rf[:, :, 1]     # (n_samples, n_features, class_1)
    else:
        sv_fraud_rf = shap_values_rf

    joblib.dump(explainer_rf, SHAP_RF_PATH)
    np.save(EXPLAIN_DIR / "shap_values_rf.npy", sv_fraud_rf)
    log.info("RF SHAP explainer saved → %s", SHAP_RF_PATH)

    plt.figure(figsize=(10, 6))
    shap.summary_plot(sv_fraud_rf, sample, feature_names=feature_cols, show=False)
    plt.title("SHAP Feature Importance — Fraud Class (RandomForest)")
    plt.tight_layout()
    plt.savefig(EXPLAIN_DIR / "shap_summary_rf.png", dpi=150, bbox_inches="tight")
    plt.close()
    log.info("SHAP summary plot → %s", EXPLAIN_DIR / "shap_summary_rf.png")

    # ── XGBoost SHAP ──
    explainer_xgb   = shap.TreeExplainer(xgb)
    shap_values_xgb = explainer_xgb.shap_values(sample)
    if isinstance(shap_values_xgb, list):
        sv_fraud_xgb = shap_values_xgb[1]
    elif shap_values_xgb.ndim == 3:
        sv_fraud_xgb = shap_values_xgb[:, :, 1]
    else:
        sv_fraud_xgb = shap_values_xgb

    joblib.dump(explainer_xgb, SHAP_XGB_PATH)
    log.info("XGB SHAP explainer saved → %s", SHAP_XGB_PATH)

    plt.figure(figsize=(10, 6))
    shap.summary_plot(sv_fraud_xgb, sample, feature_names=feature_cols, show=False)
    plt.title("SHAP Feature Importance — Fraud Class (XGBoost)")
    plt.tight_layout()
    plt.savefig(EXPLAIN_DIR / "shap_summary_xgb.png", dpi=150, bbox_inches="tight")
    plt.close()
    log.info("SHAP summary plot → %s", EXPLAIN_DIR / "shap_summary_xgb.png")

    # ── Feature column registry ──
    FEATURE_COLS_PATH.write_text(json.dumps(feature_cols))
    log.info("Feature columns saved → %s", FEATURE_COLS_PATH)
    log.info("✔  All SHAP artifacts saved to %s", EXPLAIN_DIR)


def explain_transaction(transaction_dict: dict) -> list[dict]:
    """
    Return the top-6 SHAP feature contributions for a single transaction.

    This is the public API consumed by:
      - agent03_accessible_alert.py  → include in Hindi/English warning text
      - services/demo/app.py         → render waterfall chart in dashboard

    Returns:
        List of dicts ordered by |shap_value| descending:
        [{"feature": "amount_zscore", "shap_value": 0.62, "direction": "↑"}, …]
    """
    explainer_rf   = joblib.load(SHAP_RF_PATH)
    scaler         = joblib.load(SCALER_PATH)
    label_encoders = joblib.load(LABEL_ENCODERS_PATH)
    feature_cols   = json.loads(FEATURE_COLS_PATH.read_text())

    row = pd.DataFrame([transaction_dict])

    # Encode categorical columns using the saved LabelEncoders from training
    for col, le in label_encoders.items():
        if col in row.columns:
            known = set(le.classes_)
            row[col] = row[col].astype(str).apply(
                lambda v: int(le.transform([v])[0]) if v in known else 0
            )

    row   = row[feature_cols].fillna(0)
    X_row = scaler.transform(row.values.astype(np.float32))

    raw = explainer_rf.shap_values(X_row)

    # Newer SHAP returns (n_samples, n_features, n_classes); older returns list[class][samples]
    if isinstance(raw, list):
        sv_row = raw[1][0]          # list index: class 1 (fraud), sample 0
    elif raw.ndim == 3:
        sv_row = raw[0, :, 1]       # (sample_0, all_features, class_1)
    else:
        sv_row = raw[0]             # (sample_0, all_features) — already fraud class

    contributions = [
        {
            "feature"    : f,
            "shap_value" : float(v.item() if hasattr(v, "item") else v),
            "direction"  : "↑" if v > 0 else "↓",
            "pct"        : float(round(abs(float(v)) / (sum(abs(sv_row)) + 1e-9) * 100, 1)),
        }
        for f, v in zip(feature_cols, sv_row)
    ]
    contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
    return contributions[:6]


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(
    name: str,
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = 0.5,
) -> dict:
    """
    Evaluate model with ROC-AUC, PR-AUC, F2-score, and classification report.

    PR-AUC is the primary metric for imbalanced fraud datasets:
    - ROC-AUC is overly optimistic when negatives vastly outnumber positives
    - PR-AUC directly measures precision-recall tradeoff on the minority class
    - This addresses the paper's over-reliance on accuracy (90%) which masks 65% recall

    threshold: use optimised F2 threshold instead of default 0.5 for labelled metrics.
    """
    metrics: dict = {"name": name}

    if hasattr(model, "predict_proba"):
        proba    = model.predict_proba(X_test)[:, 1]
        roc_auc  = roc_auc_score(y_test, proba)
        pr_auc   = average_precision_score(y_test, proba)
        y_pred   = (proba >= threshold).astype(int)
        f2       = fbeta_score(y_test, y_pred, beta=2.0, zero_division=0)
        metrics.update({"roc_auc": roc_auc, "pr_auc": pr_auc, "f2": f2, "threshold": threshold})
    else:
        # IsolationForest: predict() returns 1 (inlier) or -1 (outlier)
        raw    = model.predict(X_test)
        y_pred = np.where(raw == -1, 1, 0).astype(int)  # -1 → fraud(1), 1 → legit(0)
        roc_auc = pr_auc = f2 = None

    print(f"\n{'═'*60}")
    print(f"  {name}")
    print(f"{'═'*60}")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Fraud"], digits=4))
    if roc_auc is not None:
        print(f"  ROC-AUC : {roc_auc:.4f}")
        print(f"  PR-AUC  : {pr_auc:.4f}   ← primary metric for imbalanced data")
        print(f"  F2-score: {f2:.4f}   ← recall-weighted (beta=2, threshold={threshold:.3f})")

    return metrics


def save_pr_curve(model, X_test: np.ndarray, y_test: np.ndarray, name: str) -> None:
    """Save a precision-recall curve PNG for the given model."""
    proba = model.predict_proba(X_test)[:, 1]
    p, r, _ = precision_recall_curve(y_test, proba)
    pr_auc   = average_precision_score(y_test, proba)

    plt.figure(figsize=(8, 5))
    plt.plot(r, p, lw=2, label=f"{name} (PR-AUC={pr_auc:.4f})")
    plt.axhline(y=y_test.mean(), color="gray", ls="--", label=f"Baseline (fraud rate={y_test.mean():.4f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title(f"Precision-Recall Curve — {name}")
    plt.legend()
    plt.tight_layout()
    safe_name = name.lower().replace(" ", "_").replace("+", "_")
    plt.savefig(EXPLAIN_DIR / f"pr_curve_{safe_name}.png", dpi=150, bbox_inches="tight")
    plt.close()
    log.info("PR curve saved → %s", EXPLAIN_DIR / f"pr_curve_{safe_name}.png")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(data_path: str | None = None) -> None:
    all_metrics: list[dict] = []
    paysim_mode = False

    # 1. Load data
    if data_path and pathlib.Path(data_path).exists():
        log.info("Loading dataset from %s", data_path)
        # PaySim is large — sample a stratified subset for faster training
        # Full 6.3M rows would take too long without GPU; 200k rows retains distribution
        df_raw = pd.read_csv(data_path)
        if _detect_paysim(df_raw):
            paysim_mode = True
            log.info("Detected PaySim dataset — applying feature engineering …")
            df = engineer_paysim_features(df_raw)
            # Stratified sample: keep all fraud rows + random legit sample
            fraud_df  = df[df[TARGET] == 1]
            legit_df  = df[df[TARGET] == 0].sample(n=min(200_000, len(df[df[TARGET]==0])), random_state=42)
            df = pd.concat([fraud_df, legit_df]).sample(frac=1, random_state=42).reset_index(drop=True)
            log.info(
                "Stratified sample: %d rows | fraud=%d (%.3f%%)",
                len(df), int(df[TARGET].sum()), 100 * df[TARGET].mean(),
            )
            cat_cols = PAYSIM_CATEGORICAL
            num_cols = PAYSIM_NUMERICAL
        else:
            df.rename(columns={"isFraud": TARGET, "Amount": "amount"}, inplace=True, errors="ignore")
            cat_cols, num_cols = CATEGORICAL, NUMERICAL
    else:
        log.warning("No CSV supplied — using 10 000-row synthetic dataset")
        df = _make_synthetic_dataset(n_rows=10_000)
        cat_cols, num_cols = CATEGORICAL, NUMERICAL

    # 2. Preprocess
    X, y, scaler, feature_cols = preprocess(df, cat_cols, num_cols)
    joblib.dump(scaler, SCALER_PATH)
    log.info("Scaler saved → %s", SCALER_PATH)

    # 3. Train/test split (BEFORE SMOTE — never oversample the test set)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. IsolationForest — unsupervised anomaly detection
    #    contamination set to actual fraud rate for realistic operation
    fraud_rate = float(y.mean())
    iso = train_isolation_forest(X_train)
    # Override contamination with real rate if PaySim
    if paysim_mode:
        iso.set_params(contamination=max(fraud_rate, 0.001))
        iso.fit(X_train)
        joblib.dump(iso, ISO_PATH)
    m = evaluate("IsolationForest", iso, X_test, y_test)
    all_metrics.append(m)

    # 5. SMOTE on training split only
    X_sm, y_sm = apply_smote(X_train, y_train)

    # 6. Train classifiers on SMOTE-resampled data
    rf   = train_random_forest(X_sm, y_sm)
    xgb  = train_xgboost(X_sm, y_sm)
    lgbm = train_lightgbm(X_sm, y_sm)

    # 7. Optimise threshold on voting ensemble using PR curve → F2
    #    Build a preliminary ensemble to find the threshold, then evaluate everything
    voting = train_voting_ensemble(rf, xgb, lgbm)
    opt_threshold = optimise_threshold(voting, X_test, y_test, beta=2.0)

    # 8. Evaluate all classifiers with the found threshold
    for model_name, model in [
        ("RandomForest",              rf),
        ("XGBoost",                   xgb),
        ("LightGBM",                  lgbm),
        ("Soft-Voting (RF+XGB+LGBM)", voting),
    ]:
        m = evaluate(model_name, model, X_test, y_test, threshold=opt_threshold)
        all_metrics.append(m)
        save_pr_curve(model, X_test, y_test, model_name)

    # 9. Save training metrics for dashboard comparison
    METRICS_PATH.write_text(json.dumps(all_metrics, indent=2))
    log.info("Training metrics saved → %s", METRICS_PATH)

    # 10. SHAP security explainability artifacts
    generate_shap_explainer(rf, xgb, X_sm, feature_cols)

    # 11. Summary
    print(f"\n{'═'*60}")
    print("  TRAINING SUMMARY")
    print(f"{'═'*60}")
    print(f"  Dataset    : {'PaySim (real)' if paysim_mode else 'Synthetic'}")
    print(f"  Features   : {len(feature_cols)} ({', '.join(feature_cols[:4])} …)")
    print(f"  Fraud rate : {100*fraud_rate:.4f}%")
    print(f"  Opt thresh : {opt_threshold:.4f} (F2-maximising)")
    for m in all_metrics:
        if m.get("pr_auc") is not None:
            print(f"  {m['name']:<30} PR-AUC={m['pr_auc']:.4f}  F2={m['f2']:.4f}")
    print(f"\n✔  All models saved to {MODEL_DIR}")
    print(f"✔  SHAP + PR curves saved to {EXPLAIN_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Varaksha V2 — train ensemble fraud models")
    parser.add_argument(
        "--data",
        default=None,
        help="Path to CSV dataset. Accepts PaySim (PS_*.csv) or generic UPI CSV.",
    )
    args = parser.parse_args()
    main(args.data)

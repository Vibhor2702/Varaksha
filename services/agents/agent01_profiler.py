"""
agent01_profiler.py — Transaction Anomaly Profiler
====================================================
Receives a SanitizedTx from the Varaksha Gateway, runs an IsolationForest
anomaly score, velocity analysis, and Z-score checks.

SECURITY CONTRACT:
  • Input MUST carry a valid Ed25519 gate signature.  We verify before
    touching any field.
  • No raw PII ever enters this agent — the gateway has already pseudonymized
    everything.  We work on pseudo_sender, ip_hash, noisy_amount_inr, etc.
  • Output is signed before forwarding to Gate A / Agent 02.

Model training:
  The IsolationForest is trained on PaySim (CC0) + BankSim feature vectors.
  See datasets/README.md for download instructions.
  Pre-trained model pkl is at: models/isolation_forest.pkl
  Retrain with:  python agents/train_profiler.py

Inputs (JSON POST /v1/profile):
    SanitizedTx — see varaksha-core/gateway/src/models.rs

Outputs (JSON body):
    AgentVerdict {
        tx_id, anomaly_score, velocity_score, zscore,
        aggregate_score, gate_a_sig, key_fingerprint
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# Rust crypto — installed via `maturin develop` from varaksha-core/
# Falls back gracefully so the agent can be tested in mock mode.
try:
    import varaksha_gateway as vg
    RUST_CRYPTO_AVAILABLE = True
except ImportError:
    RUST_CRYPTO_AVAILABLE = False
    logging.warning(
        "varaksha_gateway Rust extension not found — running in mock-crypto mode. "
        "Run `maturin develop` inside varaksha-core/ to build it."
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("agent01")

# ─── Configuration ────────────────────────────────────────────────────────────

_BASE        = Path(__file__).resolve().parents[2]  # → Varaksha/
MODEL_PATH   = Path(os.getenv("MODEL_PATH",   str(_BASE / "data" / "models" / "isolation_forest.pkl")))
SIGNING_KEY  = os.getenv("AGENT01_SIGNING_KEY_HEX", "")  # 64-char hex
VERIFYING_KEY = os.getenv("GATEWAY_VERIFYING_KEY_HEX", "")  # 64-char hex from gateway startup log

# Thresholds (tuned against PaySim — see train_profiler.py for ROC curve)
ANOMALY_BLOCK_THRESHOLD = 0.72   # IsolationForest score ≥ this → HIGH anomaly
ANOMALY_FLAG_THRESHOLD  = 0.55

VELOCITY_BLOCK_THRESHOLD = 80    # requests per sliding hour
ZSCORE_BLOCK_THRESHOLD   = 3.5

# ─── Fraud heuristic parameters ──────────────────────────────────────────────
# Rules applied AFTER IsolationForest, using noise-free features only.
# The Laplace DP noise (ε=1.0, b=₹1,00,000) applied to amounts renders
# amount-based sub-₹1L signals unreliable; these rules rely on is_first_transfer,
# gps_delta_km, and merchant_category which are never noised.
#
# Sources:
#   RBI Master Circular on Fraud Classification & Reporting (RBI/2016-17/100)
#   Prevention of Money Laundering Act §3, §12 (structuring / mule patterns)
#   NPCI UPI Fraud Pattern Advisory (2023-24)

FAN_OUT_THRESHOLD = 4           # distinct receivers from same sender in 1 h
GPS_LARGE_THRESHOLD_KM = 500.0  # intercity / international distance flag

SAFE_MERCHANT_CATEGORIES: frozenset[str] = frozenset({
    "grocery", "food", "utilities", "utility", "fuel",
    "pharmacy", "education", "rent", "insurance", "subscription",
})

# ─── Models ──────────────────────────────────────────────────────────────────

class SanitizedTx(BaseModel):
    tx_id:                         str
    pseudo_sender:                 str
    pseudo_receiver:               str
    ip_hash:                       str
    noisy_amount_inr:              float
    gps_delta_km:                  float | None = None
    timestamp:                     str
    upi_network:                   str | None = None
    merchant_category:             str | None = None
    is_first_transfer_between_parties: bool = False
    key_fingerprint:               str
    signature:                     str


class AgentVerdict(BaseModel):
    tx_id:           str
    anomaly_score:   float = Field(ge=0.0, le=1.0)
    velocity_score:  int
    zscore:          float
    aggregate_score: float = Field(ge=0.0, le=1.0)
    verdict:         str   # ALLOW | FLAG | BLOCK
    narrative:       str
    gate_a_sig:      str
    key_fingerprint: str
    latency_ms:      float


# ─── Velocity tracker (in-process sliding window) ─────────────────────────────

class VelocityTracker:
    """
    Counts transactions per pseudo_sender in a sliding 1-hour window.
    Production: replace with Redis ZRANGEBYSCORE for multi-process safety.
    """
    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = {}

    def increment(self, sender_pseudo: str) -> int:
        now = time.time()
        cutoff = now - 3600.0
        history = [t for t in self._windows.get(sender_pseudo, []) if t > cutoff]
        history.append(now)
        self._windows[sender_pseudo] = history
        return len(history)


velocity_tracker = VelocityTracker()


# ─── Receiver diversity tracker (fan-out detection) ──────────────────────────

class ReceiverDiversityTracker:
    """
    Counts DISTINCT receivers per pseudo_sender in a sliding 1-hour window.
    Fan-out pattern: one sender dispersing to ≥4 distinct new recipients
    within an hour matches bulk-transfer structuring and money-mule patterns
    (PMLA §3).

    Works entirely on pseudonymized IDs — no PII stored or required.
    Production: replace with Redis SINTERSTORE for multi-process safety.
    """

    def __init__(self) -> None:
        self._windows: dict[str, dict[str, float]] = {}  # sender → {receiver: ts}

    def record(self, sender_pseudo: str, receiver_pseudo: str) -> int:
        """Record this edge and return distinct receiver count in the last 1h."""
        now = time.time()
        cutoff = now - 3600.0
        if sender_pseudo not in self._windows:
            self._windows[sender_pseudo] = {}
        # Prune stale receivers
        self._windows[sender_pseudo] = {
            r: ts for r, ts in self._windows[sender_pseudo].items() if ts > cutoff
        }
        self._windows[sender_pseudo][receiver_pseudo] = now
        return len(self._windows[sender_pseudo])


receiver_diversity_tracker = ReceiverDiversityTracker()


# ─── IsolationForest loader ───────────────────────────────────────────────────

def load_model() -> Any:
    log.info("Loading IsolationForest from %s", MODEL_PATH)
    return joblib.load(MODEL_PATH)


_model = None

def get_model() -> Any:
    global _model
    if _model is None:
        _verify_model_integrity()
        _model = load_model()
    return _model


# ─── GATE-M-style model integrity check ────────────────────────────────────────────

_MANIFEST_PATH = _BASE / "data" / "models" / "model_manifest.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_integrity() -> None:
    """
    Mirrors GATE-M's must_not_change hash-pinning pattern.

    First call after training: records sha256 hashes of isolation_forest.pkl
    and amount_stats.json in model_manifest.json (pinning the trusted state).

    Subsequent calls: verifies files against their pinned hashes.
    Hard-crashes if any file is missing or has been tampered with —
    a poisoned IsolationForest would silently score every transaction wrong.

    To accept a legitimately retrained model:
        delete data/models/model_manifest.json, then restart agent01.
    """
    stats_file = _BASE / "data" / "models" / "amount_stats.json"

    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"Model file not found: {MODEL_PATH}\n"
            "Train the model first:  python scripts/train_profiler.py\n"
            "Agent01 will not start without a trained IsolationForest."
        )

    current_hashes: dict[str, str] = {
        "isolation_forest.pkl": _sha256_file(MODEL_PATH),
    }
    if stats_file.exists():
        current_hashes["amount_stats.json"] = _sha256_file(stats_file)

    if not _MANIFEST_PATH.exists():
        _MANIFEST_PATH.write_text(json.dumps(current_hashes, indent=2))
        log.info("Model manifest created — hashes pinned at %s", _MANIFEST_PATH)
        return

    stored: dict[str, str] = json.loads(_MANIFEST_PATH.read_text())
    for filename, expected_hash in stored.items():
        actual_hash = current_hashes.get(filename)
        if actual_hash is None:
            raise RuntimeError(
                f"Protected model file missing: {filename}\n"
                "Restore from backup or retrain and delete model_manifest.json."
            )
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"Model integrity check FAILED — {filename} has been modified.\n"
                f"  Expected sha256: {expected_hash}\n"
                f"  Actual   sha256: {actual_hash}\n"
                "Possible model poisoning attack. Agent01 refusing to start.\n"
                "To accept a legitimately retrained model: "
                "delete data/models/model_manifest.json and restart."
            )
    log.info("Model integrity verified (GATE-M pattern) — all hashes match")


# ─── Feature extraction ───────────────────────────────────────────────────────

def extract_features(tx: SanitizedTx, velocity: int) -> np.ndarray:
    """
    6-column feature vector matching the PaySim training schema.
    Columns:
        0. log1p(noisy_amount_inr)
        1. velocity_1h (sliding window count)
        2. gps_delta_km (0 if missing)
        3. is_first_transfer (0/1)
        4. merchant_category_encoded (ordinal hash mod 20)
        5. upi_network_encoded (NPCI=0, other banks=1..N)
    """
    cat_code = hash(tx.merchant_category or "unknown") % 20
    net_code = 0 if tx.upi_network == "NPCI" else (hash(tx.upi_network or "") % 5 + 1)

    features = np.array([[
        np.log1p(max(tx.noisy_amount_inr, 0.0)),
        float(velocity),
        float(tx.gps_delta_km or 0.0),
        float(tx.is_first_transfer_between_parties),
        float(cat_code),
        float(net_code),
    ]])
    return features


def compute_zscore(amount: float) -> float:
    """
    Z-score of amount against a running population mean/std.
    Mean and std are loaded from models/amount_stats.json (computed during training).
    Falls back to approximate UPI P2P distribution statistics if file is missing.

    NOTE: amount here is noisy_amount_inr (Laplace ε=1.0, b=₹100K applied by gateway).
    Z-score is most reliable for amounts well above ₹1L where the noise is proportionally
    smaller. Below ₹1L, heuristic rules are the primary signal.
    """
    stats_path = _BASE / "data" / "models" / "amount_stats.json"
    if stats_path.exists():
        stats = json.loads(stats_path.read_text())
        mean, std = stats["mean"], stats["std"]
        # PaySim stats are in USD-scale (typically mean ≈ $180K mapped to INR).
        # If mean > ₹50K that's likely a PaySim artefact; use UPI fallback instead.
        if mean > 50_000.0:
            mean, std = 16_432.0, 62_188.0
    else:
        # Approximate UPI P2P distribution (RBI Payments Data 2022-23)
        mean, std = 16_432.0, 62_188.0  # INR
    if std == 0:
        return 0.0
    return abs(amount - mean) / std


# ─── Fraud heuristic rule engine ─────────────────────────────────────────────

def apply_fraud_heuristics(
    tx: "SanitizedTx",
    anomaly_score: float,
    distinct_receivers: int,
) -> tuple[float, list[str]]:
    """
    Deterministic rule-based fraud signal layer applied AFTER IsolationForest.
    Operates ONLY on noise-free features:
      • is_first_transfer_between_parties  (boolean — never noised)
      • gps_delta_km                       (haversine scalar — never noised)
      • merchant_category                  (string — never noised)
      • distinct_receivers                 (live counter — never noised)

    The noisy_amount_inr (Laplace ε=1.0, b=₹1,00,000) is NOT used here;
    sub-₹1L amount signals are lost in the noise and handled by z-score and
    IsolationForest only for amounts well above the noise floor.

    Rule sources:
      [R1] RBI Master Circular on Fraud — §6.2 merchant category safe-listing
      [R2] NPCI Advisory 2023-24 — large-GPS first transfers as ATO signal
      [R3] RBI Circular RBI/2022-23/38 — new-recipient review on first transfers
      [R4] PMLA §3 & §12 — fan-out structuring and money-mule circuit detection
    """
    labels: list[str] = []
    cat = (tx.merchant_category or "").lower()
    gps_km = tx.gps_delta_km or 0.0

    # ── Rule 1 [R1]: SAFE_MERCHANT_SHIELD ────────────────────────────────────
    # Established (non-first) transactions at known retail merchants should not
    # be flagged by IsolationForest noise — cap anomaly below FLAG threshold.
    if not tx.is_first_transfer_between_parties and cat in SAFE_MERCHANT_CATEGORIES:
        if anomaly_score > 0.50:
            anomaly_score = 0.50
            labels.append("SAFE_MERCHANT_SHIELD")

    # ── Rule 2 [R2]: LARGE_GPS_FIRST_TRANSFER ────────────────────────────────
    # First-time transfer with intercity/international GPS gap (>500 km) is a
    # strong ATO / money-mule signal — push straight to BLOCK anomaly level.
    if tx.is_first_transfer_between_parties and gps_km > GPS_LARGE_THRESHOLD_KM:
        anomaly_score = max(anomaly_score, 0.75)
        labels.append(f"LARGE_GPS_FIRST_TRANSFER:{gps_km:.0f}km")

    # ── Rule 3 [R3]: FIRST_TRANSFER_UNVERIFIED_RECIPIENT ─────────────────────
    # First-time transfer to a non-retail recipient warrants human review.
    # Raises anomaly to FLAG level only if Rule 2 hasn't already raised it higher.
    # Matches UPI industry practice: PhonePe / Paytm both flag first-time
    # transfers above ₹5K for OTP re-confirmation.
    if (
        tx.is_first_transfer_between_parties
        and cat not in SAFE_MERCHANT_CATEGORIES
        and anomaly_score < 0.75
    ):
        anomaly_score = max(anomaly_score, 0.58)
        labels.append("FIRST_TRANSFER_UNVERIFIED_RECIPIENT")

    # ── Rule 4 [R4]: FAN_OUT_SIGNAL ──────────────────────────────────────────
    # Sender dispatching to ≥4 distinct new recipients in 1 hour matches
    # bulk-transfer structuring and money-mule fan-out patterns (PMLA §3).
    if distinct_receivers >= FAN_OUT_THRESHOLD:
        anomaly_score = max(anomaly_score, 0.60)
        labels.append(f"FAN_OUT_SIGNAL:{distinct_receivers}_receivers_1h")

    return anomaly_score, labels


# ─── Signature helpers (with fallback for mock mode) ─────────────────────────

def verify_gate_sig(tx: SanitizedTx) -> bool:
    if not RUST_CRYPTO_AVAILABLE or not VERIFYING_KEY:
        log.warning("Gate signature verification SKIPPED — mock mode or no key configured")
        return True
    payload = tx.model_dump(exclude={"signature"})
    return vg.verify_payload(json.dumps(payload, sort_keys=True), tx.signature, VERIFYING_KEY)


def sign_verdict(verdict_dict: dict) -> str:
    if not RUST_CRYPTO_AVAILABLE or not SIGNING_KEY:
        return "mock-sig-agent01"
    return vg.sign_payload(json.dumps(verdict_dict, sort_keys=True), SIGNING_KEY)


# ─── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Varaksha Agent 01 — Transaction Profiler",
    description=(
        "IsolationForest anomaly scorer. Receives pseudonymized SanitizedTx "
        "from the Rust gateway. No PII accepted or stored."
    ),
    version="0.1.0",
)


@app.post("/v1/profile", response_model=AgentVerdict)
async def profile_transaction(tx: SanitizedTx) -> AgentVerdict:
    t0 = time.perf_counter()

    # 1. Verify gateway signature ────────────────────────────────────────────
    if not verify_gate_sig(tx):
        log.warning("tx_id=%s gate signature invalid — reject", tx.tx_id)
        raise HTTPException(status_code=400, detail="gate_sig_invalid")

    # 2. Velocity ─────────────────────────────────────────────────────────────
    velocity = velocity_tracker.increment(tx.pseudo_sender)

    # 2b. Receiver diversity (fan-out detection) ──────────────────────────────
    distinct_receivers = receiver_diversity_tracker.record(
        tx.pseudo_sender, tx.pseudo_receiver
    )

    # 3. IsolationForest anomaly score ─────────────────────────────────────────
    features = extract_features(tx, velocity)
    model = get_model()
    # IsolationForest.decision_function: more negative = more anomalous
    raw_score: float = float(model.decision_function(features)[0])
    # Normalise to [0, 1] where 1 = most anomalous
    # Typical range is [-0.5, 0.5]; clamp and invert
    raw_anomaly_score = float(np.clip(-raw_score + 0.5, 0.0, 1.0))

    # 3b. Fraud heuristics (noise-free feature rules) ─────────────────────────
    anomaly_score, heuristic_labels = apply_fraud_heuristics(
        tx, raw_anomaly_score, distinct_receivers
    )

    # 4. Z-score ───────────────────────────────────────────────────────────────
    zscore = compute_zscore(tx.noisy_amount_inr)

    # 5. Aggregate risk (weights match TEAM_RUST_BRIEF.md spec) ───────────────
    # Agent 01 contributes the anomaly + velocity + diversity components.
    # The full multi-agent weighted formula runs in Agent 03.
    velocity_norm       = min(velocity / 100.0, 1.0)
    diversity_norm      = min(distinct_receivers / FAN_OUT_THRESHOLD, 1.0)
    aggregate = float(
        0.45 * anomaly_score            # post-heuristic anomaly (primary signal)
        + 0.25 * velocity_norm          # temporal volume
        + 0.15 * min(zscore / 5.0, 1.0) # amount distribution outlier
        + 0.15 * diversity_norm         # fan-out / receiver spread
    )
    aggregate = round(float(np.clip(aggregate, 0.0, 1.0)), 4)

    # 6. Preliminary verdict ───────────────────────────────────────────────────
    if (
        anomaly_score >= ANOMALY_BLOCK_THRESHOLD
        or velocity >= VELOCITY_BLOCK_THRESHOLD
        or zscore >= ZSCORE_BLOCK_THRESHOLD
    ):
        verdict = "BLOCK"
    elif anomaly_score >= ANOMALY_FLAG_THRESHOLD:
        verdict = "FLAG"
    else:
        verdict = "ALLOW"

    if heuristic_labels:
        log.info(
            "tx_id=%s heuristics=%s IF_raw=%.3f anomaly=%.3f",
            tx.tx_id, heuristic_labels, raw_anomaly_score, anomaly_score,
        )
    log.info(
        "tx_id=%s anomaly=%.3f velocity=%d distinct_recv=%d zscore=%.2f agg=%.3f verdict=%s",
        tx.tx_id, anomaly_score, velocity, distinct_receivers, zscore, aggregate, verdict,
    )

    # 7. Build and sign the outgoing verdict ───────────────────────────────────
    fp = SIGNING_KEY[:32] if SIGNING_KEY else "agent01-mock-fp"
    verdict_dict = {
        "tx_id":           tx.tx_id,
        "anomaly_score":   anomaly_score,
        "velocity_score":  velocity,
        "zscore":          zscore,
        "aggregate_score": aggregate,
        "verdict":         verdict,
        "narrative":       " | ".join(heuristic_labels) if heuristic_labels else "",
        "gate_a_sig":      "",     # filled below
        "key_fingerprint": fp,
        "latency_ms":      0.0,    # filled below
    }
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    verdict_dict["latency_ms"] = latency_ms
    verdict_dict["gate_a_sig"] = sign_verdict(verdict_dict)

    return AgentVerdict(**verdict_dict)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "agent": "profiler", "model_loaded": _model is not None}

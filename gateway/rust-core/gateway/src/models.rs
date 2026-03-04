/// models.rs — all shared request/response types for the Varaksha gateway.
///
/// FIELD NAMING: field names here match JSON keys expected by Python agents
/// (agent01_profiler.py, pipeline.py) and the Streamlit demo (demo/app.py).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── INBOUND: raw UPI transaction (contains real PII) ────────────────────────
/// This struct is NEVER forwarded to any agent.
/// The privacy gate consumes every field and emits `SanitizedTx`.
#[derive(Debug, Deserialize)]
pub struct RawTransaction {
    /// Real UPI handle — pseudonymized before leaving this struct
    pub sender_upi_id:   String,
    pub receiver_upi_id: String,
    /// Amount in INR — Laplace DP noise will be applied
    pub amount_inr:      f64,
    pub merchant_category: Option<String>,
    pub upi_network:     Option<String>,
    pub is_first_transfer: Option<bool>,
    /// Raw GPS — DROPPED after computing great-circle delta
    pub sender_lat:   Option<f64>,
    pub sender_lon:   Option<f64>,
    pub receiver_lat: Option<f64>,
    pub receiver_lon: Option<f64>,
    pub timestamp:    Option<DateTime<Utc>>,
}

// ─── OUTBOUND: sanitized payload forwarded to Agent 01 ───────────────────────
/// All PII has been removed. Safe to send to the Python agent layer.
/// Signed with Ed25519 so agents can verify this came from the gateway.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SanitizedTx {
    pub tx_id: String,
    /// HMAC-SHA256(sender_upi_id, session_key) → 64-char hex
    pub pseudo_sender:   String,
    /// HMAC-SHA256(receiver_upi_id, session_key) → 64-char hex
    pub pseudo_receiver: String,
    /// One-way hash of client IP (not reversible)
    pub ip_hash: String,
    /// Amount with Laplace DP noise applied (ε=1.0)
    pub noisy_amount_inr: f64,
    /// Great-circle distance between sender/receiver GPS in km.
    /// Raw coordinates are dropped; only this scalar is forwarded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gps_delta_km: Option<f64>,
    pub timestamp: DateTime<Utc>,
    pub upi_network: Option<String>,
    pub merchant_category: Option<String>,
    pub is_first_transfer_between_parties: bool,
    pub key_fingerprint: String,
    pub signature: String,
}

// ─── GATE VERDICT ─────────────────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[allow(dead_code)] // reserved for typed verdict promotion in future agent stages
pub enum GateVerdict {
    Allow,
    Block,
    Flag,
}

impl std::fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Block => write!(f, "BLOCK"),
            Self::Flag  => write!(f, "FLAG"),
        }
    }
}

// ─── AGENT VERDICT (from Agent 01 / pipeline back to gateway) ────────────────
/// Accepted from any agent stage.
/// Agent 01 sends `aggregate_score`; Agent 03 / pipeline sends `final_score`.
/// Both are aliased to `final_score` so a single struct covers the pipeline.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentVerdict {
    pub tx_id: String,
    /// Agent 01 emits `aggregate_score`; Agent 03 emits `final_score`.
    #[serde(default, alias = "aggregate_score")]
    pub final_score: f64,
    /// Some stages also emit `anomaly_score` — captured for logging.
    #[serde(default)]
    pub anomaly_score: f64,
    pub verdict: String,  // "ALLOW" | "FLAG" | "BLOCK"
    #[serde(default)]
    pub narrative: String,
    #[serde(default)]
    pub law_refs: Vec<serde_json::Value>,
    /// Ed25519 sig from Agent 03 (absent on early-stage responses).
    #[serde(default)]
    pub gate_final_sig: String,
    #[serde(default)]
    pub key_fingerprint: String,
    #[serde(default)]
    pub latency_ms: f64,
    #[serde(default)]
    pub gate_a_sig: String,
    #[serde(default)]
    pub risk_score: f64,
}

// ─── API RESPONSE (gateway → client) ─────────────────────────────────────────
#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub tx_id:            String,
    pub verdict:          String,
    pub risk_score:       f64,
    pub narrative:        String,
    pub gate_fingerprint: String,
    pub processed_at:     DateTime<Utc>,
}

// ─── ERROR RESPONSE ───────────────────────────────────────────────────────────
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error:   String,
    pub message: String,
    pub tx_id:   String,
}

// ─── INTERNAL ERRORS ─────────────────────────────────────────────────────────
#[derive(Debug, Error)]
#[allow(dead_code)] // SigningError / SerializationError reserved for future agent paths
pub enum VarakshError {
    #[error("agent pipeline error: {0}")]
    AgentError(String),
    #[error("Ed25519 signing error: {0}")]
    SigningError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
}

// // gateway/src/models.rs
// // ─────────────────────────────────────────────────────────────────────────────
// // JSON payload definitions for the Varaksha V2 gateway.
// //
// // Two endpoints are served:
// //   POST /v1/tx                  — real-time transaction risk check
// //   POST /v1/webhook/update_cache — async signal from the Python graph layer
// //
// // Your job [teammate]: these structs are complete.  You should NOT need to
// // change this file.  Just use them in main.rs handlers and cache.rs logic.
// // ─────────────────────────────────────────────────────────────────────────────

// use serde::{Deserialize, Serialize};

// // ── Inbound: transaction risk check ─────────────────────────────────────────

// /// Payload sent by the UPI payment client for a real-time risk check.
// /// The `vpa` field is a raw VPA string (e.g. "alice@okaxis").
// /// The gateway will hash it before looking up the DashMap — we never store
// /// raw VPAs in memory.
// #[derive(Debug, Deserialize)]
// pub struct TxRequest {
//     /// Raw Virtual Payment Address.  Will be SHA-256 hashed before cache lookup.
//     pub vpa: String,

//     /// Transaction amount in INR paise (integer, avoids float precision issues).
//     pub amount_paise: u64,

//     /// Merchant category code (ISO 18245).
//     pub merchant_category: String,

//     /// Opaque device fingerprint string (hashed on the client side ideally).
//     pub device_id: String,

//     /// ISO-8601 timestamp string from the initiating client.
//     pub initiated_at: String,
// }

// /// Gateway verdict returned to the caller.
// #[derive(Debug, Serialize)]
// pub struct TxResponse {
//     /// SHA-256 hex digest of the VPA.  Never echoes the raw VPA back.
//     pub vpa_hash: String,

//     /// One of: "ALLOW" | "FLAG" | "BLOCK"
//     ///
//     /// - ALLOW  → risk_score < 0.4, proceed normally.
//     /// - FLAG   → 0.4 ≤ risk_score < 0.75, trigger biometric step-up auth.
//     /// - BLOCK  → risk_score ≥ 0.75, halt transaction immediately.
//     pub verdict: Verdict,

//     /// Consortium risk score in [0.0, 1.0].  Populated from the DashMap entry
//     /// if present, otherwise defaults to 0.0 (unknown = cautious ALLOW).
//     pub risk_score: f32,

//     /// Unique request trace ID for log correlation.
//     pub trace_id: String,

//     /// Processing latency in microseconds (target: < 5 000 µs = 5 ms).
//     pub latency_us: u64,
// }

// /// Verdict enum — serialises to a plain string for JSON.
// #[derive(Debug, Serialize, PartialEq)]
// #[serde(rename_all = "UPPERCASE")]
// pub enum Verdict {
//     Allow,
//     Flag,
//     Block,
// }

// // ── Inbound: async cache update from the Python graph layer ──────────────────

// /// Payload pushed by `services/graph/graph_agent.py` after every graph sweep.
// /// The Python layer hashes VPAs itself before posting here so the Rust process
// /// never sees raw PII.
// ///
// /// TODO [teammate]: verify the HMAC-SHA256 `x-varaksha-sig` request header
// /// against a shared secret (read from $VARAKSHA_WEBHOOK_SECRET env var) before
// /// applying the update.
// #[derive(Debug, Deserialize)]
// pub struct CacheUpdateRequest {
//     /// Pre-computed SHA-256 hex digest of the VPA.
//     pub vpa_hash: String,

//     /// New consortium risk score in [0.0, 1.0].
//     pub risk_score: f32,

//     /// Human-readable reason code for audit logs.
//     /// e.g. "GRAPH:FAN_OUT", "GRAPH:CYCLE", "ML:HIGH_ANOMALY"
//     pub reason: String,

//     /// TTL for this cache entry in seconds.
//     /// After expiry, the entry should be evicted and fall back to 0.0.
//     /// TODO [teammate]: implement TTL eviction (DashMap does not do it
//     /// natively — use a background tokio task or `moka` crate).
//     pub ttl_seconds: u64,
// }

// /// Response for a successful cache update.
// #[derive(Debug, Serialize)]
// pub struct CacheUpdateResponse {
//     pub ok: bool,
//     pub vpa_hash: String,
//     pub trace_id: String,
// }
// gateway/src/models.rs

use serde::{Deserialize, Serialize};

/// Payload sent by the UPI payment client for a real-time risk check.
///
/// # DPDP Act 2023 — Data Fiduciary obligations
///
/// `vpa` and `device_id` are **personal data** under DPDP Act 2023 §2(t) because
/// they are about an identifiable individual.  Before this struct is populated
/// in production, the calling PSP MUST have:
///
///   1. Provided the notice required by §5 and DPDP Rules 2025 Rule 3 in the
///      language the Data Principal specified (or English) before, or at the time
///      of, first collection of their VPA.
///
///   2. Obtained free, specific, informed, unconditional and unambiguous consent
///      under §6; the `consent_token` field MUST carry the Consent Artefact ID
///      issued by a DPDP-compliant Consent Manager (Rule 4 / AA framework).
///
///   3. Limited the purpose to fraud prevention (§7(e)) or the specific purpose
///      stated in the consent notice — purpose limitation applies under §6(3).
///
/// **PRODUCTION TODO**: The `check_tx` handler MUST:
///   a. Reject the request with HTTP 422 if `consent_token` is absent or empty.
///   b. Call the Consent Manager SDk to verify the token is valid, unexpired, and
///      covers the "fraud-risk-check" purpose before hashing or processing `vpa`.
///   c. Log the consent artefact ID alongside the trace_id for audit purposes.
///
/// Failure to do so constitutes unlawful processing under §4(1) and may attract
/// a penalty of up to ₹250 crore under Schedule 1 of the Act.
#[derive(Debug, Deserialize)]
pub struct TxRequest {
    /// Raw Virtual Payment Address — SHA-256 hashed at ingress; never stored.
    /// Phone-number VPAs (e.g. "9876543210@ybl") are personal data per §2(t).
    pub vpa: String,

    /// Transaction amount in INR paise (integer avoids float precision issues).
    pub amount_paise: u64,

    /// Merchant category code (ISO 18245).
    pub merchant_category: String,

    /// Device fingerprint.  MUST be pre-hashed client-side before transmission
    /// so the raw fingerprint never traverses the network.  A raw device ID is
    /// personal data per §2(t) and collecting it without hashing constitutes
    /// processing of personal data at the network layer without minimisation.
    pub device_id: String,

    /// ISO-8601 timestamp from the initiating client.
    pub initiated_at: String,

    /// Consent Artefact ID issued by the PSP's DPDP-compliant Consent Manager.
    ///
    /// REQUIRED in production (§4(1), §6, DPDP Rules 2025 Rule 4).
    /// The gateway handler MUST validate this token before processing `vpa`.
    /// `None` is accepted in this struct for backward-compat during development
    /// ONLY — the handler enforces presence at the application level.
    pub consent_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TxResponse {
    pub vpa_hash: String,
    pub verdict: Verdict,
    pub risk_score: f32,
    pub trace_id: String,
    pub latency_us: u64,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Allow,
    Flag,
    Block,
}

#[derive(Debug, Deserialize)]
pub struct CacheUpdateRequest {
    pub vpa_hash: String,
    pub risk_score: f32,
    pub reason: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct CacheUpdateResponse {
    pub ok: bool,
    pub vpa_hash: String,
    pub trace_id: String,
}
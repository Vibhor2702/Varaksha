// varaksha-core/gateway/src/lib.rs
// PyO3 bindings — exposes Varaksha Rust crypto to Python agents WITHOUT a network hop.
//
// Usage from Python:
//   import varaksha_gateway as vg
//   pseudo = vg.pseudonymize("user@bank", session_key_hex)
//   sig    = vg.sign_payload(json_str, signing_key_hex)
//   ok     = vg.verify_payload(json_str, sig_hex, verifying_key_hex)
//
// All functions receive/return plain strings to avoid PyO3 type complexity.
// Keys are hex-encoded bytes.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

#[allow(dead_code)] mod gate;
#[allow(dead_code)] mod models;
#[allow(dead_code)] mod privacy;
#[allow(dead_code)] mod rate_limit;

// ─── pseudonymize ─────────────────────────────────────────────────────────────

/// Return HMAC-SHA256 hex of `real_id` using `session_key_hex` (64-char hex = 32 bytes).
///
/// Args:
///     real_id (str): The raw PII identifier (UPI ID, phone number, etc.)
///     session_key_hex (str): 64-character hex string — current session key.
///
/// Returns:
///     str: 64-character lowercase hex string (pseudonym).
///
/// Raises:
///     ValueError: if `session_key_hex` is not exactly 64 hex chars.
#[pyfunction]
fn pseudonymize_py(real_id: &str, session_key_hex: &str) -> PyResult<String> {
    let key_bytes = hex::decode(session_key_hex)
        .map_err(|e| PyValueError::new_err(format!("invalid session_key_hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "session_key_hex must decode to 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(privacy::pseudonymize(real_id, &key))
}

// ─── hash_ip ─────────────────────────────────────────────────────────────────

/// One-way hash of an IP address for forensic correlation (no reverse possible).
///
/// Args:
///     ip (str): IPv4 or IPv6 address as string.
///     static_salt (str): A deployment-fixed salt (from env var).
///
/// Returns:
///     str: 16-character hex string.
#[pyfunction]
fn hash_ip_py(ip: &str, static_salt: &str) -> String {
    privacy::hash_ip(ip, static_salt.as_bytes())
}

// ─── add_laplace_noise ────────────────────────────────────────────────────────

/// Apply Laplace differential-privacy noise to a monetary amount.
///
/// Args:
///     amount_inr (float): Original transaction amount in INR.
///
/// Returns:
///     float: Noisy amount (always >= 0.0).  ε=1.0, sensitivity=₹1,00,000.
#[pyfunction]
fn add_laplace_noise_py(amount_inr: f64) -> f64 {
    privacy::add_laplace_noise(amount_inr)
}

// ─── compute_gps_delta ────────────────────────────────────────────────────────

/// Great-circle distance between two GPS coordinates in kilometres.
/// Raw coordinates are NOT stored; only this delta reaches agents.
///
/// Args:
///     sender_lat, sender_lon, receiver_lat, receiver_lon (float): degrees
///
/// Returns:
///     float: Distance in km.
#[pyfunction]
fn compute_gps_delta_py(
    sender_lat: f64,
    sender_lon: f64,
    receiver_lat: f64,
    receiver_lon: f64,
) -> f64 {
    privacy::compute_gps_delta(sender_lat, sender_lon, Some(receiver_lat), Some(receiver_lon))
}

// ─── Ed25519 key generation ───────────────────────────────────────────────────

/// Generate a fresh Ed25519 key pair.
///
/// Returns:
///     tuple[str, str]: (signing_key_hex, verifying_key_hex) — each 64 hex chars (32 bytes).
#[pyfunction]
fn generate_key_pair_py() -> (String, String) {
    let kp = gate::GateKeyPair::generate();
    let signing_bytes = kp.signing_key_bytes();
    let verifying_bytes = kp.verifying_key_bytes();
    (hex::encode(signing_bytes), hex::encode(verifying_bytes))
}

// ─── sign ─────────────────────────────────────────────────────────────────────

/// Sign a JSON payload with an Ed25519 signing key.
///
/// Args:
///     payload_json (str): Canonical JSON string of the object to sign.
///     signing_key_hex (str): 64-char hex (32-byte Ed25519 signing key).
///
/// Returns:
///     str: 128-char hex signature.
///
/// Raises:
///     ValueError: on invalid key length or malformed JSON.
#[pyfunction]
fn sign_payload_py(payload_json: &str, signing_key_hex: &str) -> PyResult<String> {
    let key_bytes = hex::decode(signing_key_hex)
        .map_err(|e| PyValueError::new_err(format!("invalid signing_key_hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(PyValueError::new_err("signing_key_hex must be 64 hex chars"));
    }
    let kp = gate::GateKeyPair::from_signing_bytes(&key_bytes)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    // parse raw JSON so sign() can re-canonicalize
    let val: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;

    kp.sign(&val)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

// ─── verify ───────────────────────────────────────────────────────────────────

/// Verify an Ed25519 signature over a JSON payload.
///
/// Args:
///     payload_json (str): Exact same JSON string that was signed.
///     sig_hex (str): 128-char hex signature.
///     verifying_key_hex (str): 64-char hex (32-byte Ed25519 verifying key).
///
/// Returns:
///     bool: True if signature is valid, False otherwise.
#[pyfunction]
fn verify_payload_py(payload_json: &str, sig_hex: &str, verifying_key_hex: &str) -> bool {
    let key_bytes = match hex::decode(verifying_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let kp = match gate::GateKeyPair::from_verifying_bytes(&key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let val: serde_json::Value = match serde_json::from_str(payload_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    kp.verify(&val, sig_hex).is_ok()
}

// ─── fingerprint ─────────────────────────────────────────────────────────────

/// Return the first 16 bytes (32 hex chars) of a verifying key — used as a gate tag
/// in agent log entries.
///
/// Args:
///     verifying_key_hex (str): 64-char hex verifying key.
///
/// Returns:
///     str: 32-char hex fingerprint.
///
/// Raises:
///     ValueError: on invalid key.
#[pyfunction]
fn key_fingerprint_py(verifying_key_hex: &str) -> PyResult<String> {
    let bytes = hex::decode(verifying_key_hex)
        .map_err(|e| PyValueError::new_err(format!("invalid key: {e}")))?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err("verifying_key_hex must be 64 hex chars"));
    }
    Ok(hex::encode(&bytes[..16]))
}

// ─── module registration ──────────────────────────────────────────────────────

/// Varaksha Gateway — Rust crypto primitives exposed to Python.
///
/// Install via `maturin develop` from the varaksha-core/ directory.
/// The resulting wheel name is `varaksha_gateway`.
#[pymodule]
fn varaksha_gateway(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pseudonymize_py, m)?)?;
    m.add_function(wrap_pyfunction!(hash_ip_py, m)?)?;
    m.add_function(wrap_pyfunction!(add_laplace_noise_py, m)?)?;
    m.add_function(wrap_pyfunction!(compute_gps_delta_py, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_pair_py, m)?)?;
    m.add_function(wrap_pyfunction!(sign_payload_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_payload_py, m)?)?;
    m.add_function(wrap_pyfunction!(key_fingerprint_py, m)?)?;
    Ok(())
}

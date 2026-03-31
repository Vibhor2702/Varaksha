//! Centralised authentication helpers.
//!
//! Two strategies are used depending on the endpoint's security requirements:
//!
//! 1. **HMAC-SHA256 body signing** (`verify_hmac`) — write endpoints where payload
//!    integrity matters: `/graph_update`, `/update_cache`, `/policy/reload`.
//!    Header: `X-Varaksha-Signature: sha256=<hex_digest>`
//!
//! 2. **API key bearer** (`verify_api_key`) — read/inference endpoints where
//!    caller identity matters but body doesn't need signing: `/inference`,
//!    `/metrics`, `/erasure/{hash}`.
//!    Header: `X-Varaksha-Api-Key: <key>`
//!
//! All comparisons use a constant-time XOR-fold to prevent timing attacks.

use actix_web::HttpRequest;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Constant-time byte-string equality via XOR-fold.
/// Returns true only when both slices are identical in length and content.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mismatch: u8 = a
        .bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    mismatch == 0
}

/// Verify an HMAC-SHA256 body signature.
///
/// Expected header: `X-Varaksha-Signature: sha256=<lowercase_hex>`
/// Returns `true` only when the header is present and the MAC matches.
pub fn verify_hmac(secret: &str, body: &[u8], req: &HttpRequest) -> bool {
    let header_val = match req.headers().get("X-Varaksha-Signature") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return false,
        },
        None => return false,
    };

    let provided_hex = match header_val.strip_prefix("sha256=") {
        Some(h) => h.to_string(),
        None => return false,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    let computed = hex::encode(mac.finalize().into_bytes());

    constant_time_eq(&computed, &provided_hex)
}

/// Verify an API key bearer token.
///
/// Expected header: `X-Varaksha-Api-Key: <key>`
/// Returns `true` only when the header is present and the key matches.
pub fn verify_api_key(expected: &str, req: &HttpRequest) -> bool {
    let provided = match req.headers().get("X-Varaksha-Api-Key") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return false,
        },
        None => return false,
    };

    constant_time_eq(expected, &provided)
}

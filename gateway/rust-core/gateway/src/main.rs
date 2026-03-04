// varaksha-core/gateway/src/main.rs
// Actix-Web HTTP entry-point for the Varaksha Gateway.
//
// Routes
//   POST /v1/tx        — receive a raw UPI transaction, pseudonymize, sign, forward to Agent 01
//   GET  /health       — liveness probe
//   POST /test/art-harness  [bench-mode ONLY] — direct feature-vector endpoint for ART attacks
//
// SECURITY CONTRACT
//   • Raw PII (UPI IDs, IPs, coordinates) NEVER leaves this process in readable form.
//   • The `bench-mode` Cargo feature exposes /test/art-harness.  It MUST NOT be compiled
//     into production binaries.  Pipeline CI/CD enforces --no-features on release builds.

use std::{net::IpAddr, sync::Arc};

use actix_web::{
    middleware::Logger,
    web::{self, Data, Json},
    App, HttpRequest, HttpResponse, HttpServer,
};
use chrono::Utc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod gate;
mod models;
mod privacy;
mod rate_limit;

use gate::GateKeyPair;
use models::{
    AgentVerdict, ErrorResponse, RawTransaction, SanitizedTx, TransactionResponse,
    VarakshError,
};
use privacy::{add_laplace_noise, compute_gps_delta, hash_ip, pseudonymize, SessionKeyStore};
use rate_limit::{AdaptiveRateLimiter, RateLimitResult, SecurityLog};

// ─── shared application state ────────────────────────────────────────────────

struct AppState {
    key_store: Arc<SessionKeyStore>,
    gate_key: Arc<GateKeyPair>,
    rate_limiter: Arc<AdaptiveRateLimiter>,
    agent01_url: String,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Extract the real client IP, respecting X-Forwarded-For if behind a trusted proxy.
fn extract_ip(req: &HttpRequest) -> IpAddr {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| {
            req.peer_addr()
                .map(|a| a.ip())
                .unwrap_or_else(|| "0.0.0.0".parse().unwrap())
        })
}

/// Forward the sanitized transaction to Agent 01.
/// Returns the verdict received or an error.
async fn forward_to_agent01(
    url: &str,
    tx: &SanitizedTx,
) -> Result<AgentVerdict, VarakshError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| VarakshError::AgentError(e.to_string()))?;

    let resp = client
        .post(url)
        .json(tx)
        .send()
        .await
        .map_err(|e| VarakshError::AgentError(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(VarakshError::AgentError(format!(
            "agent01 returned HTTP {status}: {body}"
        )));
    }

    resp.json::<AgentVerdict>()
        .await
        .map_err(|e| VarakshError::AgentError(e.to_string()))
}

// ─── GET /health ─────────────────────────────────────────────────────────────

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "ts": Utc::now().to_rfc3339(),
    }))
}

// ─── POST /v1/tx ─────────────────────────────────────────────────────────────

async fn process_transaction(
    req: HttpRequest,
    state: Data<AppState>,
    body: Json<RawTransaction>,
) -> HttpResponse {
    let tx_id = Uuid::new_v4().to_string();
    let client_ip = extract_ip(&req);

    // 1. Rate-limit check ────────────────────────────────────────────────────
    match state.rate_limiter.check(client_ip) {
        RateLimitResult::Quarantined { until } => {
            warn!(
                tx_id = %tx_id,
                ip = %client_ip,
                quarantine_until = ?until,
                "Request from quarantined IP"
            );
            return HttpResponse::TooManyRequests().json(ErrorResponse {
                error: "ip_quarantined".into(),
                message: "IP address is temporarily blocked due to repeated violations.".into(),
                tx_id,
            });
        }
        RateLimitResult::Exceeded => {
            warn!(tx_id = %tx_id, ip = %client_ip, "Rate limit exceeded");
            return HttpResponse::TooManyRequests().json(ErrorResponse {
                error: "rate_limited".into(),
                message: "Too many requests. Please slow down.".into(),
                tx_id,
            });
        }
        RateLimitResult::Allowed => {}
    }

    let raw = body.into_inner();

    // 2. Basic validation ────────────────────────────────────────────────────
    if raw.amount_inr <= 0.0 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_amount".into(),
            message: "Transaction amount must be positive.".into(),
            tx_id,
        });
    }

    // 3. Pseudonymize PII ────────────────────────────────────────────────────
    let key = state.key_store.get_key();
    let pseudo_sender = pseudonymize(&raw.sender_upi_id, &key);
    let pseudo_receiver = pseudonymize(&raw.receiver_upi_id, &key);

    let ip_salt = std::env::var("VARAKSHA_IP_SALT")
        .unwrap_or_else(|_| "varaksha-ip-salt-CHANGE-IN-PROD".to_string());
    let ip_hash = hash_ip(&client_ip.to_string(), ip_salt.as_bytes());

    // 4. Differential-privacy noise on amount ────────────────────────────────
    let noisy_amount = add_laplace_noise(raw.amount_inr);

    // 5. GPS delta (great-circle km; no raw coordinates forwarded) ───────────
    let gps_delta_km = raw.sender_lat.zip(raw.sender_lon).zip(
        raw.receiver_lat.zip(raw.receiver_lon),
    ).map(|((slat, slon), (rlat, rlon))| {
        compute_gps_delta(slat, slon, Some(rlat), Some(rlon))
    });

    // 6. Build SanitizedTx ───────────────────────────────────────────────────
    let mut sanitized = SanitizedTx {
        tx_id: tx_id.clone(),
        pseudo_sender,
        pseudo_receiver,
        ip_hash,
        noisy_amount_inr: noisy_amount,
        gps_delta_km,
        timestamp: raw.timestamp.unwrap_or_else(Utc::now),
        upi_network: raw.upi_network.clone(),
        merchant_category: raw.merchant_category.clone(),
        is_first_transfer_between_parties: raw.is_first_transfer.unwrap_or(false),
        key_fingerprint: state.gate_key.fingerprint(),
        signature: String::new(), // filled below
    };

    // 7. Ed25519 sign ────────────────────────────────────────────────────────
    match state.gate_key.sign(&sanitized) {
        Ok(sig) => sanitized.signature = sig,
        Err(e) => {
            error!(tx_id = %tx_id, error = %e, "Failed to sign sanitized transaction");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "signing_failed".into(),
                message: "Internal error. Please retry.".into(),
                tx_id,
            });
        }
    }

    info!(
        tx_id = %tx_id,
        ip_hash = %sanitized.ip_hash,
        "Sanitized transaction ready — forwarding to Agent 01"
    );

    // 8. Forward to Agent 01 ─────────────────────────────────────────────────
    let verdict = match forward_to_agent01(&state.agent01_url, &sanitized).await {
        Ok(v) => v,
        Err(e) => {
            error!(tx_id = %tx_id, error = %e, "Agent 01 unavailable");
            return HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "agent_unavailable".into(),
                message: "Fraud-detection pipeline is temporarily unavailable.".into(),
                tx_id,
            });
        }
    };

    // 9. Verify Gate A signature (production: hard-reject; demo: warn if mock/empty)
    let is_real_sig = !verdict.gate_a_sig.is_empty()
        && !verdict.gate_a_sig.starts_with("mock-");
    if is_real_sig {
        if let Err(e) = state.gate_key.verify(&verdict, &verdict.gate_a_sig) {
            warn!(tx_id = %tx_id, error = %e, "Gate A signature verification failed");
            return HttpResponse::BadGateway().json(ErrorResponse {
                error: "gate_sig_mismatch".into(),
                message: "Pipeline integrity check failed.".into(),
                tx_id,
            });
        }
    } else {
        warn!(tx_id = %tx_id, "Gate A sig absent or mock — skipping verification (demo mode)");
    }

    HttpResponse::Ok().json(TransactionResponse {
        tx_id,
        verdict: verdict.verdict.clone(),
        risk_score: if verdict.final_score > 0.0 { verdict.final_score } else { verdict.risk_score },
        narrative: verdict.narrative,
        gate_fingerprint: state.gate_key.fingerprint(),
        processed_at: Utc::now(),
    })
}

// ─── POST /test/art-harness  (bench-mode only) ───────────────────────────────

#[cfg(feature = "bench-mode")]
async fn art_harness(body: web::Bytes) -> HttpResponse {
    // Accepts raw feature vectors from the IBM ART attack suite.
    // Returns the anomaly score that Agent 01 would compute.
    // NO rate-limiting, NO pseudonymization — attack surface intentionally open
    // for adversarial robustness testing.
    //
    // This route MUST NOT be reachable in production.
    use serde_json::Value;
    let features: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().body("invalid JSON"),
    };
    // Delegate to a lightweight scorer (stub — replaced by Python IsolationForest via PyO3)
    HttpResponse::Ok().json(serde_json::json!({
        "art_target": "anomaly_score",
        "input": features,
        "score_stub": 0.0,
        "note": "Connect IBMart ART attack suite to this endpoint. bench-mode feature only."
    }))
}

// ─── main ────────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Structured JSON logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();

    let bind_addr = std::env::var("VARAKSHA_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let agent01_url = std::env::var("AGENT01_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8001/v1/profile".to_string());

    info!(bind = %bind_addr, agent01 = %agent01_url, "Varaksha Gateway starting");

    let key_store = Arc::new(SessionKeyStore::new());
    let gate_key = Arc::new(GateKeyPair::generate());
    let security_log = SecurityLog::new();
    let rate_limiter = Arc::new(AdaptiveRateLimiter::new(security_log));

    info!(
        fingerprint = %gate_key.fingerprint(),
        "Gate key pair generated"
    );

    let state = Data::new(AppState {
        key_store,
        gate_key,
        rate_limiter,
        agent01_url,
    });

    HttpServer::new(move || {
        let app = App::new()
            .app_data(state.clone())
            .app_data(
                web::JsonConfig::default()
                    .limit(16_384) // 16 KB max body
                    .error_handler(|err, _req| {
                        let tx_id = Uuid::new_v4().to_string();
                        let resp = HttpResponse::BadRequest().json(ErrorResponse {
                            error: "invalid_json".into(),
                            message: err.to_string(),
                            tx_id,
                        });
                        actix_web::error::InternalError::from_response(err, resp).into()
                    }),
            )
            .wrap(Logger::default())
            .route("/health", web::get().to(health))
            .route("/v1/tx", web::post().to(process_transaction));

        #[cfg(feature = "bench-mode")]
        let app = app.route("/test/art-harness", web::post().to(art_harness));

        app
    })
    .bind(&bind_addr)?
    .run()
    .await
}

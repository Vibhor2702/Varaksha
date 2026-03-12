mod models;
mod consent;

use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};

use models::{CacheUpdateRequest, CacheUpdateResponse, TxRequest, TxResponse, Verdict};
use consent::ConsentManagerClient;

use risk_cache::RiskCache;

use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use uuid::Uuid;

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

struct AppState {
    cache:           RiskCache,
    consent_manager: ConsentManagerClient,
    /// Per VPA-hash request counter for NPCI OC-215/2025-26 rate cap.
    /// Value is (requests_in_window, window_start).
    rate_limiter:    DashMap<String, (u32, Instant)>,
}

/// Normalise a VPA to a canonical form before hashing so that a full
/// phone-number VPA and its already-masked counterpart produce the same
/// hash in the consortium cache.
///
/// Rule (mirrors NPCI display convention):
///   - handle is 10+ consecutive digits  →  mask to  XX****XX@bank
///   - handle already matches XX****XX    →  kept as-is  (already canonical)
///   - name-based handle                  →  kept as-is
///
/// Examples
///   9876543210@ybl   →  98****10@ybl  (full phone → canonical)
///   98****10@ybl     →  98****10@ybl  (already canonical → unchanged)
///   ravi.kumar@axis  →  ravi.kumar@axis
fn normalise_vpa(vpa: &str) -> String {
    if let Some(at) = vpa.find('@') {
        let handle = &vpa[..at];
        let bank   = &vpa[at + 1..];
        // Full phone number (10+ digits)
        if handle.len() >= 10 && handle.chars().all(|c| c.is_ascii_digit()) {
            let h = handle;
            return format!("{}****{}@{}", &h[..2], &h[h.len()-2..], bank);
        }
        // Already-masked phone (e.g. "98****10") — treat as canonical
        if handle.len() == 8
            && handle[..2].chars().all(|c| c.is_ascii_digit())
            && &handle[2..6] == "****"
            && handle[6..].chars().all(|c| c.is_ascii_digit())
        {
            return vpa.to_string();
        }
    }
    vpa.to_string()
}

fn hash_vpa(vpa: &str) -> String {

    let canonical = normalise_vpa(vpa);

    let mut hasher = Sha256::new();

    hasher.update(canonical.as_bytes());

    hex::encode(hasher.finalize())
}

fn score_to_verdict(score: f32) -> Verdict {

    if score >= 0.75 {
        Verdict::Block
    } else if score >= 0.40 {
        Verdict::Flag
    } else {
        Verdict::Allow
    }
}

#[get("/health")]
async fn health(data: web::Data<Arc<AppState>>) -> impl Responder {

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "cache_entries": data.cache.len(),
        "version": "2.0.0"
    }))
}

#[post("/v1/tx")]
async fn check_tx(
    data: web::Data<Arc<AppState>>,
    body: web::Json<TxRequest>,
) -> impl Responder {

    let started = Instant::now();

    let trace_id = Uuid::new_v4().to_string();

    let tx = body.into_inner();

    // ── DPDP Act 2023 — Lawful Processing Gate ──────────────────────────────────
    // Dual legal basis (belt-and-braces):
    //   §7(g)  — PRIMARY: "legitimate use" for ensuring safety and security /
    //            preventing or detecting fraud.  No explicit consent is required
    //            when a PSP invokes this exemption in a banking context.
    //   §4(1)  — SECONDARY: explicit consent via AA Consent Artefact (Sahamati /
    //            ReBIT v2.0 spec) for PSPs that provide a consent token.
    //
    // In production: set env vars CONSENT_MANAGER_BASE_URL, CONSENT_MANAGER_API_KEY,
    // CONSENT_MANAGER_FI_ID.  In local dev: set DPDP_CONSENT_DEV_BYPASS=true.
    //
    // On success, consent_id is logged against trace_id for §12(a) audit trail.
    // ──────────────────────────────────────────────────────────────────────────
    match data.consent_manager.verify(tx.consent_token.as_ref(), &trace_id).await {
        Ok(consent_id) => {
            log::info!(
                "[{}] consent verified: artefact_id={}",
                trace_id, consent_id
            );
        }
        Err(consent::ConsentError::TokenMissing) => {
            return HttpResponse::UnprocessableEntity().json(serde_json::json!({
                "error":  "CONSENT_REQUIRED",
                "detail": "DPDP Act 2023 \u{00a7}4(1): consent_token is mandatory. \
                            Obtain a consent artefact from your Consent Manager \
                            before calling this endpoint.",
                "trace_id": trace_id,
            }));
        }
        Err(consent::ConsentError::NotActive(status)) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error":  "CONSENT_NOT_ACTIVE",
                "detail": format!("Consent artefact is not active (status={status}). \
                                   The Data Principal must grant or renew consent."),
                "trace_id": trace_id,
            }));
        }
        Err(e) => {
            log::error!("[{}] consent verification failed: {}", trace_id, e);
            return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error":  "CONSENT_CHECK_FAILED",
                "detail": format!("{e}"),
                "trace_id": trace_id,
            }));
        }
    }

    let vpa_hash = hash_vpa(&tx.vpa);

    // ── NPCI OC-215/2025-26 — Per-VPA daily rate cap ──────────────────────────
    // NPCI enforces a maximum of 50 balance checks per VPA per day and 3 status
    // checks per transaction.  We apply a conservative 100-request/24 h window
    // on fraud scoring calls so our architecture is physically incapable of
    // flooding the UPI rail on a per-VPA basis.
    {
        const CAP: u32     = 100;
        const WINDOW: Duration = Duration::from_secs(86_400); // 24 h
        let mut entry = data.rate_limiter
            .entry(vpa_hash.clone())
            .or_insert((0u32, Instant::now()));
        if entry.1.elapsed() >= WINDOW {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
            if entry.0 > CAP {
                drop(entry);
                return HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error":   "RATE_LIMIT_EXCEEDED",
                    "detail":  "NPCI OC-215/2025-26: daily scoring request cap for this VPA exceeded. Retry after the 24-hour window resets.",
                    "trace_id": trace_id,
                }));
            }
        }
    }
    // ──────────────────────────────────────────────────────────────────────────

    let (risk_score, reason) = data.cache.get(&vpa_hash);

    let verdict = score_to_verdict(risk_score);

    let latency = started.elapsed().as_micros() as u64;

    if verdict == Verdict::Block {

        log::warn!(
            "[{}] BLOCKED tx hash={} score={:.3} reason={}",
            trace_id,
            vpa_hash,
            risk_score,
            reason
        );
    }

    HttpResponse::Ok().json(TxResponse {
        vpa_hash,
        verdict,
        risk_score,
        trace_id,
        latency_us: latency,
    })
}

#[post("/v1/webhook/update_cache")]
async fn update_cache(
    req: HttpRequest,
    data: web::Data<Arc<AppState>>,
    body: web::Json<CacheUpdateRequest>,
) -> impl Responder {

    let trace_id = Uuid::new_v4().to_string();

    let update = body.into_inner();

    let sig_header = match req.headers().get("x-varaksha-sig") {
        Some(v) => v,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let secret = std::env::var("VARAKSHA_WEBHOOK_SECRET")
        .expect("VARAKSHA_WEBHOOK_SECRET must be set");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");

    let payload = format!(
        "{}:{}:{}:{}",
        update.vpa_hash,
        update.risk_score,
        update.reason,
        update.ttl_seconds
    );

    mac.update(payload.as_bytes());

    let sig_bytes = hex::decode(sig_header.to_str().unwrap()).unwrap();

    if mac.verify_slice(&sig_bytes).is_err() {

        log::warn!("invalid webhook signature");

        return HttpResponse::Unauthorized().finish();
    }

    data.cache.upsert(
        update.vpa_hash.clone(),
        update.risk_score,
        update.reason.clone(),
        update.ttl_seconds,
    );

    log::info!(
        "[{}] cache update hash={} score={:.3} reason={}",
        trace_id,
        update.vpa_hash,
        update.risk_score,
        update.reason
    );

    HttpResponse::Ok().json(CacheUpdateResponse {
        ok: true,
        vpa_hash: update.vpa_hash,
        trace_id,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    env_logger::init();

    let consent_manager = ConsentManagerClient::from_env()
        .unwrap_or_else(|e| {
            panic!("Failed to initialise Consent Manager client: {e}. \
                    Set DPDP_CONSENT_DEV_BYPASS=true for local development.");
        });

    let state = Arc::new(AppState {
        cache:           RiskCache::new(),
        consent_manager,
        rate_limiter:    DashMap::new(),
    });

    let port = std::env::var("GATEWAY_PORT")
        .unwrap_or_else(|_| "8082".to_string())
        .parse::<u16>()
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Arc::clone(&state)))
            .service(health)
            .service(check_tx)
            .service(update_cache)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dashmap::DashMap;
use log::{info, warn};
use risk_cache::{
    auth::{verify_api_key, verify_hmac},
    audit,
    cache::RiskCache,
    config::PolicyConfig,
    models::ModelSessions,
    rate_limiter::RateLimiter,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ── Shared state ──────────────────────────────────────────────────────────────

struct GatewayState {
    models: Arc<ModelSessions>,
    /// Runtime config — reloadable via POST /policy/reload without restart.
    config: Arc<RwLock<PolicyConfig>>,
    /// Device feature cache. Keys are SHA-256 hashed device surrogates only.
    feature_cache: DashMap<String, Vec<f32>>,
    /// Graph agent risk deltas. HMAC-signed writes only.
    risk_delta_cache: RiskCache,
    rate_limiter: Arc<RateLimiter>,
    audit_log_path: String,
    /// Unix timestamp (seconds) when the process started — used by /metrics.
    started_at: u64,
}

// ── Request / Response shapes ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct InferenceRequest {
    transaction_id: String,
    raw_device_id: String,
    amount: f32,
}

#[derive(Debug, Deserialize)]
struct CacheUpdateRequest {
    /// Caller must pre-hash the device_id with SHA-256 before sending.
    hashed_device_id: String,
    features: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct GraphUpdateRequest {
    vpa_hash: String,
    risk_delta: f32,
    reason: String,
    _timestamp: u64,
}

#[derive(Debug, Serialize)]
struct InferenceResponse {
    hashed_txn_id: String,
    risk_score: f32,
    lgbm_score: f32,
    anomaly_score: f32,
    verdict: String,
    execution_time_ms: u128,
    graph_reason: Option<String>,
    tier: String,
}

// ── PII helpers ───────────────────────────────────────────────────────────────

/// One-way SHA-256 hash. Call this at the entry point — never store raw PII.
fn anonymize_pii(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn env_non_empty(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

// ── Feature vector normalization ──────────────────────────────────────────────

/// Ensure the vector is exactly `n_features` long and injects the transaction
/// amount at index 0 (the first feature column in the manifest).
fn normalize_feature_vector(mut features: Vec<f32>, amount: f32, n_features: usize) -> Vec<f32> {
    features.resize(n_features, 0.0);
    features[0] = amount;
    features
}

// ── Verdict helper ────────────────────────────────────────────────────────────

fn compute_verdict(score: f32, allow: f32, block: f32) -> &'static str {
    if score < allow {
        "ALLOW"
    } else if score >= block {
        "BLOCK"
    } else {
        "FLAG"
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /inference — score a transaction.
///
/// Auth: X-Varaksha-Api-Key header (VARAKSHA_API_KEY env var).
/// Rate limit: per hashed device_id.
/// PII: raw_device_id and transaction_id are hashed immediately on arrival.
async fn inference(
    req: HttpRequest,
    state: web::Data<GatewayState>,
    payload: web::Json<InferenceRequest>,
) -> impl Responder {
    let started = Instant::now();

    // ── Auth ───────────────────────────────────────────────────────────────
    let api_key = match std::env::var("VARAKSHA_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "inference API key not configured"}));
        }
    };
    if !verify_api_key(&api_key, &req) {
        warn!("inference_auth_fail");
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid API key"}));
    }

    // ── PII anonymization (must happen before any logging or storage) ──────
    let device_surrogate = anonymize_pii(&payload.raw_device_id);
    let hashed_txn_id = anonymize_pii(&payload.transaction_id);

    // ── Rate limit ─────────────────────────────────────────────────────────
    if !state.rate_limiter.check_and_record(&device_surrogate) {
        let retry_after = state.rate_limiter.retry_after(&device_surrogate);
        warn!("rate_limit_exceeded");
        return HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", retry_after.to_string()))
            .json(serde_json::json!({"error": "rate limit exceeded", "retry_after_seconds": retry_after}));
    }

    // ── Feature lookup ─────────────────────────────────────────────────────
    let config = state.config.read().unwrap();
    let n_features = config.n_features;

    let cached_features = state
        .feature_cache
        .get(&device_surrogate)
        .map(|v| v.clone())
        .unwrap_or_else(|| vec![0.0; n_features]);

    let features = normalize_feature_vector(cached_features, payload.amount, n_features);

    // ── Graph topology delta ───────────────────────────────────────────────
    let (graph_delta, graph_reason_str) = state.risk_delta_cache.get(&device_surrogate);

    // ── Dual ONNX inference + weighted fusion ──────────────────────────────
    let scored = match state.models.infer(features, &config, graph_delta) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError().body(e);
        }
    };

    let verdict = compute_verdict(scored.fused_score, config.allow_threshold, config.block_threshold);
    let tier_str = config.tier.as_str().to_string();

    let graph_reason: Option<String> = if graph_delta > 0.0 {
        Some(graph_reason_str)
    } else {
        None
    };

    info!(
        "inference verdict={} score={:.4} lgbm={:.4} anomaly={:.4} exec_ms={}",
        verdict,
        scored.fused_score,
        scored.lgbm_score,
        scored.anomaly_score,
        started.elapsed().as_millis()
    );

    HttpResponse::Ok().json(InferenceResponse {
        hashed_txn_id,
        risk_score: scored.fused_score,
        lgbm_score: scored.lgbm_score,
        anomaly_score: scored.anomaly_score,
        verdict: verdict.to_string(),
        execution_time_ms: started.elapsed().as_millis(),
        graph_reason,
        tier: tier_str,
    })
}

/// POST /update_cache — inject pre-computed feature vector for a device.
///
/// Auth: HMAC-SHA256 body signature (VARAKSHA_UPDATE_SECRET env var).
/// Only available on Cloud and OnPrem tiers.
async fn update_cache(
    req: HttpRequest,
    state: web::Data<GatewayState>,
    body: web::Bytes,
) -> impl Responder {
    let secret = match std::env::var("VARAKSHA_UPDATE_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "update secret not configured"}));
        }
    };

    if !verify_hmac(&secret, &body, &req) {
        warn!("update_cache_auth_fail");
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid signature"}));
    }

    let payload: CacheUpdateRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("invalid JSON: {e}")}));
        }
    };

    let config = state.config.read().unwrap();
    let n_features = config.n_features;
    drop(config);

    // Validate feature vector length.
    if payload.features.len() != n_features {
        return HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "error": format!("expected {} features, got {}", n_features, payload.features.len())
        }));
    }

    info!("cache_update accepted");
    state
        .feature_cache
        .insert(payload.hashed_device_id.clone(), payload.features);

    HttpResponse::Ok().json(serde_json::json!({"status": "success"}))
}

/// POST /graph_update — receive a risk delta from the graph agent.
///
/// Auth: HMAC-SHA256 body signature (VARAKSHA_GRAPH_SECRET env var).
/// Only available on Cloud and OnPrem tiers.
async fn graph_update(
    req: HttpRequest,
    state: web::Data<GatewayState>,
    body: web::Bytes,
) -> impl Responder {
    let secret = match std::env::var("VARAKSHA_GRAPH_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "graph secret not configured"}));
        }
    };

    if !verify_hmac(&secret, &body, &req) {
        warn!("graph_update_auth_fail");
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid signature"}));
    }

    let payload: GraphUpdateRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("invalid JSON: {e}")}));
        }
    };

    let risk_delta = payload.risk_delta.clamp(0.0, 1.0);
    let audit_reason = format!("graph | {} | delta={:.4}", payload.reason, risk_delta);

    state.risk_delta_cache.upsert(
        payload.vpa_hash.clone(),
        risk_delta,
        payload.reason.clone(),
        audit_reason,
    );

    let audit_event = serde_json::json!({
        "event": "graph_update",
        "ts": unix_now(),
        "vpa_hash": payload.vpa_hash,
        "risk_delta": risk_delta,
        "reason": payload.reason,
    });
    if let Err(e) = audit::append_jsonl(&state.audit_log_path, audit_event) {
        warn!("audit_log_write_failed event=graph_update err={}", e);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "vpa_hash": payload.vpa_hash,
        "risk_delta": risk_delta,
        "reason": payload.reason,
    }))
}

/// POST /policy/reload — re-read feature_manifest.json and bank_risk_policy.json from disk.
///
/// Auth: HMAC-SHA256 (VARAKSHA_UPDATE_SECRET env var). No restart required.
/// Used by 04_monthly_risk_analyzer.py after writing bank_risk_policy.json.
async fn policy_reload(
    req: HttpRequest,
    state: web::Data<GatewayState>,
    body: web::Bytes,
) -> impl Responder {
    let secret = match std::env::var("VARAKSHA_UPDATE_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "update secret not configured"}));
        }
    };

    if !verify_hmac(&secret, &body, &req) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid signature"}));
    }

    match PolicyConfig::load() {
        Ok(new_config) => {
            let new_allow = new_config.allow_threshold;
            let new_block = new_config.block_threshold;
            *state.config.write().unwrap() = new_config;
            info!("policy_reload allow={:.4} block={:.4}", new_allow, new_block);

            let audit_event = serde_json::json!({
                "event": "policy_reload",
                "ts": unix_now(),
                "status": "ok",
                "allow_threshold": new_allow,
                "block_threshold": new_block,
            });
            if let Err(e) = audit::append_jsonl(&state.audit_log_path, audit_event) {
                warn!("audit_log_write_failed event=policy_reload err={}", e);
            }

            HttpResponse::Ok().json(serde_json::json!({
                "status": "reloaded",
                "allow_threshold": new_allow,
                "block_threshold": new_block,
            }))
        }
        Err(e) => {
            warn!("policy_reload_failed err={}", e);
            let audit_event = serde_json::json!({
                "event": "policy_reload",
                "ts": unix_now(),
                "status": "error",
                "error": e.to_string(),
            });
            if let Err(write_err) = audit::append_jsonl(&state.audit_log_path, audit_event) {
                warn!("audit_log_write_failed event=policy_reload err={}", write_err);
            }
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("reload failed: {e}")}))
        }
    }
}

/// DELETE /erasure/{vpa_hash} — DPDP §12(b) right to erasure.
///
/// Auth: X-Varaksha-Api-Key.
/// Removes the VPA hash from both feature_cache and risk_delta_cache.
/// Emits an audit log entry for the 5-year RBI retention requirement.
async fn erasure(
    req: HttpRequest,
    state: web::Data<GatewayState>,
    path: web::Path<String>,
) -> impl Responder {
    let api_key = match std::env::var("VARAKSHA_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "API key not configured"}));
        }
    };
    if !verify_api_key(&api_key, &req) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid API key"}));
    }

    let vpa_hash = path.into_inner();
    let removed_delta = state.risk_delta_cache.remove(&vpa_hash);
    let removed_feature = state.feature_cache.remove(&vpa_hash).is_some();

    // RBI IT Master Direction §15: structured audit trail, no PII.
    info!(
        "erasure_request removed_delta={} removed_feature={} timestamp={}",
        removed_delta,
        removed_feature,
        unix_now()
    );

    let audit_event = serde_json::json!({
        "event": "erasure",
        "ts": unix_now(),
        "vpa_hash": vpa_hash,
        "removed_delta": removed_delta,
        "removed_feature": removed_feature,
    });
    if let Err(e) = audit::append_jsonl(&state.audit_log_path, audit_event) {
        warn!("audit_log_write_failed event=erasure err={}", e);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "erased": true,
        "vpa_hash": vpa_hash,
        "removed_delta_entry": removed_delta,
        "removed_feature_entry": removed_feature,
    }))
}

/// GET /metrics — internal observability endpoint.
///
/// Auth: X-Varaksha-Api-Key. No PII in output.
async fn metrics(req: HttpRequest, state: web::Data<GatewayState>) -> impl Responder {
    let api_key = match std::env::var("VARAKSHA_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "API key not configured"}));
        }
    };
    if !verify_api_key(&api_key, &req) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "invalid API key"}));
    }

    let config = state.config.read().unwrap();
    let m = state.risk_delta_cache.metrics();
    use std::sync::atomic::Ordering;

    HttpResponse::Ok().json(serde_json::json!({
        "uptime_seconds": unix_now().saturating_sub(state.started_at),
        "tier": config.tier.as_str(),
        "n_features": config.n_features,
        "active_allow_threshold": config.allow_threshold,
        "active_block_threshold": config.block_threshold,
        "lgbm_weight": config.lgbm_weight,
        "anomaly_weight": config.anomaly_weight,
        "topology_weight": config.topology_weight,
        "risk_delta_cache": {
            "size": state.risk_delta_cache.len(),
            "hits": m.hits.load(Ordering::Relaxed),
            "misses": m.misses.load(Ordering::Relaxed),
            "expired": m.expired.load(Ordering::Relaxed),
        },
        "feature_cache_size": state.feature_cache.len(),
    }))
}

/// GET /health — liveness check. No auth required.
async fn health(state: web::Data<GatewayState>) -> impl Responder {
    let config = state.config.read().unwrap();
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "tier": config.tier.as_str(),
    }))
}

// ── Startup ───────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // ── Load config from feature_manifest.json + bank_risk_policy.json ─────
    let config = match PolicyConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("startup_config_load_failed: {}", e);
            return Err(std::io::Error::other(e));
        }
    };

    if config.is_production {
        let mut missing = Vec::new();
        if !env_non_empty("VARAKSHA_API_KEY") {
            missing.push("VARAKSHA_API_KEY");
        }
        if !env_non_empty("VARAKSHA_UPDATE_SECRET") {
            missing.push("VARAKSHA_UPDATE_SECRET");
        }
        if config.tier != risk_cache::config::VarakshaTier::Edge && !env_non_empty("VARAKSHA_GRAPH_SECRET") {
            missing.push("VARAKSHA_GRAPH_SECRET");
        }

        if !missing.is_empty() {
            return Err(std::io::Error::other(format!(
                "Missing required environment variables in production mode: {}",
                missing.join(", ")
            )));
        }
    }

    info!(
        "varaksha_gateway_start tier={} n_features={} allow={:.3} block={:.3} models_dir={}",
        config.tier.as_str(),
        config.n_features,
        config.allow_threshold,
        config.block_threshold,
        config.models_dir,
    );

    // ── Load ONNX models ───────────────────────────────────────────────────
    let models = match ModelSessions::load(&config) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("startup_model_load_failed: {}", e);
            return Err(std::io::Error::other(e));
        }
    };

    info!(
        "models_loaded lgbm={} if={}",
        config.lgbm_onnx_path,
        config.if_onnx_path.as_deref().unwrap_or("none (edge tier)")
    );

    let tier = config.tier.clone();
    let cache_ttl = config.cache_ttl_seconds;
    let rate_max = config.rate_max;
    let rate_window = config.rate_window_seconds;
    let bind_addr = config.bind_addr.clone();
    let audit_log_path = std::env::var("VARAKSHA_AUDIT_LOG_PATH")
        .unwrap_or_else(|_| "./logs/security_audit.jsonl".to_string());

    let state = web::Data::new(GatewayState {
        models: Arc::new(models),
        config: Arc::new(RwLock::new(config)),
        feature_cache: DashMap::new(),
        risk_delta_cache: RiskCache::new(cache_ttl),
        rate_limiter: Arc::new(RateLimiter::new(rate_max, rate_window)),
        audit_log_path,
        started_at: unix_now(),
    });

    info!("binding addr={}", bind_addr);

    let server = HttpServer::new(move || {
        let mut app = App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/metrics", web::get().to(metrics))
            .route("/inference", web::post().to(inference))
            .route("/policy/reload", web::post().to(policy_reload))
            .route("/erasure/{vpa_hash}", web::delete().to(erasure));

        // graph_update and update_cache are disabled on Edge tier.
        // The graph agent doesn't run on Edge, and features are pre-baked into the SDK.
        if tier != risk_cache::config::VarakshaTier::Edge {
            app = app
                .route("/update_cache", web::post().to(update_cache))
                .route("/graph_update", web::post().to(graph_update));
        }

        app
    })
    .bind(&bind_addr);

    let server = match server {
        Ok(s) => s,
        Err(e) => {
            eprintln!("startup_bind_failed addr={} err={}", bind_addr, e);
            return Err(e);
        }
    };

    if let Err(e) = server.run().await {
        eprintln!("startup_server_run_failed: {}", e);
        return Err(e);
    }

    Ok(())
}

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use ndarray::Array2;
use ort::{inputs, session::Session};
use ort::value::TensorRef;
use risk_cache::RiskCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

const FEATURE_VECTOR_SIZE: usize = 43;
const AMOUNT_FEATURE_INDEX: usize = 0;
const ALLOW_THRESHOLD: f32 = 0.30;
const BLOCK_THRESHOLD: f32 = 0.85;

struct GatewayState {
    // Stage-1 ONNX session (Sweeper)
    session: Mutex<Session>,
    // High-speed cache. Keys must be SHA-256 hashed surrogates only.
    feature_cache: DashMap<String, Vec<f32>>,
    // Graph agent risk deltas. Populated via POST /graph_update (HMAC-signed).
    risk_delta_cache: RiskCache,
}

#[derive(Debug, Deserialize)]
struct InferenceRequest {
    transaction_id: String,
    raw_device_id: String,
    amount: f32,
}

#[derive(Debug, Deserialize)]
struct CacheUpdateRequest {
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
    verdict: String,
    execution_time_ms: u128,
    graph_reason: Option<String>,
}

fn anonymize_pii(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn normalize_feature_vector(mut features: Vec<f32>, amount: f32) -> Vec<f32> {
    if features.len() < FEATURE_VECTOR_SIZE {
        features.resize(FEATURE_VECTOR_SIZE, 0.0);
    } else if features.len() > FEATURE_VECTOR_SIZE {
        features.truncate(FEATURE_VECTOR_SIZE);
    }

    features[AMOUNT_FEATURE_INDEX] = amount;
    features
}

fn extract_probability(outputs: &ort::session::SessionOutputs<'_>) -> Result<f32, String> {
    let value = &outputs[0];

    let (_shape, values) = value
        .try_extract_tensor::<f32>()
        .map_err(|e| format!("Failed to extract ONNX tensor: {e}"))?;

    if values.is_empty() {
        return Err("ONNX output tensor is empty".to_string());
    }

    // Common binary-classifier outputs are [p] or [neg, pos].
    let prob = if values.len() >= 2 { values[1] } else { values[0] };
    Ok(prob.clamp(0.0, 1.0))
}

/// Verify HMAC-SHA256 signature from X-Varaksha-Signature header.
/// Header format: "sha256=<hex_digest>"
/// Returns true only when the header is present and the MAC matches.
fn verify_hmac(secret: &str, body: &[u8], req: &HttpRequest) -> bool {
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

    // Constant-time comparison via XOR-fold to prevent timing attacks.
    if computed.len() != provided_hex.len() {
        return false;
    }
    let mismatch: u8 = computed
        .bytes()
        .zip(provided_hex.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    mismatch == 0
}

async fn inference(
    state: web::Data<GatewayState>,
    payload: web::Json<InferenceRequest>,
) -> impl Responder {
    let started = Instant::now();

    // Step A: Anonymize incoming PII immediately.
    let device_surrogate = anonymize_pii(&payload.raw_device_id);
    let hashed_txn_id = anonymize_pii(&payload.transaction_id);

    // Step B: Lookup secure surrogate in feature cache, fallback to cold-start vector.
    let cached_features = state
        .feature_cache
        .get(&device_surrogate)
        .map(|v| v.clone())
        .unwrap_or_else(|| vec![0.0; FEATURE_VECTOR_SIZE]);

    let features = normalize_feature_vector(cached_features, payload.amount);

    // Step C: ONNX inference.
    let input = match Array2::from_shape_vec((1, FEATURE_VECTOR_SIZE), features) {
        Ok(arr) => arr,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to build input tensor: {e}"));
        }
    };

    let ml_score = {
        let mut session = match state.session.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return HttpResponse::InternalServerError().body("Session lock poisoned");
            }
        };

        let input_tensor = match TensorRef::from_array_view(&input) {
            Ok(t) => t,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to create ONNX input tensor: {e}"));
            }
        };

        let outputs = match session.run(inputs![input_tensor]) {
            Ok(result) => result,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("ONNX inference failed: {e}"));
            }
        };

        match extract_probability(&outputs) {
            Ok(v) => v,
            Err(e) => return HttpResponse::InternalServerError().body(e),
        }
    };

    // Step D: Fuse graph agent risk delta (additive, clamped to [0, 1]).
    let (graph_delta, graph_reason_str) = state.risk_delta_cache.get(&device_surrogate);
    let risk_score = (ml_score + graph_delta).clamp(0.0, 1.0);

    let graph_reason: Option<String> = if graph_delta > 0.0 {
        Some(graph_reason_str)
    } else {
        None
    };

    let verdict = if risk_score < ALLOW_THRESHOLD {
        "ALLOW"
    } else if risk_score > BLOCK_THRESHOLD {
        "BLOCK"
    } else {
        "FLAG"
    }
    .to_string();

    let response = InferenceResponse {
        hashed_txn_id,
        risk_score,
        verdict,
        execution_time_ms: started.elapsed().as_millis(),
        graph_reason,
    };

    HttpResponse::Ok().json(response)
}

async fn update_cache(
    state: web::Data<GatewayState>,
    payload: web::Json<CacheUpdateRequest>,
) -> impl Responder {
    state
        .feature_cache
        .insert(payload.hashed_device_id.clone(), payload.features.clone());

    HttpResponse::Ok().json(serde_json::json!({"status": "success"}))
}

async fn graph_update(
    req: HttpRequest,
    state: web::Data<GatewayState>,
    body: web::Bytes,
) -> impl Responder {
    // Read HMAC secret from environment. Reject update if secret is not configured.
    let secret = match std::env::var("VARAKSHA_GRAPH_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"error": "graph secret not configured"}));
        }
    };

    if !verify_hmac(&secret, &body, &req) {
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
    state
        .risk_delta_cache
        .upsert(payload.vpa_hash.clone(), risk_delta, payload.reason.clone(), 300);

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "vpa_hash": payload.vpa_hash,
        "risk_delta": risk_delta,
        "reason": payload.reason,
    }))
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure ONNX model path here.
    // For production, set VARAKSHA_STAGE1_ONNX_PATH via environment/secret config.
    let model_path = std::env::var("VARAKSHA_STAGE1_ONNX_PATH")
        .unwrap_or_else(|_| "./varaksha_stage1_sweeper.onnx".to_string());

    let session = Session::builder()
        .map_err(|e| std::io::Error::other(format!("ORT builder error: {e}")))?
        .commit_from_file(&model_path)
        .map_err(|e| std::io::Error::other(format!("Failed to load ONNX model: {e}")))?;

    let state = web::Data::new(GatewayState {
        session: Mutex::new(session),
        feature_cache: DashMap::new(),
        risk_delta_cache: RiskCache::new(),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/update_cache", web::post().to(update_cache))
            .route("/inference", web::post().to(inference))
            .route("/graph_update", web::post().to(graph_update))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

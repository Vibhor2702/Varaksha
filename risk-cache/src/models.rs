//! Dual ONNX session management and weighted score fusion.
//!
//! Layer 3 — LightGBM binary classifier (primary supervised signal, weight 0.6)
//! Layer 2 — IsolationForest anomaly model (novel-pattern signal, weight 0.3)
//! Layer 1 — Graph topology delta, passed in from the risk_delta_cache (weight 0.1)
//!
//! ORT v2 Session is Send + Sync — we use Arc<Session> to allow true concurrent
//! inference without a serializing Mutex.
//!
//! IsolationForest raw score convention (skl2onnx):
//!   score ∈ [−0.5, +0.5]: −0.5 is most anomalous, +0.5 is most normal.
//!   We normalize to [0, 1] via: normalized = (−raw + 0.5).clamp(0.0, 1.0)

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use log::{info, warn};
use ndarray::Array2;
use ort::{ep, inputs, session::Session};
use ort::value::TensorRef;

use crate::config::PolicyConfig;

pub struct ModelSessions {
    /// Mutex required because Session::run() takes &mut self in ORT v2.
    pub lgbm: Arc<Mutex<Session>>,
    /// None on Edge tier — IsolationForest model is not loaded.
    pub isolation_forest: Option<Arc<Mutex<Session>>>,
}

pub struct ScoredResult {
    /// Raw LightGBM positive-class probability [0, 1].
    pub lgbm_score: f32,
    /// Normalized IsolationForest anomaly score [0, 1]. 0.0 when IF is absent.
    pub anomaly_score: f32,
    /// Final weighted fusion score: lgbm_weight*lgbm + anomaly_weight*anomaly + topology_weight*graph_delta.
    pub fused_score: f32,
}

impl ModelSessions {
    fn ensure_ort_dylib_path(config: &PolicyConfig) {
        if std::env::var("ORT_DYLIB_PATH").ok().filter(|v| !v.is_empty()).is_some() {
            return;
        }

        let models_dir = Path::new(&config.models_dir);
        let repo_root = models_dir.parent().unwrap_or(models_dir);

        let candidates = [
            repo_root.join(".venv").join("Lib").join("site-packages").join("onnxruntime").join("capi").join("onnxruntime.dll"),
            repo_root.join(".venv").join("lib").join("site-packages").join("onnxruntime").join("capi").join("onnxruntime.so"),
            repo_root.join(".venv").join("lib").join("site-packages").join("onnxruntime").join("capi").join("libonnxruntime.dylib"),
        ];

        for candidate in candidates {
            if candidate.exists() {
                std::env::set_var("ORT_DYLIB_PATH", &candidate);
                info!("ort_dylib_path_resolved path={}", candidate.display());
                return;
            }
        }

        warn!("ort_dylib_path_unset reason=no_runtime_dylib_found_near_venv; relying_on_system_loader=true");
    }

    fn optimized_cache_path(config: &PolicyConfig, source_path: &str) -> Option<PathBuf> {
        let source = Path::new(source_path);
        let file_name = source.file_name()?.to_string_lossy().to_string();
        Some(Path::new(&config.optimized_models_dir).join(file_name))
    }

    fn should_use_optimized_cache(source_path: &str, optimized_path: &Path) -> bool {
        let source_meta = std::fs::metadata(source_path).ok();
        let optimized_meta = std::fs::metadata(optimized_path).ok();

        match (source_meta, optimized_meta) {
            (Some(src), Some(opt)) => {
                if let (Ok(src_mtime), Ok(opt_mtime)) = (src.modified(), opt.modified()) {
                    opt_mtime >= src_mtime
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    fn build_builder(config: &PolicyConfig) -> Result<ort::session::builder::SessionBuilder, String> {
        let mut builder = Session::builder().map_err(|e| format!("ORT builder error: {e}"))?;

        // Force CPU EP to avoid expensive provider probing during startup.
        builder = builder
            .with_execution_providers([ep::CPU::default().with_arena_allocator(config.ort_cpu_mem_arena).build()])
            .map_err(|e| format!("Failed to configure CPU execution provider: {e}"))?;

        builder = builder
            .with_optimization_level(config.ort_optimization_level)
            .map_err(|e| format!("Failed to set ORT optimization level: {e}"))?
            .with_intra_threads(config.ort_intra_threads)
            .map_err(|e| format!("Failed to set ORT intra threads: {e}"))?
            .with_inter_threads(config.ort_inter_threads)
            .map_err(|e| format!("Failed to set ORT inter threads: {e}"))?
            .with_parallel_execution(config.ort_parallel_execution)
            .map_err(|e| format!("Failed to set ORT parallel execution: {e}"))?;

        Ok(builder)
    }

    fn load_single_model(config: &PolicyConfig, source_path: &str, label: &str) -> Result<Session, String> {
        let t0 = Instant::now();
        let optimized_path = Self::optimized_cache_path(config, source_path);

        if let Some(ref cache_path) = optimized_path {
            if let Some(parent) = cache_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!("model={} cache_dir_create_failed path={} err={}", label, parent.display(), e);
                }
            }

            if Self::should_use_optimized_cache(source_path, cache_path) {
                let session = Self::build_builder(config)?
                    .commit_from_file(cache_path)
                    .map_err(|e| {
                        format!(
                            "Failed to load optimized {} ONNX from {}: {e}",
                            label,
                            cache_path.display()
                        )
                    })?;

                info!(
                    "model_loaded label={} source=optimized path={} load_ms={}",
                    label,
                    cache_path.display(),
                    t0.elapsed().as_millis()
                );
                return Ok(session);
            }
        }

        let mut builder = Self::build_builder(config)?;
        if let Some(ref cache_path) = optimized_path {
            builder = builder
                .with_optimized_model_path(cache_path)
                .map_err(|e| format!("Failed to set optimized model output path {}: {e}", cache_path.display()))?;
        }

        let session = builder
            .commit_from_file(source_path)
            .map_err(|e| format!("Failed to load {} ONNX from {}: {e}", label, source_path))?;

        info!(
            "model_loaded label={} source=raw path={} load_ms={}",
            label,
            source_path,
            t0.elapsed().as_millis()
        );
        Ok(session)
    }

    /// Load ONNX sessions from paths in PolicyConfig.
    pub fn load(config: &PolicyConfig) -> Result<Self, String> {
        Self::ensure_ort_dylib_path(config);

        let lgbm = Self::load_single_model(config, &config.lgbm_onnx_path, "lgbm")?;

        let isolation_forest = match &config.if_onnx_path {
            Some(path) => {
                let session = Self::load_single_model(config, path, "isolation_forest")?;
                Some(Arc::new(Mutex::new(session)))
            }
            None => None,
        };

        Ok(ModelSessions {
            lgbm: Arc::new(Mutex::new(lgbm)),
            isolation_forest,
        })
    }

    /// Run both models and return the weighted fused score.
    ///
    /// `features` must be exactly `config.n_features` floats.
    /// `graph_delta` is the topology risk delta from RiskCache (0.0 when absent).
    pub fn infer(
        &self,
        features: Vec<f32>,
        config: &PolicyConfig,
        graph_delta: f32,
    ) -> Result<ScoredResult, String> {
        let n = config.n_features;

        // ── Layer 3: LightGBM ──────────────────────────────────────────────
        let lgbm_score = {
            let input = Array2::from_shape_vec((1, n), features.clone())
                .map_err(|e| format!("Failed to build LGBM input tensor: {e}"))?;
            let tensor = TensorRef::from_array_view(&input)
                .map_err(|e| format!("Failed to create LGBM TensorRef: {e}"))?;
            let mut session = self.lgbm.lock().map_err(|_| "LGBM session lock poisoned".to_string())?;
            let outputs = session.run(inputs![tensor])
                .map_err(|e| format!("LightGBM ONNX inference failed: {e}"))?;
            extract_lgbm_probability(&outputs)?
        };

        // ── Layer 2: IsolationForest (skipped on Edge tier) ────────────────
        let anomaly_score = if let Some(if_mutex) = &self.isolation_forest {
            let input = Array2::from_shape_vec((1, n), features)
                .map_err(|e| format!("Failed to build IF input tensor: {e}"))?;
            let tensor = TensorRef::from_array_view(&input)
                .map_err(|e| format!("Failed to create IF TensorRef: {e}"))?;
            let mut session = if_mutex.lock().map_err(|_| "IF session lock poisoned".to_string())?;
            let outputs = session.run(inputs![tensor])
                .map_err(|e| format!("IsolationForest ONNX inference failed: {e}"))?;
            extract_if_anomaly_score(&outputs)?
        } else {
            0.0_f32
        };

        // ── Weighted fusion ────────────────────────────────────────────────
        // Weights are loaded from feature_manifest.json at startup (no hardcoding).
        let fused_score = (config.lgbm_weight * lgbm_score
            + config.anomaly_weight * anomaly_score
            + config.topology_weight * graph_delta)
            .clamp(0.0, 1.0);

        Ok(ScoredResult {
            lgbm_score,
            anomaly_score,
            fused_score,
        })
    }
}

/// Extract positive-class probability from LightGBM ONNX output.
///
/// With zipmap=False (required), LightGBM outputs a float tensor.
/// Binary classifier shape: [1, 2] → we want index [1] (positive class).
/// Scalar output shape: [1] → we use index [0] directly.
fn extract_lgbm_probability(outputs: &ort::session::SessionOutputs<'_>) -> Result<f32, String> {
    // LightGBM with zipmap=False outputs the probabilities as the second output.
    // Output 0 is the predicted label (int64), output 1 is the probability tensor (float).
    let value = if outputs.len() >= 2 {
        &outputs[1]
    } else {
        &outputs[0]
    };

    let (_shape, values) = value
        .try_extract_tensor::<f32>()
        .map_err(|e| format!("Failed to extract LightGBM tensor: {e}"))?;

    if values.is_empty() {
        return Err("LightGBM output tensor is empty".to_string());
    }

    // [neg_prob, pos_prob] → take pos_prob
    let prob = if values.len() >= 2 { values[1] } else { values[0] };
    Ok(prob.clamp(0.0, 1.0))
}

/// Extract and normalize IsolationForest anomaly score.
///
/// skl2onnx exports the raw IF score (score_samples output) in approximately [−0.5, +0.5].
///   −0.5 = most anomalous → should map to risk 1.0
///   +0.5 = most normal   → should map to risk 0.0
///
/// Normalization: normalized = (−raw + 0.5).clamp(0.0, 1.0)
fn extract_if_anomaly_score(outputs: &ort::session::SessionOutputs<'_>) -> Result<f32, String> {
    // skl2onnx IsolationForest: output 0 = predicted label (-1/1), output 1 = score
    let value = if outputs.len() >= 2 {
        &outputs[1]
    } else {
        &outputs[0]
    };

    let (_shape, values) = value
        .try_extract_tensor::<f32>()
        .map_err(|e| format!("Failed to extract IsolationForest tensor: {e}"))?;

    if values.is_empty() {
        return Err("IsolationForest output tensor is empty".to_string());
    }

    let raw = values[0];
    // Flip and shift: lower raw score (more anomalous) → higher risk
    let normalized = (-raw + 0.5_f32).clamp(0.0, 1.0);
    Ok(normalized)
}
